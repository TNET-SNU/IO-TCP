#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <rte_hexdump.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <unistd.h>
#include <stdlib.h>

#include "fhash.h"
#include "offload_write.h"
#include "memorypool.h"

/* connection table */
struct fc_hashtable *file_cache_ht[MAX_CPUS];

/* # of disk slaves per core -- confgurable */
static int g_numDiskSlavesPerCore = 1;

/* disk slaves (slave = thread)*/
static DiskIOSlave *g_dslaves[MAX_CPUS];

/* current disk slave index per core */
static int g_slaveIdx[MAX_CPUS];

#if NO_FS_PERFTEST
static int fd_per_core[MAX_CPUS]; // for fake filesystem
static int fd_file_count[MAX_CPUS] = {0}; // for fake filesystem
#endif
static pool filecache_pools[MAX_CPUS]; // for fake filesystem
static pool freadreq_pools[MAX_CPUS]; // for fake filesystem


/* total amount of shared cache memory = 2GB -- configurable
   currently, all cache memory is shared across all worker threads */
static int64_t g_cacheMemorySize = 2*1024*1024*1024L; 

// #define SHOW_STATS 1 --> options.h
#ifdef SHOW_STATS
/* statistics */
static int64_t g_numBytesSent[MAX_CPUS] = {0};
static int64_t g_numBytesResent[MAX_CPUS] = {0};
static int     g_numFlows[MAX_CPUS] = {0};
#endif

/* # of bytes to be sent out (per-core) */
static int g_numBytesToSend[MAX_CPUS] = {0};

#define TCP_SEQ_LT(a,b)                ((int32_t)((a)-(b)) < 0)
#define TCP_SEQ_LEQ(a,b)               ((int32_t)((a)-(b)) <= 0)
#define TCP_SEQ_GT(a,b)                ((int32_t)((a)-(b)) > 0)
#define TCP_SEQ_GEQ(a,b)               ((int32_t)((a)-(b)) >= 0)
#define TCP_SEQ_BETWEEN(a,b,c) (TCP_SEQ_GEQ(a,b) && TCP_SEQ_LEQ(a,c))

#define GET_TCP_HEADER_LEN(tcph) ((tcph->data_off & 0xf0) >> 2)

uint8_t *tmpbuf;


/*---------------------------------------------------------------------------*/
/* Function Prototype */

static void ProcessPacket(uint16_t core_id, uint16_t port,
						  uint8_t *pktbuf, int len);

static inline int CheckReady(void);

/*---------------------------------------------------------------------------*/
static inline double
GetCurrentTimeMsec(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1e3 + tv.tv_usec *1e-3);
}
/*---------------------------------------------------------------------------*/
static void
thread_local_init(int core_id)
{
	struct thread_context *ctx;
	struct dpdk_private_context *dpc;
	int nb_ports;
	int i, j, ret;
	
	nb_ports = rte_eth_dev_count_avail();
	
	/* Allocate memory for thread context */
	ctx_array[core_id] = calloc(1, sizeof(struct thread_context));
	ctx = ctx_array[core_id];
	if (ctx == NULL)
		rte_exit(EXIT_FAILURE,
				 "[CPU %d] Cannot allocate memory for thread_context, "
				 "errno: %d\n",
				 rte_lcore_id(), errno);
	
	ctx->ready = 0;
	ctx->coreid = (uint16_t)core_id;
	
	/* Allocate memory for dpdk private context */
	ctx->dpc = calloc(1, sizeof(struct dpdk_private_context));
	dpc = ctx->dpc;
	if (dpc == NULL)
		rte_exit(EXIT_FAILURE,
				 "[CPU %d] Cannot allocate memory for dpdk_private_context, "
				 "errno: %d\n",
				 rte_lcore_id(), errno);
	
	/* Assign packet mbuf pool to dpdk private context */
	dpc->pktmbuf_pool = pktmbuf_pool[core_id];
	
	for (j = 0; j < nb_ports; j++) {
		/* Allocate wmbufs for each registered port */
		for (i = 0; i < MAX_PKT_BURST; i++) {
			dpc->wmbufs[j].m_table[i] =
				rte_pktmbuf_alloc(pktmbuf_pool[core_id]);
			if (dpc->wmbufs[j].m_table[i] == NULL) {
				rte_exit(EXIT_FAILURE,
						 "[CPU %d] Cannot allocate memory for "
						 "port %d wmbuf[%d]\n",
						 rte_lcore_id(), j, i);
			}
		}
		dpc->wmbufs[j].len = 0;
	}

#if NO_HARDWARE_TSO
	/* Create GSO context */
	gso_ctx_array[core_id] = calloc(1, sizeof(struct rte_gso_ctx));
	if (gso_ctx_array == NULL)
		rte_exit(EXIT_FAILURE,
				 "[CPU %d] Cannot allocate memory for rte_gso_ctx, "
				 "errno: %d\n",
				 rte_lcore_id(), errno);
	
	gso_ctx_array[core_id]->direct_pool = gso_pool[core_id];
	gso_ctx_array[core_id]->indirect_pool = gso_pool[core_id];
	gso_ctx_array[core_id]->flag = RTE_GSO_FLAG_IPID_FIXED;
	gso_ctx_array[core_id]->gso_types = DEV_TX_OFFLOAD_TCP_TSO;
	gso_ctx_array[core_id]->gso_size = MTU;
#endif

	if((ret = posix_memalign((void **)&tmpbuf, getpagesize(), MAX_TSO_PKTSIZE*4)) != 0) {
		TRACE_ERROR("posix_memalign failed errno=%d\n", ret);
		exit(-1);
	}

}
/*---------------------------------------------------------------------------*/
static void
thread_local_destroy(int core_id)
{
  struct thread_context *ctx;
  struct dpdk_private_context *dpc;
  int port;

  ctx = ctx_array[core_id];
  dpc = ctx->dpc;

  /* Free dpdk private context */
  RTE_ETH_FOREACH_DEV(port) {
    if (dpc->rmbufs[port].len != 0) {
      free_pkts(dpc->rmbufs[port].m_table, dpc->rmbufs[port].len);
      dpc->rmbufs[port].len = 0;
    }
  }
  rte_mempool_free(dpc->pktmbuf_pool);

#if NO_HARDWARE_TSO
  rte_mempool_free(gso_pool[core_id]);
  /* Free GSO context */
  free(gso_ctx_array[core_id]);
#endif

  free(ctx->dpc);

  /* Free thread context */
  free(ctx);
}
/*---------------------------------------------------------------------------*/
static inline void
CloseFileCache(uint16_t core_id, struct file_cache *fc)
{
	int i;
	int core = rte_lcore_id();
	
	assert(fc != NULL);
	/* free file blocks */
	for (i = 0; i < fc->fc_blkCnt; i++)
		bfree(core, fc->fc_blkPtr[i]);
	// close(fc->fc_fd);
	
	fc_ht_remove(file_cache_ht[core_id], fc);

	//free(fc);
	
	if (fc->fc_stat) {
		free(fc->fc_stat);
	}
	//rte_mempool_put(fc_pool[core_id], fc);
	poolFree(&filecache_pools[core_id], fc);
}
/*---------------------------------------------------------------------------*/
static void
CancelDiskIO(struct file_cache *fc, int cid)
{
	DiskIOSlave *pslave = g_dslaves[cid];
	FReadReq *frr;
	int i, j, fd, numPendingIOs = fc->fc_numPendingIOs;

	if (numPendingIOs == 0)
		return;

	fd = fc->fc_fd;
	for (i = 0; numPendingIOs > 0 && i < g_numDiskSlavesPerCore; i++) {
		for (j = 0; numPendingIOs > 0 && j < pslave[i].dis_numIOs; j++) {
			frr = pslave[i].dis_frr[j];
			if (frr->fr_fc->fc_fd == fd) {
				frr->fr_isCanceled = TRUE;
				numPendingIOs--;
			}
		}
	}
	assert(numPendingIOs == 0);
	//	fc->b_numPendingIOs = 0;
}
/*---------------------------------------------------------------------------*/
enum {CMD_INVALID,
	  CMD_FILE_OPEN,         /* open a file */
	  CMD_FILE_CLOSE,        /* close a file */
	  CMD_SEND_CONTENT,      /* send the content of a file (offset, length) */
	  CMD_ACKED_SEQNUM};     /* inform me of an ACKed sequence number */

/*---------------------------------------------------------------------------*/
static int
OpenFileForOffload(int cid, char *file_name, uint32_t fid, uint8_t *haddr)
{
  struct file_cache *fc;
  int fd = 0;
	
  /* fc should not have been allocated */
  assert((fc = fc_ht_search(file_cache_ht[cid], fid)) == NULL);

  /* create a file cache entry */
  // fc = calloc(1, sizeof(struct file_cache));
  /*if (rte_mempool_get(fc_pool[cid], (void**)&fc) < 0){
	  fprintf(stderr,"malloc() for file_cache failed\n");
	  exit(-1);
  }*/
  fc = poolMalloc(&filecache_pools[cid]);
  if (fc == NULL) {
	fprintf(stderr,"malloc() for file_cache failed\n");
	//   exit(-1);
	return 0;
  }

  rte_memcpy(fc->fc_haddr, haddr, sizeof(fc->fc_haddr));
  
  /* open the file with direct IO */
#if NO_FS_PERFTEST
  fd = fd_per_core[cid];
  lseek64(fd, 512000 * fd_file_count[cid], SEEK_SET);
  fd_file_count[cid]++;
  if (fd_file_count[cid] > 100000)
	fd_file_count[cid] = 0;
#else
  fd = open(file_name, O_RDONLY | O_DIRECT);
#endif
  if (fd < 0) {
	TRACE_ERROR("open() failed: %s errno: %d\n", file_name, errno);
	//   exit(-1);
	return 0;
  } 
  TRACE_DBG("(%d) Open file %s, fd: %d, fid: %u\n",
			rte_lcore_id(), file_name, fd, fid);
#if NO_FS_PERFTEST
  fc->fc_fileSize = 512000;
#elif INDEPENDENT_FSTAT
  fc->fc_fileSize = lseek64(fd, 0, SEEK_END);
#elif NICTOHOST_FSTAT
  fc->fc_stat = (struct stat*)malloc(sizeof(struct stat));
  if (fc->fc_stat == NULL) {
	TRACE_ERROR("malloc() failed\n");
	exit(-1);
  }
  fstat(fd, fc->fc_stat);
  fc->fc_fileSize = fc->fc_stat->st_size;
#endif
  fc->fc_fd    = fd;
  fc->fc_fid   = fid;
  snprintf(fc->fc_file, NAME_LIMIT, "%s", file_name);
  fc_ht_insert(file_cache_ht[cid], fc);
  
  
#ifdef SHOW_STATS
	g_numFlows[cid]++;
#endif

	return 1;
}
/*---------------------------------------------------------------------------*/
static void
CloseFileForOffload(int cid, uint32_t fid)
{
  struct file_cache *fc;
  
  fc = fc_ht_search(file_cache_ht[cid], fid);
  if (fc == NULL) {
	  fprintf(stderr,"(%d) fc NOT FOUND for closing (fid: %u)\n", cid, fid);
	  assert(fc != NULL);
	  exit(-1);
  }
  
  /* close the file cache */
  TRACE_DBG("(%d) fc found for closing (file: %s)\n", cid, fc->fc_file);
  
  /* cancel all pending I/Os associated with this file */
  CancelDiskIO(fc, cid);
  
  fc->fc_isClosed = TRUE;
  if (fc->fc_numPendingIOs == 0)
	  CloseFileCache(cid, fc); 
	  
#ifdef SHOW_STATS
	g_numFlows[cid]--;
#endif
}
/*---------------------------------------------------------------------------*/
static inline void
CopyIOVToBuf(uint8_t *buf, const struct iovec *iov, int cnt)
{
	int i, len = 0;

	// for (i = 1; i < cnt; i++) {
	// 	rte_memcpy(buf + len, iov[i].iov_base, iov[i].iov_len);
	// 	len += iov[i].iov_len;
	// }
	
	// /* loop-unrolled */
	// rte_memcpy(buf, iov[0].iov_base, iov[0].iov_len);
	// len = iov[0].iov_len;
	rte_memcpy(buf + len, iov[1].iov_base, iov[1].iov_len);
	if (cnt > 2) {
		rte_memcpy(buf + len + iov[1].iov_len, iov[2].iov_base, iov[2].iov_len);
		if (cnt > 3) {
			buf += (len + iov[1].iov_len + iov[2].iov_len);
			for (i = 3; i < cnt; i++) {
				rte_memcpy(buf, iov[i].iov_base, iov[i].iov_len);
				buf += iov[i].iov_len;
			}
		}
	} 
}
/*---------------------------------------------------------------------------*/

/* Define a free call back function to be used for external buffer */
static void
ext_buf_free_callback_fn(void *addr __rte_unused, void *opaque)
{
	struct shinfo_ctx *shinfo = opaque;
	// struct rte_mbuf_ext_shared_info *shinfo = opaque;
	if (shinfo != NULL) {
		rte_mempool_put(shinfo_pool[shinfo->core_id], shinfo);
		// rte_free(shinfo);
	}
	// void *ext_buf_addr = opaque;

	// if (ext_buf_addr == NULL) {
	// 	printf("External buffer address is invalid\n");
	// 	return;
	// }
	// rte_free(ext_buf_addr);
	// ext_buf_addr = NULL;
	// printf("External buffer freed via callback\n");
}

/*---------------------------------------------------------------------------*/
static int
GenerateTSOPacket(uint16_t core_id, uint16_t port, uint8_t* phdr, int hdrlen,
				  struct file_cache *fc, off_t foff, int flen)
{
  struct rte_mbuf *m, *payloadm, *prev;
  struct rte_ether_hdr *ethh;
  struct rte_ipv4_hdr *iph;
  struct rte_tcp_hdr *tcph;
  int len = 0, i; //hdrlen = 0;
  int *pbytes = &g_numBytesToSend[core_id];
  struct shinfo_ctx *ret_shinfo = NULL;
  // struct rte_mbuf_ext_shared_info *ret_shinfo = NULL;
  rte_iova_t buf_iova;
  void *ext_buf_addr = NULL;
  uint16_t buf_len;
  int off, idx, cnt = 0;
  void* io_base;
  size_t io_len;
  off = foff - fc->fc_blkStartOff;
  idx = CACHEBLKIDX(off);
  off = CACHEBLKOFF(off);

  // uint8_t *payload;

  /* calculate total length (= ethernet/ip/tcp headers + tcp payload) */
  // hdrlen = iov[0].iov_len;
  // for (i = 1; i < iovcnt; i++)
  //	  len += iov[i].iov_len;
  // assert(len < MAX_TSO_PKTSIZE);
  
  /* allocate an mbuf for sending */
  m = get_wptr(core_id, port, hdrlen);
  ethh = (struct rte_ether_hdr *)rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
  assert(ethh != NULL);

  /* copy header data */
  rte_memcpy((uint8_t *)ethh, phdr, hdrlen);

  /* set up some parameters */
  iph  = (struct rte_ipv4_hdr *)(ethh + 1);
  tcph = (struct rte_tcp_hdr *)(iph + 1);

  m->l2_len    = sizeof(struct rte_ether_hdr);
  m->l3_len    = sizeof(struct rte_ipv4_hdr);
  m->l4_len    = GET_TCP_HEADER_LEN(tcph);
  m->tso_segsz = MTU - (m->l3_len + m->l4_len);
  m->ol_flags |= PKT_TX_IPV4 | PKT_TX_TCP_CKSUM |
	             PKT_TX_IP_CKSUM | PKT_TX_TCP_SEG;

  prev = m;

  for (i = idx; flen > 0 && i < MAX_BLOCKS; i++, cnt++) {
	// for (i = 1; i < iovcnt; i++) {
 	if(rte_mempool_get(shinfo_pool[core_id], (void **)&ret_shinfo) < 0) {
		TRACE_ERROR("FAILED TO GET SHINFO FROM MEMPOOL\n");
			exit(-1);
	}
	// ret_shinfo = (struct rte_mbuf_ext_shared_info *)rte_malloc("shinfo", sizeof(struct rte_mbuf_ext_shared_info *), RTE_CACHE_LINE_SIZE);
	io_base = fc->fc_blkPtr[i] + off;
	io_len = MIN(flen, fc->fc_blkLen[i] - off);
	flen -= io_len;
	off = 0;
	len += io_len;

	ext_buf_addr = io_base;
	buf_iova = getIOVA(core_id, ext_buf_addr);
	buf_len = io_len;
	ret_shinfo->shinfo.free_cb = ext_buf_free_callback_fn;
	ret_shinfo->shinfo.fcb_opaque = ret_shinfo;
	ret_shinfo->core_id = core_id;
	rte_mbuf_ext_refcnt_set(&ret_shinfo->shinfo, 1);
	// ret_shinfo->free_cb = ext_buf_free_callback_fn;
	// ret_shinfo->fcb_opaque = ret_shinfo;
	// rte_mbuf_ext_refcnt_set(ret_shinfo, 1);
	payloadm = rte_pktmbuf_alloc(pktmbuf_pool[core_id]);

	payloadm->nb_segs = 1;
	payloadm->next    = NULL;

	prev->next = payloadm;
	m->pkt_len += payloadm->data_len;
	// fprintf(stderr, "pkt_len: %u, payloadm:%d\n", m->pkt_len, payloadm->data_len);
	m->nb_segs += 1;

	prev = payloadm;

	rte_pktmbuf_attach_extbuf(payloadm, ext_buf_addr, buf_iova, buf_len, &ret_shinfo->shinfo);

	rte_pktmbuf_reset_headroom(payloadm);
	rte_pktmbuf_adj(payloadm, io_len);

	// fprintf(stderr, "Attaching payload with buf %p and len %u so m has now a pkt_len of %u with m->next pointing to %p (%p)\n", ext_buf_addr, buf_len, m->pkt_len, m->next, payloadm);

	payloadm->data_len = io_len;
	payloadm->data_off = 0;

	if (payloadm->ol_flags != EXT_ATTACHED_MBUF) {
		fprintf(stderr, "FAILED TO ATTACH EXTERNAL MBUF\n");
		exit(-1);
	}
}

  iph->total_length     = htons(hdrlen + len - ETHERNET_HEADER_LEN);
  iph->type_of_service  = 0;  /* FIX ME: WHY?? */
  iph->hdr_checksum     = 0;
  tcph->cksum           = 0;

  *pbytes += hdrlen + len;
  TRACE_DBG("GenerateTSOPacket pbytes: %d\n",*pbytes);
#define THRESHOLD_PACKETS (16 * MTU)
  if (*pbytes >= THRESHOLD_PACKETS) {
 	  TRACE_DBG("send_pkts \n");
	  send_pkts(core_id, port);
	  *pbytes = 0;
  }

#ifdef SHOW_STATS
  g_numBytesSent[core_id] += hdrlen + len;
#endif
  //send_pkts(core_id, port);
  //*pbytes = 0;

  return 1;
}
/*---------------------------------------------------------------------------*/
/* return TRUE if the requested content is already in file cache memory */
static inline int
CanServeFromCache(struct file_cache *fc, off_t off, int len)
{
	return ((off >= fc->fc_blkStartOff) &&
			(off + len) <= (fc->fc_blkStartOff + fc->fc_blkSize));
}
/*---------------------------------------------------------------------------*/
static int
CreateIOVFromCache(struct iovec *iov, int iovcnt,
				   struct file_cache *fc, off_t foff, int flen)
{
	int off, idx, i, len, cnt = 0;
	
	assert(fc->fc_blkStartOff <= foff);
	off = foff - fc->fc_blkStartOff;
	idx = CACHEBLKIDX(off);
	off = CACHEBLKOFF(off);
	assert(off >= 0 && idx < MAX_BLOCKS);
	
	for (i = idx; flen > 0 && i < MAX_BLOCKS; i++, cnt++) {
		iov[cnt].iov_base = fc->fc_blkPtr[i] + off;
		len = MIN(flen, fc->fc_blkLen[i] - off);
		iov[cnt].iov_len = len;
		flen -= len;
		off   = 0;
	}
	assert(cnt <= iovcnt);
	assert(flen == 0);
	return cnt;
}
/*---------------------------------------------------------------------------*/
static void
SendEchoPacket(uint16_t core_id, uint16_t port, uint8_t* phdr, int flen)
{
	struct rte_mbuf *m;
	struct rte_ether_hdr *ethh;
	struct rte_ipv4_hdr *iph;
	struct rte_tcp_hdr *tcph;
	uint32_t tmp_addr;
	uint16_t tmp_port;	
	uint8_t tmp_eth_addr[RTE_ETHER_ADDR_LEN];
	char p[128];
	int p_len;
	int hdrlen;

 	ethh = (struct rte_ether_hdr *) phdr;
	assert(ethh != NULL);
	
	/* set up some parameters */
	iph  = (struct rte_ipv4_hdr *)(ethh + 1);
	tcph = (struct rte_tcp_hdr *)(iph + 1);

	hdrlen = ETHERNET_HEADER_LEN + IP_HEADER_LEN + (GET_TCP_HEADER_LEN(tcph));
	
	p_len = snprintf(p, 128, "SEND %d", flen);
	m = get_wptr(core_id, port, hdrlen + p_len);
	ethh = (struct rte_ether_hdr *)rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	rte_memcpy(ethh, phdr, hdrlen);
	iph = (struct rte_ipv4_hdr *)(ethh + 1);
	tcph = (struct rte_tcp_hdr *)(iph + 1);
	
	/* swap ethernet addrs */
	rte_memcpy(tmp_eth_addr, ethh->d_addr.addr_bytes, sizeof(tmp_eth_addr));
	rte_memcpy(ethh->d_addr.addr_bytes,
			   ethh->s_addr.addr_bytes, sizeof(tmp_eth_addr));
	rte_memcpy(ethh->s_addr.addr_bytes, tmp_eth_addr, sizeof(tmp_eth_addr));

	/* mark it special */
	iph->type_of_service = 4;
	iph->total_length = htons(hdrlen + p_len - ETHERNET_HEADER_LEN);

	/* swap IP addrs */
	tmp_addr = iph->src_addr;
	iph->src_addr = iph->dst_addr;
	iph->dst_addr = tmp_addr;

	/* swap port numbers */
	tmp_port = tcph->src_port;
	tcph->src_port = tcph->dst_port;
	tcph->dst_port = tmp_port;

	rte_memcpy((uint8_t *)ethh + hdrlen, p,  p_len);

	m->l2_len    = sizeof(struct rte_ether_hdr);
	m->l3_len    = sizeof(struct rte_ipv4_hdr);
	m->l4_len    = GET_TCP_HEADER_LEN(tcph);
}
/*---------------------------------------------------------------------------*/
static void
SendOpenEchoPacket(uint16_t core_id, uint16_t port, uint8_t* phdr, int offload_fid,
			int offload_open_status)
{
	struct rte_mbuf *m;
	struct rte_ether_hdr *ethh;
	struct rte_ipv4_hdr *iph;
	struct rte_tcp_hdr *tcph;
	uint32_t tmp_addr;
	uint16_t tmp_port;	
	uint8_t tmp_eth_addr[RTE_ETHER_ADDR_LEN];
	char p[128];
	int p_len;
	int hdrlen;
	struct file_cache *fc;

 	ethh = (struct rte_ether_hdr *) phdr;
	assert(ethh != NULL);
	
	/* set up some parameters */
	iph  = (struct rte_ipv4_hdr *)(ethh + 1);
	tcph = (struct rte_tcp_hdr *)(iph + 1);

	hdrlen = ETHERNET_HEADER_LEN + IP_HEADER_LEN + (GET_TCP_HEADER_LEN(tcph));
	
	fc = fc_ht_search(file_cache_ht[core_id], offload_fid);

#if WHOLE_FSTAT
	p_len = snprintf(p, 128, "OPEN %d %d ", offload_fid, offload_open_status);
	memcpy(p + p_len, fc->fc_stat, sizeof(struct stat));
	p_len += sizeof(struct stat);
#else
	p_len = snprintf(p, 128, "OPEN %d %d %d", offload_fid, offload_open_status, fc->fc_stat->st_size);
#endif

	m = get_wptr(core_id, port, hdrlen + p_len);
	ethh = (struct rte_ether_hdr *)rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	rte_memcpy(ethh, phdr, hdrlen);
	iph = (struct rte_ipv4_hdr *)(ethh + 1);
	tcph = (struct rte_tcp_hdr *)(iph + 1);
	
	/* swap ethernet addrs */
	rte_memcpy(tmp_eth_addr, ethh->d_addr.addr_bytes, sizeof(tmp_eth_addr));
	rte_memcpy(ethh->d_addr.addr_bytes,
			   ethh->s_addr.addr_bytes, sizeof(tmp_eth_addr));
	rte_memcpy(ethh->s_addr.addr_bytes, tmp_eth_addr, sizeof(tmp_eth_addr));

	/* mark it special */
	iph->type_of_service = 4;
	// fprintf(stderr, "[%d] hdrlen %d p_len %d sizeof(struct stat) %d \n",__LINE__, hdrlen, p_len, sizeof(struct stat));
	iph->total_length = htons(hdrlen + p_len - ETHERNET_HEADER_LEN);

	/* swap IP addrs */
	tmp_addr = iph->src_addr;
	iph->src_addr = iph->dst_addr;
	iph->dst_addr = tmp_addr;

	/* swap port numbers */
	tmp_port = tcph->src_port;
	tcph->src_port = tcph->dst_port;
	tcph->dst_port = tmp_port;

	rte_memcpy((uint8_t *)ethh + hdrlen, p, p_len);

	m->l2_len    = sizeof(struct rte_ether_hdr);
	m->l3_len    = sizeof(struct rte_ipv4_hdr);
	m->l4_len    = GET_TCP_HEADER_LEN(tcph);
}
/*---------------------------------------------------------------------------*/
static void
UpdateTimestampOption(uint8_t *topt, int totlen, uint32_t ts_diff)
{
	int i, optlen;
	int kind;
	
	for (i = 0; i < totlen; i++) {
		kind   = *(topt + i++);  /* 1-byte KIND */
		optlen = *(topt + i++);  /* 1-byte Length */
		if (kind == TCP_OPT_TIMESTAMP) {
			uint32_t tval = ntohl(*(uint32_t *)(topt + i));
			tval += ts_diff;
			*(uint32_t *)(topt + i) = htonl(tval);
			return;
		}
		i += (optlen - 2); /* skip other options */
	}
}
/*---------------------------------------------------------------------------*/
static void
WritePacketsToSend(uint16_t core_id, uint16_t port,
				   struct file_cache *fc, uint8_t* phdr, int hdrlen,
				   double timestamp, uint64_t foff, int flen)
{
	// struct iovec iov[MAX_IOV+1];
	int cnt, len, maxlen_tso_packet, maxlen_per_packet;
	struct rte_tcp_hdr *tcph;
	uint32_t seq;
	uint32_t diff = (uint32_t)(GetCurrentTimeMsec() - timestamp);
	// diff = 0;
	tcph = (struct rte_tcp_hdr *)
		   (((struct rte_ipv4_hdr *)((struct rte_ether_hdr *)phdr + 1)) + 1);
	
	/* maxlen_tso_packet
       = max TSO packet payload size (MAX_TSO_PKTSIZE (offload_write.h))
         - ETHERNET/IP/TCP/HEADER+options (hdrlen)
         - mbuf-overhead (RTE_PKTMBUF_HEADROOM)
       it should be a multiple of maxpayload_per_packet (MTU-TCP/IP headers)
	   future work: align src/dst buffer ptrs to 16-byte boundary
                    need cooperation from the host side
	*/
	maxlen_tso_packet  = (MAX_TSO_PKTSIZE - hdrlen - RTE_PKTMBUF_HEADROOM);
	maxlen_per_packet  = (MTU - hdrlen + ETHERNET_HEADER_LEN); // 1446
	maxlen_tso_packet -= (maxlen_tso_packet % maxlen_per_packet);

	/* Ethernet/IP/TCP headers and IP/TCP options */
	if (diff > 0) 
		UpdateTimestampOption((uint8_t *)tcph + TCP_HEADER_LEN,
							  GET_TCP_HEADER_LEN(tcph) - TCP_HEADER_LEN, diff);
	// iov[0].iov_base = phdr;
	// iov[0].iov_len  = hdrlen;

	/* check the seq number is continuous */
	seq = ntohl(tcph->sent_seq);
	assert(TCP_SEQ_GEQ(fc->fc_nextSeq, seq));
#ifdef SHOW_STATS
	if (TCP_SEQ_GT(fc->fc_nextSeq, seq)) {
		g_numBytesResent[core_id] += MIN((int)(fc->fc_nextSeq - seq), flen);
	}
#endif
	if (TCP_SEQ_LT(fc->fc_nextSeq, seq + flen))
		fc->fc_nextSeq = seq + flen;
	
	TRACE_DBG("(%d) SEND-w (name: %s off:%10ld off+len:%10ld "
			  "len:%5d seq: %10u dst: %u)\n", core_id, fc->fc_file,
			  foff, foff+flen, flen,
			  ntohl(tcph->sent_seq), ntohs(tcph->dst_port));

	/* Send back the echo packet before the header is manipulated */
	SendEchoPacket(core_id, port, phdr, flen);
	
	/* payloadlen could be larger than 64K */
	while (flen > 0) {
		len = MIN(flen, maxlen_tso_packet);
		// cnt = CreateIOVFromCache(&iov[1], MAX_IOV, fc, foff, len);
		// assert(cnt > 0 && cnt <= MAX_IOV);
		
		/* FIX: the current version ignores any options in the IP headers */
		if (GenerateTSOPacket(core_id, port, phdr, hdrlen, fc, foff, len) <= 0) {
			TRACE_ERROR("No packets were sent\n");
			exit(-1); /* better stop here */
		}
		
		foff += len;
		flen -= len;		
		
		/* update the sequence number field of the TCP header */
		seq += len;
		tcph->sent_seq = htonl(seq);
	}
}
/*---------------------------------------------------------------------------*/
/*  Shift block buffers to the left by "cnt"                                 */
/*   - The first "cnt" blocks will lose the content (b_len becomes 0)        */
/*   - Then, they will be moved to the end                                   */
/*   - Other blocks will be shifted to the left by "cnt"                     */
/*  Let l = MAX_BLOCKS-cnt, conceptually it does                             */
/*     fc->fc_blkPtr[0..l-1] = fc->fc_ptr[cnt..MAX_BLOCKS-1]                   */
/*     fc->fc_blkPtr[l..MAX_BLOCKS-1] = fc->fc_blkPtr[0..cnt-1]                  */
/*---------------------------------------------------------------------------*/
static void
ShiftBufferToLeft(struct file_cache *fc, int cnt)
{
	int l, nbytes = (CACHEBLKSIZE * cnt);
	uint8_t *b_ptr[cnt];
	
	assert(cnt > 0 && cnt <= fc->fc_blkCnt);

	fc->fc_blkStartOff += nbytes;  /* file offset advances by nbytes */
	fc->fc_seqStartOff += nbytes;  /* TCP sequence number advances as well */
	fc->fc_blkSize     -= nbytes;  /* throw away nbytes of the content */
	assert(fc->fc_blkSize >= 0);
	if (cnt == fc->fc_blkCnt) {      /* special case */
		memset(&fc->fc_blkLen[0], 0, sizeof(int) * cnt);
		return;
	}
	
	/* back up the first "cnt" block pointers */
	rte_memcpy(b_ptr, &fc->fc_blkPtr[0], sizeof(uint8_t *) * cnt); 

	/* shift blocks to the left by "cnt" */
	l = fc->fc_blkCnt - cnt;
	memmove(&fc->fc_blkLen[0], &fc->fc_blkLen[cnt],  sizeof(int) * l);
	memmove(&fc->fc_blkPtr[0], &fc->fc_blkPtr[cnt],  sizeof(uint8_t *) * l); 

	/* the first "cnt" blocks will be moved to the end */
	memset(&fc->fc_blkLen[l], 0, sizeof(int) * cnt);
	rte_memcpy(&fc->fc_blkPtr[l], b_ptr, sizeof(uint8_t *) * cnt);
}
/*---------------------------------------------------------------------------*/
static void
AllocateFileBuffer(struct file_cache *fc, uint32_t seqnum, off_t foff, int flen)
{
	int num;

	/* make the initial offset block-algined */
	if (!DISKBLKALIGNED(foff)) {
		flen += DISKBLKOFF(foff);
		foff -= DISKBLKOFF(foff);                
	}
	num = NUMCACHEBLOCKS(flen);
	assert(num <= MAX_BLOCKS);
	if (balloc(rte_lcore_id(), fc->fc_blkPtr, num) != TRUE) {
		TRACE_ERROR("balloc() failed\n");
		exit(-1);
	}
	/* 
	   FIX: we support only reading from offset 0 for now 
	   but we need to support reading from an arbitrary offset 
	*/
	assert(foff == 0); 
	fc->fc_blkStartOff   = foff;
	fc->fc_seqStartOff   = seqnum;
	fc->fc_fileMaxReqOff = foff;
	fc->fc_blkCnt        = num;
	fc->fc_nextSeq       = seqnum;
}
/*---------------------------------------------------------------------------*/
static void
ExpandFileBuffer(struct file_cache *fc, int moreBytes)
{
	int num = NUMCACHEBLOCKS(moreBytes);
	int shiftLeft = (fc->fc_blkCnt + num) - MAX_BLOCKS;
	int alloc;

	if (fc->fc_blkCnt < MAX_BLOCKS) {
		alloc = (shiftLeft <= 0) ? num : (MAX_BLOCKS - fc->fc_blkCnt);
		if (balloc(rte_lcore_id(), &fc->fc_blkPtr[fc->fc_blkCnt], alloc) != TRUE) {
			TRACE_ERROR("balloc() failed\n");
			exit(-1);		
		}
		fc->fc_blkCnt += alloc;
	}

	assert(shiftLeft <= 0); /* ACKD should work! */
	if (shiftLeft > 0) {
		/* ideally, we should never do this if the host stack informs
		   the NIC stack of the ACK in time */
		assert (shiftLeft <= MAX_BLOCKS);
		ShiftBufferToLeft(fc, shiftLeft);
	}
}
/*---------------------------------------------------------------------------*/
static void
MergeDiskIO(FReadReq *f, int cid)
{
	DiskIOSlave *pslave = g_dslaves[cid];
	FReadReq *frr;
	int i, j;
	struct file_cache *fc;
	off_t last  = f->fr_foff + f->fr_flen;
	
	fc = f->fr_fc;
	for (i = 0; i < g_numDiskSlavesPerCore; i++) {
		for (j = 0; j < pslave[i].dis_numIOs; j++) {
			frr = pslave[i].dis_frr[j];
			if (frr->fr_fc == fc &&
				last <= (frr->fr_offset + frr->fr_totlen)) {
				/* found it */
				if (frr->fr_next == NULL) {
					assert(frr->fr_tail == NULL);
					assert(frr->fr_foff + frr->fr_flen >= f->fr_foff);
					frr->fr_next = frr->fr_tail = f;
				} else {
					assert(frr->fr_tail &&
						   (frr->fr_tail->fr_foff + frr->fr_tail->fr_flen
							>= f->fr_foff));
					frr->fr_tail->fr_next = f;
					frr->fr_tail = f;
				}
				return;
			}
		}
	}
	/* IMPOSSIBLE: we did not find the right entry! */
	assert(0);	
}
/*---------------------------------------------------------------------------*/
static FReadReq*
PrepareDiskRequest(uint16_t core_id, struct file_cache *fc, uint16_t port,  uint8_t *pkthdr,
				   int hdrlen, double timestamp, off_t foff, int flen)
{
	FReadReq *frr;
	int i, len, tlen, b_idx, b_off, spill;

	assert(hdrlen < MAX_HDRLEN);
	
	// if ((frr = calloc(1, sizeof(FReadReq))) == NULL) {
	/*if (rte_mempool_get(frr_pool[core_id], (void**)&frr) < 0) {
		TRACE_ERROR("calloc() failed\n");
		exit(-1); 
		return NULL;
	}*/
        frr = poolMalloc(&freadreq_pools[core_id]);
        if (frr == NULL) {
	  fprintf(stderr,"malloc() for file_cache failed\n");
	  exit(-1);
        }

	/* current time in miliseconds */
	frr->fr_timestamp = timestamp;

	/* FIX: we assume sequential reads from the host */
	frr->fr_offset = fc->fc_fileMaxReqOff;
	assert(foff <= frr->fr_offset && frr->fr_offset <= fc->fc_fileSize);

	/* - length is first expanded to be aligned to DISKBLKSIZE, but its
	     offset should not exceed the file size.

	   - note that the real transfer size to preadv() must be a mutiple
	     of a logical block size (typically 512 bytes).  If necessary,
	     the length of the last iov bufferh will be re-adjusted in
	     DiskSlaveMain().
	*/
	len = flen + (foff - frr->fr_offset);        /* off_t is signed! */
	if (len <= 0) {
		/* this implies that the previously-issued read I/O subsumes the
		   current request, so no need to issue a real disk I/O */
		frr->fr_totlen = -1;
	}
	else {
		assert(DISKBLKALIGNED(frr->fr_offset));
		len = NUMDISKBLOCKS(len) * DISKBLKSIZE;     /* aligned to DISKBLKSIZE */
		len = MIN (len, fc->fc_fileSize - frr->fr_offset); /*  <= file size */
		assert(len > 0 && len <= fc->fc_fileSize);
		fc->fc_fileMaxReqOff = frr->fr_offset + len;    /* record the last offset 
													   of the pending I/O */
		frr->fr_totlen = len;
	}
	
	/* cache original request */
	frr->fr_fc     = fc;
	frr->fr_foff   = foff;
	frr->fr_flen   = flen;
	frr->fr_port   = port;
	frr->fr_hdrlen = hdrlen;
	assert(hdrlen < MAX_HDRLEN);
	rte_memcpy(frr->fr_pkthdr, pkthdr, hdrlen);

	// frr->fr_iovcnt = 0;    /* already 0 due to calloc() */
	if (!IS_DISKIO_REAL(frr)) { /* no need to issue a real disk request? */
		MergeDiskIO(frr, rte_lcore_id());
		return NULL;
	}

	/*  allocate more buffers if needed */
	spill = (fc->fc_fileMaxReqOff -
			 (fc->fc_blkStartOff + (fc->fc_blkCnt * CACHEBLKSIZE)));
	if (spill > 0) {
		ExpandFileBuffer(fc, spill);
	}
	
	b_idx = CACHEBLKIDX(frr->fr_offset - fc->fc_blkStartOff);
	b_off = CACHEBLKOFF(frr->fr_offset - fc->fc_blkStartOff);
	assert(b_idx >= 0 && b_idx < MAX_BLOCKS);

	TRACE_DBG("Disk request: offset:%ld len:%d offset+len:%ld "
			  "b_idx:%d b_off:%d\n", frr->fr_offset, len, frr->fr_offset+len,
			  b_idx, b_off); 
	
	/* set up iov entries */
	for (i = 0; len > 0 && i < MAX_IOV; i++, b_idx++) {
		frr->fr_iov[i].iov_base = fc->fc_blkPtr[b_idx] + b_off;
		tlen = MIN(len, (CACHEBLKSIZE - b_off));
		frr->fr_iov[i].iov_len = tlen;
		frr->fr_iovcnt++;
		len  -= tlen;
		b_off = 0;
	}
	if (frr->fr_iovcnt > 4)
	        fprintf(stderr, "iovcnt %d\n", frr->fr_iovcnt);
	assert(len == 0);
	return frr;
}
/*---------------------------------------------------------------------------*/
static inline DiskIOSlave *
GetNextDiskSlave(int cid)
{
	DiskIOSlave *dis = g_dslaves[cid] + g_slaveIdx[cid];
	g_slaveIdx[cid] = (g_slaveIdx[cid] + 1)  % g_numDiskSlavesPerCore;
	return dis;
}
/*---------------------------------------------------------------------------*/
static void
SendRequestToDiskSlave(int cid, FReadReq *frr)
{
	DiskIOSlave *dis = GetNextDiskSlave(cid);
	int res;

	assert (dis->dis_numIOs < MAX_DISKIO);
	frr->fr_fc->fc_numPendingIOs++;
	dis->dis_frr[dis->dis_numIOs++] = frr;
	if ((res = write(dis->dis_fd, &frr, sizeof(frr))) != sizeof(frr)) {
		TRACE_ERROR("write() failed, res=%d errno=%d\n", res, errno);
		exit(-1);
	}
}
/*---------------------------------------------------------------------------*/
#define LAST_SEQNUM (0xFFFFFFFF)
static void
ProcessACK(struct file_cache *fc, uint32_t newAck)
{
	int ackedBytes = (fc->fc_seqStartOff < newAck) ?
		             (newAck - fc->fc_seqStartOff) :
	                 (newAck + (LAST_SEQNUM - fc->fc_seqStartOff) + 1);
	int shiftLeft;

    ackedBytes = MIN(ackedBytes, fc->fc_fileSize - fc->fc_blkStartOff);
	assert(ackedBytes <= fc->fc_blkSize);
	shiftLeft = ackedBytes/CACHEBLKSIZE;
	TRACE_DBG("Acked %d bytes, shift left by %d\n", ackedBytes, shiftLeft);
	if (shiftLeft > 0)
		ShiftBufferToLeft(fc, shiftLeft);
}
/*---------------------------------------------------------------------------*/
static  void
ProcessPacket(uint16_t core_id, uint16_t port, uint8_t *pktbuf, int totlen)
{
#define MAX_COMMAND 128                 /* max command length */
  struct rte_ether_hdr *ethh;
  struct rte_ipv4_hdr *iph;
  struct rte_tcp_hdr *tcph;
  char file_name[NAME_LIMIT];            /* file path */
  int  tcp_opt, hdrlen, p_len;           /* options, header, payload lengths */
  uint32_t fid = 0;                      /* file id */
  int flen;                              /* length to read */
  off_t foff;                            /* file offset to read */
  uint32_t acked;                        /* acked seq number */
  struct file_cache *fc;
  char p[MAX_COMMAND];
  int command = CMD_INVALID;
  unsigned char haddr[6];
  FReadReq *frr;
  double timestamp;
  int ret;

  /* record the arrival time of this request */
  timestamp = GetCurrentTimeMsec();
  
  ethh = (struct rte_ether_hdr *)pktbuf;
  iph = (struct rte_ipv4_hdr *)(ethh + 1);

  /* check errors first */
  if (unlikely(ethh->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) ||
	  unlikely(iph->type_of_service != 4)) {
	  /* 
	  tcph    = (struct rte_tcp_hdr *)(iph + 1);
	  tcp_opt = ((tcph->data_off & 0xf0) >> 2) - TCP_HEADER_LEN;
	  p_len   = ntohs(iph->total_length)
		         - (IP_HEADER_LEN + TCP_HEADER_LEN + tcp_opt);
	  TRACE_DBG("Dropping packet (conn: %u.%u.%u.%u:%u -> "
				"%u.%u.%u.%u:%u, seq:%u, payload_len:%d)\n",
				((ntohl(iph->src_addr) >> 24) & 0xff),
				((ntohl(iph->src_addr) >> 16) & 0xff),
				((ntohl(iph->src_addr) >> 8) & 0xff),
				((ntohl(iph->src_addr)) & 0xff),
				ntohs(tcph->src_port),
				((ntohl(iph->dst_addr) >> 24) & 0xff),
				((ntohl(iph->dst_addr) >> 16) & 0xff),
				((ntohl(iph->dst_addr) >> 8) & 0xff),
				((ntohl(iph->dst_addr)) & 0xff),
				ntohs(tcph->dst_port),
				ntohl(tcph->sent_seq),
				p_len); */
    //TRACE_DBG("Error Message \n");
    return;
  }

  /* process offload I/O requests */
  /* we assume no IP options */
  assert(((iph->version_ihl & 0x0f) << 2) == IP_HEADER_LEN);
  tcph    = (struct rte_tcp_hdr *)(iph + 1);
  tcp_opt = GET_TCP_HEADER_LEN(tcph) - TCP_HEADER_LEN;

  hdrlen = TOTAL_HEADER_LEN + tcp_opt;
  p_len  = ntohs(iph->total_length) - (hdrlen - ETHERNET_HEADER_LEN);
  assert(p_len > 0 && p_len < MAX_COMMAND);
  /* p_len  = MIN(p_len, MAX_COMMAND-1); */  /* paranoid but no need */
  
  /* let p point to the first payload byte in the packet */
  rte_memcpy(p, (uint8_t *)tcph + TCP_HEADER_LEN + tcp_opt, p_len);
  p[p_len] = 0; /* null-terminate the string */

  /* parse the command */
  if (memcmp(p, "SEND", 4) == 0) {
	  TRACE_DBG("Received SEND \n");
	  if (sscanf(p + 4, "%u %ld %d", &fid, &foff, &flen) == 3) {
	  	  TRACE_DBG("CMD_SEND_CONTENT %ld\n", foff);
		  command = CMD_SEND_CONTENT;
	  }
  }
  else if (memcmp(p, "ACKD", 4) == 0) {
	  TRACE_DBG("Received ACKD \n");
	  if (sscanf(p + 4, "%u %u", &fid, &acked) == 2) {
	  	  TRACE_DBG("CMD_ACKED_SEQNUM \n");
		  command = CMD_ACKED_SEQNUM;
	  }
  }
  else if (memcmp(p, "OPEN", 4) == 0) {
#if NO_FS_PERFTEST
	  assert(false);
#endif
	  if (sscanf(p + 4, "%u %s %hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				 &fid, file_name, 
				 &haddr[0], &haddr[1], &haddr[2],
				 &haddr[3], &haddr[4], &haddr[5]) == 8) {
		command = CMD_FILE_OPEN;

		TRACE_DBG("(%d) Received OFFLOAD_FLAG_OPEN "
					"(file: %s conn: %u.%u.%u.%u : %u -> %u.%u.%u.%u : %u)\n",
					rte_lcore_id(), file_name,
					((ntohl(iph->src_addr) >> 24) & 0xff),
					((ntohl(iph->src_addr) >> 16) & 0xff),
					((ntohl(iph->src_addr) >> 8) & 0xff),
					((ntohl(iph->src_addr)) & 0xff),
					ntohs(tcph->src_port),
					((ntohl(iph->dst_addr) >> 24) & 0xff),
					((ntohl(iph->dst_addr) >> 16) & 0xff),
					((ntohl(iph->dst_addr) >> 8) & 0xff),
					((ntohl(iph->dst_addr)) & 0xff),
					ntohs(tcph->dst_port));
		ret = OpenFileForOffload(core_id, file_name, fid, haddr);
#if NICTOHOST_FSTAT
		SendOpenEchoPacket(core_id, port, pktbuf, fid, ret);
#endif

		return; /* we're done */
	  }
  }
  else if (memcmp(p, "CLOS", 4) == 0) {
	  if (sscanf(p + 4, "%u", &fid) == 1) {
		  command = CMD_FILE_CLOSE;

		  TRACE_DBG("(%d) Received OFFLOAD_FLAG_CLOSE "
			"(file: %s conn: %u.%u.%u.%u : %u -> %u.%u.%u.%u : %u)\n",
			rte_lcore_id(), file_name, 
			((ntohl(iph->src_addr) >> 24) & 0xff),
			((ntohl(iph->src_addr) >> 16) & 0xff),
			((ntohl(iph->src_addr) >> 8) & 0xff),
			((ntohl(iph->src_addr)) & 0xff),
			ntohs(tcph->src_port),
			((ntohl(iph->dst_addr) >> 24) & 0xff),
			((ntohl(iph->dst_addr) >> 16) & 0xff),
			((ntohl(iph->dst_addr) >> 8) & 0xff),
			((ntohl(iph->dst_addr)) & 0xff),
			ntohs(tcph->dst_port));

		  CloseFileForOffload(core_id, fid);
		  return; /* we're done */
	  }
  }  
  if (command == CMD_INVALID) {  /* failed to parse the command */
	  TRACE_ERROR("Cannto recognize offload I/O request\n");
	  dump_pkt(pktbuf, totlen);
	  exit(-1);
  }
  
  /* find the file cache entry */
  fc = fc_ht_search(file_cache_ht[core_id], fid);
#if NO_FS_PERFTEST
  if (fc == NULL) {
    haddr[0] = 0x98;
    haddr[1] = 0x03;
    haddr[2] = 0x9b;
    haddr[3] = 0x1e;
    haddr[4] = 0xdd;
    haddr[5] = 0x48;
    OpenFileForOffload(core_id, file_name, fid, haddr);
    fc = fc_ht_search(file_cache_ht[core_id], fid);
  }
#else
  if (fc == NULL) {
	  TRACE_ERROR("(%u) Attempting to offload write "
				  "but cannot find the file cache entry. (fid: %u)\n",
				  core_id, fid);
	  dump_pkt(pktbuf, totlen);
	  exit(-1); /* better stop here */
  }
#endif
  /* try throwing away the acked content */
  if (command == CMD_ACKED_SEQNUM) {
	  TRACE_DBG("ProcessACK \n");
	  return;
	  ProcessACK(fc, acked);
	  return;
  }

  TRACE_DBG("(%d) SEND-r (fid: %u name: %s off:%10ld off+len:%10ld "
			"len:%5d seq: %10u) (%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u) \n",
			rte_lcore_id(), fid, fc->fc_file,
			foff, foff+flen, flen, ntohl(tcph->sent_seq),
			((ntohl(iph->src_addr) >> 24) & 0xff),
			((ntohl(iph->src_addr) >> 16) & 0xff),
			((ntohl(iph->src_addr) >> 8) & 0xff),
			((ntohl(iph->src_addr)) & 0xff),
			ntohs(tcph->src_port),
			((ntohl(iph->dst_addr) >> 24) & 0xff),
			((ntohl(iph->dst_addr) >> 16) & 0xff),
			((ntohl(iph->dst_addr) >> 8) & 0xff),
			((ntohl(iph->dst_addr)) & 0xff),
			ntohs(tcph->dst_port)); 
  
  if (unlikely(flen <= 0) || unlikely((foff + flen) > fc->fc_fileSize)) {
	  TRACE_ERROR("File offset or payloadlen is invalid! "
				  "(File: %s off: %lu payloadlen:%d, size: %lu)\n",
				  fc->fc_file, foff, flen, fc->fc_fileSize);
	  exit(-1); /* better stop here for debugging */
  }

  /* copies dest eth addr */
  rte_memcpy(ethh->d_addr.addr_bytes, fc->fc_haddr, sizeof(fc->fc_haddr));

	if (fc->fc_nextSeq && TCP_SEQ_LT(ntohl(tcph->sent_seq), fc->fc_nextSeq)) {
#ifndef NO_READ_PERFTEST
		if(pread(fc->fc_fd, tmpbuf, flen-(flen%512), foff-(foff%512)) < 0) {
			TRACE_DBG("pread() failed errno=%d at seq %u\n", errno, ntohl(tcph->sent_seq));
		}
#endif
	}
  
  /* check if we can send the content from memory without disk I/O */
  if (CanServeFromCache(fc, foff, flen)) {
	  WritePacketsToSend(core_id, port, fc,
						 pktbuf, hdrlen, timestamp, foff, flen);
	  return;
  }

  if (fc->fc_blkCnt == 0) {   /* allocate buffer if it's the first time */
	  AllocateFileBuffer(fc, ntohl(tcph->sent_seq), foff, flen);
  } 

  frr = PrepareDiskRequest(core_id, fc, port, pktbuf, hdrlen, timestamp, foff, flen);
  if (frr != NULL)
	  SendRequestToDiskSlave(core_id, frr);
}
/*---------------------------------------------------------------------------*/
static inline int
CheckReady(void)
{
	unsigned int ready = 0;
	unsigned int i;
	
	for (i = 0; i < rte_lcore_count(); i++) {
		if (ctx_array[i])
			ready += ctx_array[i]->ready;
	}
	assert(ready <= rte_lcore_count());
	return (ready == rte_lcore_count());
}
/*---------------------------------------------------------------------------*/
static void
InitDiskSlaves(int cid)
{
	DiskIOSlave *pslave;
	int i;
	
	g_dslaves[cid] = (DiskIOSlave *)calloc(g_numDiskSlavesPerCore,
										   sizeof(DiskIOSlave));
	if (g_dslaves[cid] == NULL) {
		TRACE_ERROR("malloc() failed core_id=%d\n", cid);
		exit(-1);
	}
	pslave = g_dslaves[cid];

	/* create disk slaves, and set up the fd */
	for (i = 0; i < g_numDiskSlavesPerCore; i++) {
		pslave[i].dis_cid = cid;
		pslave[i].dis_fd  = CreateDiskSlave(cid);
	}
}
/*---------------------------------------------------------------------------*/
static inline void
SkipContent(FReadReq *frr, int len)
{
	struct rte_tcp_hdr *tcph;
	uint32_t seq;

	tcph = (struct rte_tcp_hdr *)
		     (((struct rte_ipv4_hdr *)
			    ((struct rte_ether_hdr *)frr->fr_pkthdr + 1)) + 1);
	
	seq = ntohl(tcph->sent_seq);
	seq += len;
	tcph->sent_seq = htonl(seq);

	frr->fr_foff += len;
	frr->fr_flen -= len;
	assert(frr->fr_flen >= 0);
}
/*---------------------------------------------------------------------------*/
static inline void
WritePacketsFromMergedIO(FReadReq *frr, int cid, struct file_cache* fc)
{
	FReadReq *f, *next;

	f = frr->fr_next;
	do {
		WritePacketsToSend(cid, f->fr_port, fc, f->fr_pkthdr, f->fr_hdrlen,
						   f->fr_timestamp, f->fr_foff, f->fr_flen);
		next = f->fr_next;
		//free(f);
        	// rte_mempool_put(frr_pool[cid], f);
	        poolFree(&freadreq_pools[cid], f);
	} while ((f = next) != NULL);
}
/*---------------------------------------------------------------------------*/
static void
ResumeAfterDiskIO(int cid, DiskIOSlave *dis)
{
	FReadReq *frr = dis->dis_frr[0];
	struct file_cache* fc;
	int len, base, idx, off, i, tlen;

	fc = frr->fr_fc;
	fc->fc_numPendingIOs--; // one disk IO is done
	
	/* if a disk IO is canceled, just clean up frr and return */
	if (IS_DISKIO_CANCELED(frr)) 
		goto cleanup_frr;

	/* IOs must be a real disk IO */
	assert (IS_DISKIO_REAL(frr));
	
	/* update fc's content length only for a real disk IO */
	len  = frr->fr_totlen;
	base = (frr->fr_offset - fc->fc_blkStartOff);
	assert(base == fc->fc_blkSize);
	idx  = CACHEBLKIDX(base);
	off  = CACHEBLKOFF(base);
	fc->fc_blkSize += len;
	tlen = MIN(len, (CACHEBLKSIZE - off));
	for (i = idx; len > 0 && i < MAX_BLOCKS; i++) {
		fc->fc_blkLen[i] += tlen;
		len -= tlen;
		tlen = MIN(len, CACHEBLKSIZE);
	}
	assert(len == 0);

	/* see if foff < startOff
	   if this is true, then it attempts to send an retransmission packet
	   whose content was aleady acked by the client (if partially) */
	len = fc->fc_blkStartOff - frr->fr_foff;
	if (len > 0) { /* if foff is smaller than startOff */
		TRACE_DBG("foff:%ld startOff: %ld len:%d, need to skip content\n",
				  frr->fr_foff, fc->fc_blkStartOff, len);
		if (len >= frr->fr_flen)
			goto cleanup_frr;
		SkipContent(frr, len);
	}
	
	WritePacketsToSend(dis->dis_cid, frr->fr_port,
					   fc, frr->fr_pkthdr, frr->fr_hdrlen,
					   frr->fr_timestamp, frr->fr_foff, frr->fr_flen);

	/* process all send requests covered by frr */
	if (frr->fr_next != NULL)
		WritePacketsFromMergedIO(frr, dis->dis_cid, fc);

cleanup_frr:
	/* handles a case where 'CLOS' arrives during other disk IOs */
	if (fc->fc_isClosed && fc->fc_numPendingIOs == 0) {
		CloseFileCache(dis->dis_cid, fc);
	}

	// free(frr);
        // rte_mempool_put(frr_pool[cid], frr);
	poolFree(&freadreq_pools[cid], frr);
	dis->dis_numIOs--;
	if (dis->dis_numIOs > 0) {
		memmove(dis->dis_frr, &dis->dis_frr[1],
				sizeof(dis->dis_frr[0]) * dis->dis_numIOs);
	}
}
/*---------------------------------------------------------------------------*/
static inline int
IsOffsetInOrder(FReadReq *frr)
{
	off_t lastOff = frr->fr_fc->fc_blkStartOff + frr->fr_fc->fc_blkSize;
	assert(frr->fr_offset >= lastOff);
	return (frr->fr_offset <= lastOff);
}
/*---------------------------------------------------------------------------*/
static void
ProcessDiskIODone(int cid)
{
	DiskIOSlave *pslave = g_dslaves[cid];
	int i, res = FALSE;
	FReadReq *frr;

	while (1) {
		for (i = 0; i < g_numDiskSlavesPerCore; i++) {
			if (pslave[i].dis_numIOs == 0)
				continue;

			frr = pslave[i].dis_frr[0]; /* the first request in the queue */
			if (IS_DISKIO_DONE(frr) &&
				(IsOffsetInOrder(frr) || IS_DISKIO_CANCELED(frr))) {	
				ResumeAfterDiskIO(cid, &pslave[i]);
				res = TRUE;
			}
		}
		if (!res) 
			return;
		res = FALSE; /* repeat until there are no more completed disk IOs */
	}
}
/*---------------------------------------------------------------------------*/
#ifdef SHOW_STATS
static void
ShowStatistics(double t)
{
#define MILLION (1000000)
	int64_t diff_bytes, diff_bytes_resent;
	int64_t total_bytes = 0, total_bytes_resent = 0;
	int i, total_flows = 0;
	int j, diskIOs = 0, total_diskIOs = 0;
	static int64_t lastNumBytesSent[MAX_CPUS] = {0};
	static int64_t lastNumBytesResent[MAX_CPUS] = {0};

	printf("--------------------------------------------------------"
		   "--------------------------------------------------------\n");
	printf("Parameters: disk block: %d KB, # of blocks: %d, "
		   "# of disk slaves per core: %d\n",
		   DISKBLKSIZE/1024, MAX_IOV, g_numDiskSlavesPerCore);
	for (i = 0; i < MAX_CPUS; i++) {
		diff_bytes = g_numBytesSent[i] - lastNumBytesSent[i];
		diff_bytes_resent = g_numBytesResent[i] - lastNumBytesResent[i];
		total_flows += g_numFlows[i];
		total_bytes += diff_bytes;
		total_bytes_resent += diff_bytes_resent;
		diskIOs = 0;
		for (j = 0; j < g_numDiskSlavesPerCore; j++) {
			if (g_dslaves[i])
				diskIOs += g_dslaves[i][j].dis_numIOs;
		}
		total_diskIOs += diskIOs;
		printf("Core %2d: # flows %6d # bytes %7.2f (MB) "
			   "# retransmit %7.2f (MB) TX rate %7.2f (Mbps) DiskIOs %4d\n",
			   i, g_numFlows[i],  diff_bytes/(1024*1024.0),
			   diff_bytes_resent/(1024*1024.0), (diff_bytes * 8)/t/MILLION,
			   diskIOs);
		lastNumBytesSent[i] = g_numBytesSent[i];
		lastNumBytesResent[i] = g_numBytesResent[i];
	}
	printf("--------------------------------------------------------"
		   "--------------------------------------------------------\n");
	printf("Total  : # flows %6d # bytes %7.2f (MB) "
		   "# retransmit %7.2f (MB) TX rate %7.2f (Mbps) DiskIOs %4d\n",
		   total_flows, total_bytes/(1024*1024.0),
		   total_bytes_resent/(1024*1024.0),  (total_bytes * 8)/t/MILLION,
		   total_diskIOs);
}
#endif
/*---------------------------------------------------------------------------*/
/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
/*---------------------------------------------------------------------------*/
int forward_main_loop(__attribute__((unused)) void *arg)
{
	uint16_t port, core_id;
	struct thread_context *ctx;
	int i, send_cnt, recv_cnt;
#ifdef SHOW_STATS
	struct timeval last, now;
	int firstRun = TRUE;
#endif
	
#define TRY_PROFILE 0
#if TRY_PROFILE
#define TIMEVAL_TO_USEC(t)	((unsigned long) ((1000000) * (t)->tv_sec	\
											  + (t)->tv_nsec/1000))
#define M_THRESHOLD    1000  /* 1000 us */
#define CORE_THRESHOLD 2000  /* 2000 us */
	struct timespec temp_ts = {0};
	unsigned long p_ts, m_ts, loop_ts;
	
#define GETTIME_BEGIN(x)                                \
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &temp_ts);	\
	(x) = TIMEVAL_TO_USEC(&temp_ts);
	
#define GETTIME_END(diff, start, thresh, core, f)          \
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &temp_ts);	   \
	(diff) = TIMEVAL_TO_USEC(&temp_ts) - (start);		   \
	if ((diff) > (thresh)) {							   \
		fprintf(stderr, "[%u] " f " took %lu microseconds\n", (core), (diff)); \
	}
#else
#define GETTIME_BEGIN(x)  (void)0
#define GETTIME_END(diff, start, thresh, core, f) (void)0
#endif
	
	core_id = rte_lcore_id();
	thread_local_init(core_id);

#if NO_FS_PERFTEST
#define NUM_NVME 4
	char file_name[100];
	strcpy(file_name, "/dev/nvme0n1");
	file_name[9] = (core_id % NUM_NVME) + 4 + '0';
        file_name[12] = 0;
	fd_per_core[core_id] = open(file_name, O_RDONLY | O_DIRECT);
	if (fd_per_core[core_id] < 0)
		fprintf(stderr, "open Error %s\n", file_name);
#endif
	assert(false);
        poolInitialize(&filecache_pools[core_id], sizeof(struct file_cache), 100000);
        poolInitialize(&freadreq_pools[core_id], sizeof(struct freadreq), 100000);

	/* allocate shared cache memory */
	if (core_id == 0)
		AllocateCacheMemory(g_cacheMemorySize, MAX_CPUS);
	
	/* initialize disk IO slaves */
	InitDiskSlaves(core_id);
	
	ctx = ctx_array[core_id];
	ctx->ready = 1;
	
	if (CheckReady()) {
		fprintf(stderr, "CPU[%d] Initialization finished\n"
				"Now start forwarding.\n\n",
				rte_lcore_id());
	} else {
		fprintf(stderr, "CPU[%d] Initialization finished\n"
				"Wait for other cores.\n\n",
				rte_lcore_id());
		while (!CheckReady()) ;
		usleep(100);
	}
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
			rte_eth_dev_socket_id(port) != (int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
				   "polling thread.\n\tPerformance will "
				   "not be optimal.\n",
				   port);
	
	printf("Core %u forwarding packets. [Ctrl+C to quit]\n\n", rte_lcore_id());
	
	/* Run until the application is quit or killed. */
	for (;;) {
		
		/* Get timestamp at start of the loop */
		GETTIME_BEGIN(loop_ts);
		
		RTE_ETH_FOREACH_DEV(port) {
			uint16_t len;
			uint8_t *pktbuf;
			
			/* Receive Packets */
			GETTIME_BEGIN(p_ts);
			recv_cnt = recv_pkts(core_id, port);
			GETTIME_END(m_ts, p_ts, M_THRESHOLD, core_id, "recv_pkts()");
			
#if VERBOSE_TCP
			if (recv_cnt > 0)
				fprintf(stderr, "recv_pkts: %d\n", recv_cnt);
#endif /* VERBOSE_TCP */
			
			/* Process Received Packets */
			GETTIME_BEGIN(p_ts);
			for (i = 0; i < recv_cnt; i++) {
				pktbuf = get_rptr(core_id, port, i, &len);
				if (pktbuf != NULL) {
#if 0
					fprintf(stderr, "\nReceived Packet from port %d\n", port);
					for (z = 0; z < len; z++)
						fprintf(stderr, "%02X%c", pktbuf[z],
								((z + 1) % 16 ? ' ' : '\n'));
					fprintf(stderr, "\n");
#endif /* VERBOSE_TCP */
					ProcessPacket(core_id, port, pktbuf, len);
				}
			}
			GETTIME_END(m_ts, p_ts, M_THRESHOLD, core_id, "ProcessPacket()");
			
			/* see if any disk IO is done */
			GETTIME_BEGIN(p_ts);
			ProcessDiskIODone(core_id);
			GETTIME_END(m_ts, p_ts,
						M_THRESHOLD, core_id, "ProcessDiskIODone()");
			
			/* Send Packets */
			GETTIME_BEGIN(p_ts);
			send_cnt = send_pkts(core_id, port);
			GETTIME_END(m_ts, p_ts, M_THRESHOLD, core_id, "send_pkts()");
			
#if VERBOSE_TCP
			if (send_cnt > 0)
				fprintf(stderr, "send_pkts: %d\n", send_cnt);
#else  
			UNUSED(send_cnt);
#endif 
		}
		
#ifdef SHOW_STATS
		GETTIME_BEGIN(p_ts);
		if (core_id == 0) {
			double t;
			
			gettimeofday(&now, NULL);
			if (firstRun) {
				last = now;
				firstRun = FALSE;
			}
			t = (now.tv_sec - last.tv_sec) +
				1e-6 * (now.tv_usec - last.tv_usec);
			if (t > 2) {
				ShowStatistics(t);
				last = now;
			}
		}
		GETTIME_END(m_ts, p_ts, M_THRESHOLD, core_id, "ShowStatistics()");
#endif
		GETTIME_END(m_ts, loop_ts, CORE_THRESHOLD, core_id, "!! core loop"); 
	}
	
	thread_local_destroy(rte_lcore_id());
	return 0;
}
