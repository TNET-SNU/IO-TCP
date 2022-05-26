#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "fhash.h"
#include "offload_write.h"

#define TCP_SEQ_LT(a, b)  ((int32_t)((a) - (b)) < 0)
#define TCP_SEQ_LEQ(a, b) ((int32_t)((a) - (b)) <= 0)
#define TCP_SEQ_GT(a, b)  ((int32_t)((a) - (b)) > 0)
#define TCP_SEQ_GEQ(a, b) ((int32_t)((a) - (b)) >= 0)
#define TCP_SEQ_BETWEEN(a, b, c) (TCP_SEQ_GEQ(a, b) && TCP_SEQ_LEQ(a, c))

#define TCP_OPT_END 0
#define TCP_OPT_OFFLOAD_WRITE 80
/* Junzhi Start */
#define TCP_OPT_ACK_SEQ 81
int64_t memuse[MAX_CPUS] = {0};
struct cc_hashtable *conn_cache_ht[MAX_CPUS];
/* Junzhi End */

/* maximum TSO packet size = 64 KB */
#define MAX_TSO_PKTSIZE (64*1024)

/*---------------------------------------------------------------------------*/
/* Function Prototype */

static inline void process_packet(uint16_t core_id, uint16_t port,
								  uint8_t *pktbuf, int len);

static inline int check_ready(void);

static int read_file(int fd, void *buf, int len, uint64_t offset);

/*---------------------------------------------------------------------------*/
static void
thread_local_init(int core_id)
{
  struct thread_context *ctx;
  struct dpdk_private_context *dpc;
  int nb_ports;
  int i, j;

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
      dpc->wmbufs[j].m_table[i] = rte_pktmbuf_alloc(pktmbuf_pool[core_id]);
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
  gso_ctx_array[core_id]->gso_size = MAX_PKT_SIZE;
#endif
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

#if 0
/*---------------------------------------------------------------------------*/
/* Junzhi Start */
static int
GetOffloadMetaTCPOption(uint8_t *tcpopt, unsigned int len, uint64_t *off,
						uint8_t *flags, uint16_t *fid, uint32_t *ack)
{
  unsigned int i;
  unsigned int opt, optlen;
  int ret = FALSE;

  for (i = 0; i < len;) {
    opt = *(tcpopt + i++);

    if (opt == TCP_OPT_END) { // end of option field
      break;
    } else if (opt == TCP_OPT_NOP) { // no option
      continue;
    } else {
      optlen = *(tcpopt + i++);

      if (i + optlen - 2 > len) {
	      break;
      }

      if (opt == TCP_OPT_OFFLOAD_WRITE) {
        *flags = (uint8_t) *(tcpopt + i++);

        *fid = *(uint16_t *) (tcpopt + i);
        i += sizeof(uint16_t);

        ret = TRUE;
      } else if (opt == TCP_OPT_ACK_SEQ) {
        *ack = *(uint32_t *)(tcpopt + i);
        i += sizeof(uint32_t);
        *off = *(uint64_t *)(tcpopt + i);
        i += sizeof(uint64_t);
        *fid = *(uint16_t *)(tcpopt + i);
        i += sizeof(uint16_t);
      } else {
        // not handle
        TRACE_DBG("Unknown meta option %d, length %d\n", opt, optlen);
        i += optlen - 2;
      }
    }
  }

  return ret;
}
#endif
/*---------------------------------------------------------------------------*/
static inline void
close_file_cache(struct file_cache *fc)
{
  close(fc->fd);
  free(fc);
  fc = NULL;
}
/*---------------------------------------------------------------------------*/
static inline void
close_conn_cache(uint16_t core_id, struct conn_cache *cc)
{
  cc_ht_remove(conn_cache_ht[core_id], cc);
  free(cc);
  cc = NULL;
}
/*---------------------------------------------------------------------------*/
static int
GeneratePayloadPackets(uint16_t core_id, uint16_t port, uint8_t *pktbuf,
					   int len, int payloadlen, uint64_t offset, int fd)
{
  struct rte_mbuf *m;
  struct rte_ether_hdr *ethh;
  struct rte_ipv4_hdr *iph;
  struct rte_tcp_hdr *tcph;
  uint8_t *buf;
  
  m = get_wptr(core_id, port, len + payloadlen);
  buf = (void *)rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
  assert(buf != NULL);

  memcpy(buf, pktbuf, len);
  if (read_file(fd, buf + len, payloadlen, offset) < 0) {
    TRACE_ERROR("File did not read\n");
    return -1;
  }

  ethh = (struct rte_ether_hdr *)rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
  iph  = (struct rte_ipv4_hdr *)(ethh + 1);
  tcph = (struct rte_tcp_hdr *)(iph + 1);

  iph->total_length = htons(len + payloadlen - ETHERNET_HEADER_LEN);
  iph->hdr_checksum = 0;
  tcph->cksum = 0;

  m->l2_len = sizeof(struct rte_ether_hdr);
  m->l3_len = sizeof(struct rte_ipv4_hdr);
  m->l4_len = (tcph->data_off & 0xf0) >> 2;
  m->tso_segsz = MAX_PKT_SIZE - (m->l3_len + m->l4_len);
  m->ol_flags |=
	  PKT_TX_IPV4 | PKT_TX_TCP_CKSUM | PKT_TX_IP_CKSUM | PKT_TX_TCP_SEG;

  return 1;

#if NO_HARDWARE_TSO
  /***
   * Fallback when there's no hardware offload TSO
   ***/

  struct dpdk_private_context *dpc;
  int pkts = 0;

  /* If packet fits in MTU, do not segment */
  if (len + payloadlen <= MAX_PKT_SIZE) {
    m = get_wptr(core_id, port, len + payloadlen);
    buf = (void *)rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    // assert(buf != NULL);

    memcpy(buf, pktbuf, len);
    if (read_file(fd, buf + len, payloadlen, offset) < 0) {
      TRACE_ERROR("File did not read\n");
      return -1;
    }

    ethh = (struct rte_ether_hdr *)rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    iph = (struct rte_ipv4_hdr *)(ethh + 1);
    tcph = (struct rte_tcp_hdr *)(iph + 1);

    iph->total_length = htons(len + payloadlen - ETHERNET_HEADER_LEN);
    iph->hdr_checksum = 0;
    tcph->cksum = 0;

    m->l2_len = sizeof(struct rte_ether_hdr);
    m->l3_len = sizeof(struct rte_ipv4_hdr);
    m->l4_len = (tcph->data_off & 0xf0) >> 2;

    m->ol_flags |=
      PKT_TX_IPV4 | PKT_TX_TCP_CKSUM | PKT_TX_IP_CKSUM;

    return 1;
  }

  /****
   * Sending packet with GSO
   * - BUG: Memory pool problems?
   * - BUG: Sometimes segments packets and sends packets without payloads
   *****/

  dpc = ctx_array[core_id]->dpc;

  /* Allocate packet buffer */
  m = get_wptr(core_id, port, len + payloadlen);
  assert(m != NULL);

  /* Make sure to send remaining packets first */
  send_pkts(core_id, port);

  /* Make a single packet to GSO */
  buf = (void *)rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
  m->ol_flags |=
      PKT_TX_IPV4 | PKT_TX_TCP_SEG | PKT_TX_TCP_CKSUM | PKT_TX_IP_CKSUM;

  memcpy(buf, pktbuf, len);
  if (read_file(fd, buf + len, payloadlen, offset) < 0) {
    TRACE_ERROR("File did not read\n");
    return -1;
  }
  
  ethh = (struct rte_ether_hdr *)buf;
  iph = (struct rte_ipv4_hdr *)(ethh + 1);
  tcph = (struct rte_tcp_hdr *)(iph + 1);

  m->l2_len = sizeof(struct rte_ether_hdr);
  m->l3_len = sizeof(struct rte_ipv4_hdr);
  m->l4_len = (tcph->data_off & 0xf0) >> 2;

  tcph->cksum = 0;

  pkts = rte_gso_segment(m, gso_ctx_array[core_id],
						 dpc->gso_pkts_burst, MAX_PKT_BURST);

  if (pkts <= 0) {
    fprintf(stderr, "\nERROR: Couldn't generate GSO segments\n");
    return -1;
  }

  /* Send GSO segments */
  struct rte_mbuf **pkts_burst;
  int ret, pkts_count, i;
  pkts_burst = dpc->gso_pkts_burst;
  pkts_count = pkts;
  do {
      ret = rte_eth_tx_burst(port, core_id, pkts_burst, pkts);
      pkts_burst += ret;
      pkts_count -= ret;
  } while (pkts_count > 0);

  for(i = 0; i < pkts; i++) {
    rte_pktmbuf_free(dpc->gso_pkts_burst[i]);
  }

  rte_pktmbuf_free(m);

  fprintf(stderr, "Sent %d packets for %u sized payload\n", pkts, payloadlen);

  return pkts;
#endif
}
/*---------------------------------------------------------------------------*/
static inline int
read_file(int fd, void *buf, int len, uint64_t offset)
{
	ssize_t ret;
	
	/* a regular file should read all content with one system call
	   we assume len and offset are correct (within the file boundary) */
	if ((ret = pread(fd, buf, len, offset)) != len) {
		/* something's wrong with pread */
		TRACE_ERROR("pread() failed, len=%d, offset=%ld, ret=%ld, errno=%d\n",
					len, offset, ret, errno);
		exit(-1);
	}
	return ret;
}

/*---------------------------------------------------------------------------*/
enum {CMD_INVALID, CMD_FILE_OPEN, CMD_FILE_CLOSE, CMD_SEND_CONTENT};
static int
process_offload_file_packet(uint16_t core_id, uint8_t *pktbuf,
							int cmd, char *file_name, uint16_t fid)
{
  struct rte_ether_hdr *ethh;
  struct rte_ipv4_hdr *iph;
  struct rte_tcp_hdr *tcph;
  struct conn_cache *cc;
  struct file_cache *fc;
  struct file_cache *walk;

  ethh = (struct rte_ether_hdr *)pktbuf;
  iph  = (struct rte_ipv4_hdr *)(ethh + 1);
  tcph = (struct rte_tcp_hdr *)(iph + 1);

  cc = cc_ht_search(conn_cache_ht[core_id], iph->src_addr,
					tcph->src_port, iph->dst_addr, tcph->dst_port);

  if (cmd == CMD_FILE_OPEN) {
    TRACE_DBG("(%d) Received OFFLOAD_FLAG_OPEN "
			  "(file: %s conn: %u.%u.%u.%u : %u -> %u.%u.%u.%u : %u)\n",
			  rte_lcore_id(), file_name, ((ntohl(iph->src_addr) >> 24) & 0xff),
			  ((ntohl(iph->src_addr) >> 16) & 0xff),
			  ((ntohl(iph->src_addr) >> 8) & 0xff),
			  ((ntohl(iph->src_addr)) & 0xff),
			  ntohs(tcph->src_port), ((ntohl(iph->dst_addr) >> 24) & 0xff),
			  ((ntohl(iph->dst_addr) >> 16) & 0xff),
			  ((ntohl(iph->dst_addr) >> 8) & 0xff),
			  ((ntohl(iph->dst_addr)) & 0xff),
			  ntohs(tcph->dst_port));
	
	/* not allocated yet? */
    if (cc == NULL) {
		cc = malloc(sizeof(struct conn_cache));
		if (cc == NULL) {
			TRACE_DBG("malloc() for conn_cache failed\n");
			exit(-1);
		}
		cc->saddr = iph->src_addr;
		cc->sport = tcph->src_port;
		cc->daddr = iph->dst_addr;
		cc->dport = tcph->dst_port;
		TAILQ_INIT(&cc->files);
		cc_ht_insert(conn_cache_ht[core_id], cc);
    }

    fc = malloc(sizeof(struct file_cache));
	if (fc == NULL) {
		TRACE_DBG("malloc() for file_cache failed\n");
		exit(-1);
	}
    TRACE_DBG("(%d) update fc info\n", rte_lcore_id());

    fc->initial_seq_set = FALSE;
    snprintf(fc->file_name, NAME_LIMIT, "%s", file_name);

    fc->fd = open(file_name, O_RDONLY);
    if (fc->fd < 0) {
      TRACE_ERROR("Opening file: %s errno: %d\n", file_name, errno);
      return -1;
    }
    TRACE_DBG("(%d) Open file %s, fd: %d, fid: %d\n",
			  rte_lcore_id(), file_name, fc->fd, fid);
    fc->size = lseek64(fc->fd, 0, SEEK_END);
    fc->file_id = fid;
    TAILQ_INSERT_TAIL(&cc->files, fc, file_cache_link);

    return 0;
  }

  /* must be file close */
  assert(cmd == CMD_FILE_CLOSE);

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
  
  if (cc != NULL) {
      TRACE_DBG("(%d) cc found for closing "
				"(file: %s, last_seq: %u last_ack: %u)\n",
				rte_lcore_id(), file_name, cc->last_seq, cc->last_ack);
	  
      /* close the file cache */
      TAILQ_FOREACH(walk, &cc->files, file_cache_link) {
		  if (fid == walk->file_id) {
			  TAILQ_REMOVE(&cc->files, walk, file_cache_link);
			  close_file_cache(walk);
			  break;
		  } 
      }
      if (TAILQ_EMPTY(&cc->files)) {
		  close_conn_cache(core_id, cc);
      }
  }
#ifdef DEBUG
  else {
	  TRACE_ERROR("(%d) cc NOT FOUND for closing "
				  "(file: %s, last_seq: %u last_ack: %u)\n",
				  rte_lcore_id(), file_name, cc->last_seq, cc->last_ack);
	  exit(-1);
  }
#endif
  
  return 0;
}
/*---------------------------------------------------------------------------*/
static inline void
process_packet(uint16_t core_id, uint16_t port, uint8_t *pktbuf, int totlen)
{
  struct rte_ether_hdr *ethh;
  struct rte_ipv4_hdr *iph;
  struct rte_tcp_hdr *tcph;
  char file_name[NAME_LIMIT];
  int ret, optlen;
  int payloadlen;
  uint16_t ip_len;
  uint16_t fid = 0;
  uint64_t off;
  struct conn_cache *cc;
  struct file_cache *fc;
  struct file_cache *walk;
  char *p;
  int command = CMD_INVALID;
 
  ethh = (struct rte_ether_hdr *)pktbuf;
  iph = (struct rte_ipv4_hdr *)(ethh + 1);

  /* check errors first */
  if (unlikely(ethh->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) ||
	  unlikely(iph->type_of_service != 4))
    return;

  /* Offload file/offload write packet */
  ip_len = ntohs(iph->total_length);
  tcph = (struct rte_tcp_hdr *)(iph + 1);
  optlen = ((tcph->data_off & 0xf0) >> 2) - TCP_HEADER_LEN;

  /* let p point to the first payload byte in the packet */
  p = (char *)tcph + TCP_HEADER_LEN + optlen;
  assert(ip_len > (TCP_HEADER_LEN + IP_HEADER_LEN));
  
  /* parse the command */
  if (memcmp(p, "OPEN", 4) == 0) {
	  if (sscanf(p + 4, "%hd %s", &fid, file_name) == 2) {
		  command = CMD_FILE_OPEN;
	  }
  } else if (memcmp(p, "CLOS", 4) == 0) {
	  if (sscanf(p + 4, "%hd", &fid) == 1) {
		  command = CMD_FILE_CLOSE;
	  }
  } else if (memcmp(p, "SEND", 4) == 0) {
	  if (sscanf(p + 4, "%hd %ld %d", &fid, &off, &payloadlen) == 3) {
		  command = CMD_SEND_CONTENT;
	  }
  } 
  if (command == CMD_INVALID) {
	  /* failed to parse the command */
	  TRACE_ERROR("Meta write packet malformed (OPEN)\n");
	  dump_pkt(pktbuf, totlen);
	  exit(-1);
  }
  
  /* process file open or close */
  if (command <= CMD_FILE_CLOSE) {
	  if (process_offload_file_packet(core_id, pktbuf,
									  command, file_name, fid) < 0) {
		  TRACE_ERROR("operation failed\n");
		  exit(-1); /* better stop here for debugging */
	  }
	  return;
  }
  
  /* find the connection cache entry */
  cc = cc_ht_search(conn_cache_ht[core_id], iph->src_addr, tcph->src_port,
					iph->dst_addr, tcph->dst_port);
  if (cc == NULL) {
	  TRACE_ERROR("Attempting to offload write but no connection is loaded.\n");
	  dump_pkt(pktbuf, totlen);
	  exit(-1); /* better stop here */
  }

  /* find the file cache entry */
  fc = NULL;
  TAILQ_FOREACH(walk, &cc->files, file_cache_link) {
    if (walk->file_id == fid) {
      fc = walk;
      break;
    }
  }
  if (fc == NULL) {
    TRACE_ERROR("Such file is not registered!\n");
	exit(-1); /* better stop here */
  }

  TRACE_DBG("(%d) Receive data packet (fid: %d name: %s)\n",
			rte_lcore_id(), fid, fc->file_name);

  TRACE_DBG("Offload packet received (fid: %u fd: %u "
			"conn: %u.%u.%u.%u : %u -> %u.%u.%u.%u : %u)\n",
			fid, fc->fd,
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

  if (unlikely(payloadlen <= 0) || unlikely(off + payloadlen > fc->size)) {
	  TRACE_ERROR("File offset or payloadlen is invalid! "
				  "(File: %s off: %lu payloadlen:%d, size: %lu)\n",
				  fc->file_name, off, payloadlen, fc->size);
	  exit(-1); /* better stop here */
  }
  tcph->cksum = 0; /* need to set it to 0 or NO NEED */

  /* FIX: forward to wood2 */
  ethh->d_addr.addr_bytes[0] = 0x98;
  ethh->d_addr.addr_bytes[1] = 0x03;
  ethh->d_addr.addr_bytes[2] = 0x9B;
  ethh->d_addr.addr_bytes[3] = 0x7F;
  ethh->d_addr.addr_bytes[4] = 0xC4;
  ethh->d_addr.addr_bytes[5] = 0x9C;

  if (!cc->initial_seq_set) {
    cc->initial_seq_set = TRUE;
    cc->initial_seq = (uint32_t)ntohl(tcph->sent_seq);
    cc->last_ack = cc->initial_seq;
    cc->last_seq = cc->initial_seq;
  }

  if (!fc->initial_seq_set) {
    fc->initial_seq_set = TRUE;
    fc->initial_seq = (uint32_t)ntohl(tcph->sent_seq);
    fc->last_ack = fc->initial_seq;
    fc->last_seq = fc->initial_seq;
    fc->current_off = fc->off;
  }

  TRACE_DBG("[CORE %d] Generating packet: "
			"(SEQ: %u, INIT_SEQ: %u, OFF: %lu LEN: %u)\n",
			core_id, ntohl(tcph->sent_seq), fc->initial_seq, off, payloadlen);

  /* payloadlen could be larger than 64K */
  while (payloadlen > 0) {
	  int plen;
	  uint32_t seq;

	  plen = (payloadlen > MAX_TSO_PKTSIZE)? MAX_TSO_PKTSIZE : payloadlen;
	  payloadlen -= plen;
	  /* FIX: the current version ignores any options in the TCP/IP headers */
	  ret = GeneratePayloadPackets(core_id, port, pktbuf,
								   TOTAL_HEADER_LEN, plen, off, fc->fd);
	  if (ret <= 0) {
		  TRACE_ERROR("No packets were sent\n");
		  exit(-1); /* better stop here */
	  }

	  off += plen;
	  seq = ntohl(tcph->sent_seq);
	  
	  if (TCP_SEQ_LT(cc->last_seq, seq)) {
		  cc->last_seq = fc->last_seq = seq + plen;
		  fc->current_off = off; 
	  }

	  /* need to advance to next seq number */
	  tcph->sent_seq = htonl(seq + plen);
  }
}
/*---------------------------------------------------------------------------*/
static inline int
check_ready(void)
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

  core_id = rte_lcore_id();
  thread_local_init(core_id);
  ctx = ctx_array[core_id];
  ctx->ready = 1;

  if (check_ready()) {
    fprintf(stderr, "CPU[%d] Initialization finished\n"
			"Now start forwarding.\n\n",
			rte_lcore_id());
  } else {
    fprintf(stderr, "CPU[%d] Initialization finished\n"
			"Wait for other cores.\n\n",
			rte_lcore_id());
    while (!check_ready()) {
    }
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

    RTE_ETH_FOREACH_DEV(port) {
      static uint16_t len;
      static uint8_t *pktbuf;

      /* Receive Packets */
      recv_cnt = recv_pkts(core_id, port);
#if VERBOSE_TCP
      if (recv_cnt > 0)
		  fprintf(stderr, "recv_pkts: %d\n", recv_cnt);
#endif /* VERBOSE_TCP */
	  
      /* Process Received Packets */
      for (i = 0; i < recv_cnt; i++) {
		  pktbuf = get_rptr(core_id, port, i, &len);
		  if (pktbuf != NULL) {
#if 0
			  fprintf(stderr, "\nReceived Packet from port %d\n", port);
			  for (unsigned z = 0; z < len; z++)
				  fprintf(stderr, "%02X%c", pktbuf[z],
						  ((z + 1) % 16 ? ' ' : '\n'));
			  fprintf(stderr, "\n");
#endif /* VERBOSE_TCP */
			  process_packet(core_id, port, pktbuf, len);
		  }
      }
	  
      /* Send Packets */
      send_cnt = send_pkts(core_id, port);
#if VERBOSE_TCP
      if (send_cnt > 0)
		  fprintf(stderr, "send_pkts: %d\n", send_cnt);
#else  /* VERBOSE_TCP */
      UNUSED(send_cnt);
#endif /* !VERBOSE_TCP */
    }
  }
  
  thread_local_destroy(rte_lcore_id());
  return 0;
}
