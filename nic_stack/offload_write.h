#ifndef __OFFWRITE_H__
#define __OFFWRITE_H__

#define NDEBUG 
#include <assert.h>
#include <byteswap.h>
#include <inttypes.h>
#include <gmp.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_mempool.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_gso.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_version.h>
#include <rte_branch_prediction.h>

#include <sys/queue.h>

#include "option.h"
#include "diskslave.h"
#include "memalloc.h"

#define RTE_TEST_RX_DESC_DEFAULT 1024*2
#define RTE_TEST_TX_DESC_DEFAULT 1024*2

#define NUM_MBUFS 4096 //2048           // used to be 8192, 4096

#define MBUF_CACHE_SIZE 256  // 128      // used to be 250(?)

#define MAX_PKT_BURST 128 //32         // used to be 256, 128
#define MAX_CPUS      8
#define MAX_DPDK_PORT 2          // used to be 8

#define RX_PTHRESH 8
#define RX_HTHRESH 8
#define RX_WTHRESH 4

#define TX_PTHRESH 36
#define TX_HTHRESH 0
#define TX_WTHRESH 0

#define RX_IDLE_ENABLE TRUE

#define ETHER_TYPE_META 0x080F

/* TCP Flags */
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl(x >> 32))
#define ntohll(x) ((((uint64_t)ntohl(x)) << 32) + ntohl(x >> 32))

#ifdef MIN
#else
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifdef MAX
#else
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#define ALIGN(x, a) (((x) + (a)-1) & ~((a)-1))

#define MTU                 1500   // default MTU

#define ETHERNET_HEADER_LEN 14
#define IP_HEADER_LEN       20
#define TCP_HEADER_LEN      20
#define TOTAL_HEADER_LEN    54

#define TCP_OPT_NOP           1
#define TCP_OPT_TIMESTAMP     8
#define TCP_OPT_TIMESTAMP_LEN 10

#define NAME_LIMIT            256

/* maximum TSO packet size */
#define MAX_TSO_PKTSIZE (32*1024)

struct mbuf_table {
  uint16_t len; /* length of queued packets */
  struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct shinfo_ctx {
  uint16_t core_id;

  struct rte_mbuf_ext_shared_info shinfo;
};
extern struct rte_mempool *shinfo_pool[MAX_CPUS];

struct dpdk_private_context {
  struct mbuf_table rmbufs[RTE_MAX_ETHPORTS];
  struct mbuf_table wmbufs[RTE_MAX_ETHPORTS];
  struct rte_mempool *pktmbuf_pool;
  struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
#if NO_HARDWARE_TSO
  struct rte_mbuf *gso_pkts_burst[MAX_PKT_BURST];
#endif
#ifdef RX_IDLE_ENABLE
  uint8_t rx_idle;
#endif
} __rte_cache_aligned;

struct thread_context {
  int ready;
  uint16_t coreid;

  struct dpdk_private_context *dpc;
};

struct mtcp_stat {
    uint64_t _st_dev;		/* Device. __dev_t */
    uint64_t _st_ino;		/* File serial number.	*/
    uint32_t _st_mode;			/* File mode.  */
    uint64_t _st_nlink;			/* Link count.  */
    uint32_t _st_uid;		/* User ID of the file's owner.	*/
    uint32_t _st_gid;		/* Group ID of the file's group.*/
    uint64_t _st_rdev;		/* Device number, if device.  */
    uint64_t _st_size;			/* Size of file, in bytes.  */
    uint64_t _st_blksize;	/* Optimal block size for I/O.  */
    uint64_t _st_blocks;		/* Number 512-byte blocks allocated. */
    int64_t _st_atime;			/* Time of last access.  */
    int64_t _st_mtime;			/* Time of last modification.  */
    int64_t _st_ctime;			/* Time of last status change.  */
};

#define MAX_BLOCKS MAX_IOV
struct file_cache {
	uint32_t  fc_fid;               // file id in the host side 
	int       fc_fd;                // open file descriptor
	int64_t   fc_fileSize;          // total file size
	int       fc_isClosed;          // becomes TRUE when 'CLOS' arrives 
	int       fc_numPendingIOs;     // # of unfinished disk IOs
	uint32_t  fc_seqStartOff;       // TCP sequence number for fc_bstartOff
	int       fc_blkCnt;            // # of valid blocks that have content
	off_t     fc_fileMaxReqOff;     // max file offset requested so far
	off_t     fc_blkStartOff;       // file offset of the first byte of bptr[0]
	int       fc_blkSize;           // total number of bytes in the blocks
	int       fc_blkLen[MAX_BLOCKS];// length of an individual block
	uint8_t  *fc_blkPtr[MAX_BLOCKS];// pointers to file content blocks
	uint8_t   fc_haddr[6];          // dest ethernet addr. why here?
	TAILQ_ENTRY(file_cache) file_cache_link;
	struct mtcp_stat *fc_stat;

	// for debugging
	//#ifndef NDEBUG
	char      fc_file[NAME_LIMIT];  // filename, just for debugging
	uint32_t  fc_nextSeq;           // next TCP seq # to send out
	//#endif
};
extern struct rte_mempool *fc_pool[MAX_CPUS];

extern struct rte_mempool *pktmbuf_pool[MAX_CPUS];
extern struct thread_context *ctx_array[MAX_CPUS];

#if NO_HARDWARE_TSO
extern struct rte_mempool *gso_pool[MAX_CPUS];
extern struct rte_gso_ctx *gso_ctx_array[MAX_CPUS];
#endif


/* Functions */
/*--------------------------------------------------------------------------*/
/* main.c */
/*--------------------------------------------------------------------------*/
void global_destroy(void);

/*--------------------------------------------------------------------------*/
/* forward.c */
/*--------------------------------------------------------------------------*/
int forward_main_loop(__attribute__((unused)) void *arg);

/*--------------------------------------------------------------------------*/
/* dpdk_io.c */
/*--------------------------------------------------------------------------*/
void free_pkts(struct rte_mbuf **mtable, unsigned len);

int32_t recv_pkts(uint16_t core_id, uint16_t port);

uint8_t *get_rptr(uint16_t core_id, uint16_t port, int index, uint16_t *len);

int send_pkts(uint16_t core_id, uint16_t port);

struct rte_mbuf *get_wptr(uint16_t core_id, uint16_t port, uint16_t pktsize);

void dump_pkt(uint8_t *pktbuf, uint16_t pkt_len);

/*--------------------------------------------------------------------------*/
/* macros for debugging trace */
/*--------------------------------------------------------------------------*/
#if DEBUG_LOG
#define TRACE_DBG(f, m...) { \
	fprintf(stderr, "[%10s:%4d] " f, __FUNCTION__, __LINE__, ##m);	\
	}
#else
#define TRACE_DBG(f, m...)	(void)0
#endif

#if ERROR_LOG
#define TRACE_ERROR(f, m...) { \
	fprintf(stderr, "[ERROR] [%10s:%4d] " f, __FUNCTION__, __LINE__, ##m);	\
	}
#define TRACE_DBG2(f, m...) { \
	fprintf(stderr, "[%10s:%4d] " f, __FUNCTION__, __LINE__, ##m);	\
	}
#else
#define TRACE_ERROR(f, m...)	(void)0
#define TRACE_DBG2(f, m...)     (void)0
#endif

#endif /* __OFFWRITE_H__ */
