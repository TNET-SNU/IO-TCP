#ifndef _DISK_SLAVE_H_
#define _DISK_SLAVE_H_

#include <sys/uio.h>
#include <inttypes.h>
#define MAX_CPUS      8 

/* modern compilers caculate and plug in constant numbers at compilation
   instead of making the code calculate them at runtime */

#define _NUMBLOCKS(x, bsize)     (((x) + (bsize)-1)/(bsize))

#define CACHEBLKBITS             (17)                      /* 2^17 = 128KB */
#define CACHEBLKSIZE             ((0x1) << CACHEBLKBITS)   /* 1 << 17 */
#define NUMCACHEBLOCKS(x)        _NUMBLOCKS(x, CACHEBLKSIZE);
#define CACHEBLKIDX(x)           ((x) >> CACHEBLKBITS)     /*(x)/CACHEBLKSIZE */
#define CACHEBLKOFF(x)           ((x) & (CACHEBLKSIZE-1))

/* typical  physical page size of an nvme device is 4KB */
#define DISKBLKBITS              (17)                      /* 2^17 = 128KB */
#define DISKBLKSIZE              ((0x1) << DISKBLKBITS)    /* 1 << 17 */
#define NUMDISKBLOCKS(x)         _NUMBLOCKS(x, DISKBLKSIZE)
#define DISKBLKOFF(x)            ((x) & (DISKBLKSIZE-1))
#define DISKBLKALIGNED(x)        (DISKBLKOFF(x) == 0)

/* logical disk block */
#define LDISKBLKBITS             (9)                       /* 2^9 = 512B */
#define LDISKBLKSIZE             ((0x1) << LDISKBLKBITS)   /* 1 << 9 */
#define NUMLDISKBLOCKS(x)        _NUMBLOCKS(x, LDISKBLKSIZE)
#define LDISKBLKOFF(x)           ((x) & (LDISKBLKSIZE-1))
#define LDISKBLKALIGNED(x)       (LDISKBLKOFF(x) == 0)

#define IS_DISKIO_DONE(x)        ((x)->fr_isDone == TRUE)
#define IS_DISKIO_CANCELED(x)    ((x)->fr_isCanceled == TRUE)
#define IS_DISKIO_REAL(x)        ((x)->fr_totlen > 0)

#define MAX_IOV		4 //2            /* should be the same as MAX_BLOCKS */
#define MAX_HDRLEN  128          /* max length for ethernet/ip/tcp headers */ 
typedef struct freadreq
{
	off_t              fr_offset;           /* start file offset to read
									          must be aligned to DISKBLKSIZE */
	struct iovec       fr_iov[MAX_IOV];     /* point to fc->b_ptr */
	int                fr_iovcnt;           /* # of iovs */
	int                fr_totlen;           /* total # of bytes to read */
	int                fr_isDone;           /* is the file IO done? */
	int                fr_isCanceled;       /* is this IO canceled? */
	struct freadreq*   fr_next;             /* merged disk IO list next */
	struct freadreq*   fr_tail;             /* merged disk IO list tail */
	
	/* original request info */
	double             fr_timestamp;          /* request arrival time */
	struct file_cache *fr_fc;                 /* file cache pointer */
	off_t              fr_foff;               /* original file offset */
	int                fr_flen;               /* original file length */
	int                fr_port:16;            /* port number: 16 bits */
	int                fr_hdrlen:16;          /* total header length: 16 bits */
	uint8_t            fr_pkthdr[MAX_HDRLEN]; /* Ethernet/IP/TCP headers */
} FReadReq;
// size of FReadReq = 
extern struct rte_mempool *frr_pool[MAX_CPUS];

#define MAX_DISKIO 512//256//128               /* max # of file read requests per slave */
typedef struct diskIOSlave
{
	int       dis_fd;                  /* fd */
	int       dis_cid;                 /* core id */
	int       dis_numIOs;              /* number I/Os queued */
	FReadReq *dis_frr[MAX_DISKIO];     /* frr pointers */
} DiskIOSlave;

int CreateDiskSlave(int cid);

#endif
