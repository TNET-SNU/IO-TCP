#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <pthread.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>
#include <sys/mman.h>             // for mlock()

#include <rte_memzone.h>

#include "diskslave.h"
#include "offload_write.h"

typedef struct FreeBlkStruct
{
  int64_t fb_size;                    /* # of (main) free blocks */
  TAILQ_ENTRY(FreeBlkStruct) fb_link;
} FreeBlkStruct;

/* just to have its type defined */
typedef struct FreeBlkHead {
  FreeBlkStruct  *tqh_first; /* first element */	
  FreeBlkStruct **tqh_last;  /* addr of last next element */
} FreeBlkHead;

typedef struct freeBlkManager
{
	uint8_t*    fm_startPtr;     /* pointer to the start pointer */
	int         fm_ntotblks;     /* total number of blocks */
	int         fm_nfreeblks;    /* number of free blocks */
	int         fm_blksize;      /* size of one block */
	FreeBlkHead fm_head;         /* head of the free block tailq */
	rte_iova_t  fm_iova;				 /* DPDK IOVA */
} FreeBlkManager;

static FreeBlkManager fbman[MAX_CPUS];

//static pthread_mutex_t g_lock;   /* a global lock to access the memory */

/*-------------------------------------------------------------------------*/
/* allocates "num" memory blocks of a fixed size (CACHEBLKSIZE) */
/* each element in pblks[0..num-1] is assigned a pointer to
   PAGE-ALIGNED memory block of a fixed size. */
/*-------------------------------------------------------------------------*/
static int
allocateBlks(FreeBlkManager *m, uint8_t** pblks, int num)
{
	FreeBlkStruct *walk, *newfb;
	int i, avail, idx = 0;
	uint8_t *ptr;
	
	assert(m->fm_nfreeblks >= num);
	assert(m->fm_nfreeblks <= m->fm_ntotblks);
	while (num > 0 && (walk = TAILQ_FIRST(&m->fm_head)) != NULL) {
		avail = (num <= walk->fb_size) ? num : walk->fb_size;
		ptr   = (uint8_t *)walk;
		for (i = 0; i < avail; i++) {
			pblks[idx++] = ptr;
			ptr += m->fm_blksize;   /* ptr advances by CACHEBLKSIZE */
		}
		
		num             -= avail;
		m->fm_nfreeblks -= avail;   /* # total free blocks decreases */
		walk->fb_size   -= avail;   /* # free blocks of walk decreases  */
		TAILQ_REMOVE(&m->fm_head, walk, fb_link);

		/* free blocks left in the current slot? */
		if (walk->fb_size > 0) {
			newfb = (FreeBlkStruct *)ptr;
			// memset(newfb, 0, sizeof(*newfb)); // no need
			newfb->fb_size = walk->fb_size;
			TAILQ_INSERT_HEAD(&m->fm_head, newfb, fb_link);
		}
	}
	assert(num == 0);
	return (num == 0);
}
/*-------------------------------------------------------------------------*/
static void
freeBlks(FreeBlkManager *m, uint8_t* pblk, int num)
{
	FreeBlkStruct *fb;
	
	m->fm_nfreeblks += num;
	fb = (FreeBlkStruct *)pblk;
	//	memset(fb, 0, sizeof(*fb)); // no need
	fb->fb_size = num;
	TAILQ_INSERT_TAIL(&m->fm_head, fb, fb_link);
}
/*-------------------------------------------------------------------------*/
static void
InitFBMan(int core, uint8_t *init_addr, rte_iova_t iova, int64_t size)
{
	FreeBlkManager *pfbman = &fbman[core];
	FreeBlkStruct *fb;
	
	pfbman->fm_startPtr  = init_addr;
	pfbman->fm_blksize   = CACHEBLKSIZE;
	pfbman->fm_ntotblks  = NUMCACHEBLOCKS(size);
	pfbman->fm_nfreeblks = pfbman->fm_ntotblks;
	pfbman->fm_iova			 = iova;
	TAILQ_INIT(&pfbman->fm_head);

	/* init the first free block */
	fb = (FreeBlkStruct *)pfbman->fm_startPtr;
	// memset(fb, 0, sizeof(*fb));  // no need
	fb->fb_size = pfbman->fm_ntotblks;
	TAILQ_INSERT_TAIL(&pfbman->fm_head, fb, fb_link);
}
/*-------------------------------------------------------------------------*/
void 
AllocateCacheMemory(int64_t size, int ncores)
{
	//int i, res;
	int i;
	uint8_t *init_addr;
	rte_iova_t init_iova;
	int64_t size_per_core;
	const struct rte_memzone *mz;
	
	/* align the size to multiples of CACHEBLKSIZE */
	/* fbman.fm_startPtr, */
	size -= CACHEBLKOFF(size);
	fprintf(stderr,"memzone_reserve_aligned 1\n");
	mz = rte_memzone_reserve_aligned("Cache Memory", size, SOCKET_ID_ANY, RTE_MEMZONE_IOVA_CONTIG, getpagesize());
	fprintf(stderr,"memzone_reserve_aligned 2\n");
	if (mz == NULL) {
	// The function failed; examine rte_errno to find out why
		int err = rte_errno;
		printf("Function failed with error code: %d\n", err);
		// You can then handle the error accordingly, perhaps with a switch statement
		switch (err) {
			case ENOSPC:
				printf("No more room in the configuration.\n");
				break;
        case EEXIST:
            printf("A memzone with the given name already exists.\n");
            break;
        case EINVAL:
            printf("Invalid parameter, such as alignment not being a power of two, or requested size too big, etc.\n");
            break;
        case ENOMEM:
            printf("Not enough memory to fulfill the request.\n");
            break;
        // Add more cases as necessary for different error codes
        default:
            printf("An unrecognized error occurred.\n");
    }
} else {
		printf("Allocated memzone %ld, %d\n",size, getpagesize());
}
	if (mz == NULL) {
		printf("Cannot allocate memzone %ld, %d",size, getpagesize());
		exit(-1);
	}

	init_addr = mz->addr;
	init_iova = mz->iova;

	fprintf(stderr,"Got mz of addr %p and iova %lu\n", mz->addr, mz->iova);
	// if ((res = posix_memalign((void **)&init_addr,
	// 						  getpagesize(), size)) != 0) {
	// 	TRACE_ERROR("posix_memalign failed size=%ld error=%d, errno=%d\n",
	// 				size, res, errno);
	// 	exit(-1);
	// }
	// /* ensure all pages are in physical RAM */
	// if ((res = mlock(init_addr, size)) < 0) {
	// 	TRACE_ERROR("mlock() failed size=%ld error=%d, errno=%d\n",
	// 				size, res, errno);
	// 	exit(-1);
	// }

	/* initialize per-core FBman */
	assert((size & (size-1)) == 0);     /* must be 2^n */
	assert((ncores & (ncores-1)) == 0); /* must be 2^n */
	size_per_core = size/ncores;
	for (i = 0; i < ncores; i++) {
		InitFBMan(i, init_addr, init_iova, size_per_core);
		// InitFBMan(i, init_addr, size_per_core);
		init_addr += size_per_core;
		init_iova += size_per_core;
	}

	/* init a mutex lock */
	//	if (pthread_mutex_init(&g_lock, NULL) != 0) {
	//		TRACE_ERROR("pthread_mutex_init() failed,");
	//		exit(-1);
	//	}
}
#if 0
/*-------------------------------------------------------------------------*/
#define LOCK()										  \
	if (pthread_mutex_lock(&g_lock) != 0) {           \
	    TRACE_ERROR("pthread_mutex_lock() failed\n"); \
        exit(-1);                                     \
	}

#define UNLOCK() 									    \
	if (pthread_mutex_unlock(&g_lock) != 0) {           \
	    TRACE_ERROR("pthread_mutex_unlock() failed\n"); \
        exit(-1);                                       \
	}
#endif

/*-------------------------------------------------------------------------*/
/* allocate "num" blocks */
/*-------------------------------------------------------------------------*/
int
balloc(int core, uint8_t** pblks, int num)
{
	int res;

	/* FIX: current LOCK() and UNLOCK() are based on a big lock that
	   is too coarse-grained.  if lock contention is too heavy,
	   consider finer-grained locks (shared memory per fewer threads)
    */
	
	//	LOCK();
	res = allocateBlks(&fbman[core], pblks, num);
	//	UNLOCK();
	return res;
}
/*-------------------------------------------------------------------------*/
/* free one block */
/*-------------------------------------------------------------------------*/
void
bfree(int core, uint8_t *pblk)
{
	//	LOCK();
	freeBlks(&fbman[core], pblk, 1);
	//	UNLOCK();
}


rte_iova_t
getIOVA(int core, uint8_t *ptr)
{
	FreeBlkManager *fm = &fbman[core];
	// fprintf(stderr, "got iova %lu with diff %lu\n", fm->fm_iova, RTE_PTR_DIFF(ptr, fm->fm_startPtr));
	// fprintf(stderr, "returning buf iova: %lu\n", fm->fm_iova + RTE_PTR_DIFF(ptr, fm->fm_startPtr));
	return (fm->fm_iova + RTE_PTR_DIFF(ptr, fm->fm_startPtr));
}
