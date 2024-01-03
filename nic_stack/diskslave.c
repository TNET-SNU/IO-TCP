#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>          
#include <sys/socket.h>
#include <pthread.h>
#include <errno.h>
#include <sys/uio.h>             /* for preadv() */
#include <sched.h>		 /* for sched_setaffinity() */

#include "diskslave.h"
#include "offload_write.h"

typedef struct diskIOParams
{
	int	dip_fd;  /* pipe descriptor */
	int	dip_cid; /* core id */
} DiskIOParams;

/*-----------------------------------------------------------------------*/
static void *
DiskSlaveMain(void *arg)
{
	FReadReq *frr;
	DiskIOParams *params = (DiskIOParams *) arg;
	cpu_set_t set;
	ssize_t res;
	int fd = (int)(long)params->dip_fd;
	
	CPU_ZERO(&set);
	CPU_SET(params->dip_cid, &set);

	if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) == -1) {
		TRACE_ERROR("pthread_setaffinity_np() failed\n");
		exit(-1);
	}
	free(params); /* this thread no longer needs this data */

	while (1) {
		struct iovec *piov;
		
		/* read one file read request */
		if (read(fd, &frr, sizeof(frr)) != sizeof(frr)) {
			TRACE_ERROR("read() failed\n");
			exit(-1);
		}

		//#if 0
		if (IS_DISKIO_REAL(frr) && !IS_DISKIO_CANCELED(frr)) {
			/* adjust the transfer size block aligned (512B) */
			piov = &frr->fr_iov[frr->fr_iovcnt-1]; /* last iov entry pointer */
			if (!LDISKBLKALIGNED(piov->iov_len))
				piov->iov_len =	(NUMLDISKBLOCKS(piov->iov_len) * LDISKBLKSIZE);
			
#ifndef NO_READ_PERFTEST
			/* process the request */
			res = preadv(frr->fr_fc->fc_fd, frr->fr_iov,
						 frr->fr_iovcnt, frr->fr_offset);
			if (res < 0) {
				TRACE_ERROR("preadv() failed errno=%d, (frr->fr_fc->fc_fd:%d frr->fr_iov:%d frr->fr_iovcnt:%d frr->fr_offset%d\n", errno, frr->fr_fc->fc_fd, frr->fr_iov, frr->fr_iovcnt, frr->fr_offset);
				exit(-1);
			}
#endif
		}
		//#endif
		frr->fr_isDone = TRUE;
	}

	free(arg);
	return NULL;
}
/*-----------------------------------------------------------------------*/
int
CreateDiskSlave(int cid)
{
	DiskIOParams *params;
	int sockVec[2];
	pthread_t t;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockVec) < 0) {
		TRACE_ERROR("error doing sockpair\n");
		return (-1);
	}
	
	params = malloc(sizeof(*params));
	if (params == NULL) {
		TRACE_ERROR("malloc() failed\n");
		exit(-1);
	}
	params->dip_fd = sockVec[1];
	params->dip_cid = cid;
 
	if (pthread_create(&t, NULL, DiskSlaveMain, (void *) params) == -1) {
		TRACE_ERROR("pthread_create() failed, errno=%d\n", errno);
		return (-1);
	}
	
	return sockVec[0];
}
