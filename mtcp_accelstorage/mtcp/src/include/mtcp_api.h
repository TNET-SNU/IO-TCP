#ifndef MTCP_API_H
#define MTCP_API_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef UNUSED
#define UNUSED(x)	(void)x
#endif

#ifndef INPORT_ANY
#define INPORT_ANY	(uint16_t)0
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OFFLOAD_FILE
#define OFFLOAD_FILE
#define OFFLOAD_FLAG_OPEN				0x01	// 0001
#define OFFLOAD_FLAG_CLOSE				0x02	// 0010
#define OFFLOAD_FLAG_ACKD				0x04	// 0100
#define OFFLOAD_ACKD_BYTES				(64*1024) // 64K
#define OFFLOAD_NAME_LIMIT				256
#define OFFLOAD_META_PAYLOAD_LIMIT		512
#endif

enum socket_type
{
	MTCP_SOCK_UNUSED, 
	MTCP_SOCK_STREAM, 
	MTCP_SOCK_PROXY, 
	MTCP_SOCK_LISTENER, 
	MTCP_SOCK_EPOLL, 
	MTCP_SOCK_PIPE, 
};

struct mtcp_conf
{
	int num_cores;
	int max_concurrency;

	int max_num_buffers;
	int rcvbuf_size;
	int sndbuf_size;

	int tcp_timewait;
	int tcp_timeout;
};

struct mtcp_stat
{
    uint64_t st_dev;		/* Device. __dev_t */
    uint64_t st_ino;		/* File serial number.	*/
    uint32_t st_mode;			/* File mode.  */
    uint64_t st_nlink;			/* Link count.  */
    uint32_t st_uid;		/* User ID of the file's owner.	*/
    uint32_t st_gid;		/* Group ID of the file's group.*/
    uint64_t st_rdev;		/* Device number, if device.  */
    uint64_t st_size;			/* Size of file, in bytes.  */
    uint64_t st_blksize;	/* Optimal block size for I/O.  */
    uint64_t st_blocks;		/* Number 512-byte blocks allocated. */
    int64_t _st_atime;			/* Time of last access.  */
    int64_t _st_mtime;			/* Time of last modification.  */
    int64_t _st_ctime;			/* Time of last status change.  */
};

typedef struct mtcp_context *mctx_t;

int 
mtcp_init(const char *config_file);

void 
mtcp_destroy();

int 
mtcp_getconf(struct mtcp_conf *conf);

int 
mtcp_setconf(const struct mtcp_conf *conf);

int 
mtcp_core_affinitize(int cpu);

mctx_t 
mtcp_create_context(int cpu);

void 
mtcp_destroy_context(mctx_t mctx);

typedef void (*mtcp_sighandler_t)(int);

mtcp_sighandler_t 
mtcp_register_signal(int signum, mtcp_sighandler_t handler);

int 
mtcp_pipe(mctx_t mctx, int pipeid[2]);

int 
mtcp_getsockopt(mctx_t mctx, int sockid, int level, 
		int optname, void *optval, socklen_t *optlen);

int 
mtcp_setsockopt(mctx_t mctx, int sockid, int level, 
		int optname, const void *optval, socklen_t optlen);

int 
mtcp_setsock_nonblock(mctx_t mctx, int sockid);

/* mtcp_socket_ioctl: similar to ioctl, 
   but only FIONREAD is supported currently */
int 
mtcp_socket_ioctl(mctx_t mctx, int sockid, int request, void *argp);

int 
mtcp_socket(mctx_t mctx, int domain, int type, int protocol);

int 
mtcp_bind(mctx_t mctx, int sockid, 
		const struct sockaddr *addr, socklen_t addrlen);

int 
mtcp_listen(mctx_t mctx, int sockid, int backlog);

int 
mtcp_accept(mctx_t mctx, int sockid, struct sockaddr *addr, socklen_t *addrlen);

int 
mtcp_init_rss(mctx_t mctx, in_addr_t saddr_base, int num_addr, 
		in_addr_t daddr, in_addr_t dport);

int 
mtcp_connect(mctx_t mctx, int sockid, 
		const struct sockaddr *addr, socklen_t addrlen);

int 
mtcp_close(mctx_t mctx, int sockid);

/** Returns the current address to which the socket sockfd is bound
 * @param [in] mctx: mtcp context
 * @param [in] addr: address buffer to be filled
 * @param [in] addrlen: amount of space pointed to by addr
 * @return 0 on success, -1 on error
 */
int
mtcp_getsockname(mctx_t mctx, int sock, struct sockaddr *addr, socklen_t *addrlen);
	
int
mtcp_getpeername(mctx_t mctx, int sockid, struct sockaddr *addr,
		 socklen_t *addrlen);

inline ssize_t
mtcp_read(mctx_t mctx, int sockid, char *buf, size_t len);

ssize_t
mtcp_recv(mctx_t mctx, int sockid, char *buf, size_t len, int flags);

/* readv should work in atomic */
int
mtcp_readv(mctx_t mctx, int sockid, const struct iovec *iov, int numIOV);

ssize_t
mtcp_write(mctx_t mctx, int sockid, const char *buf, size_t len);

/* writev should work in atomic */
int
mtcp_writev(mctx_t mctx, int sockid, const struct iovec *iov, int numIOV);

#ifdef __cplusplus
};
#endif

int
mtcp_offload_open(mctx_t mctx, int sockid, const char *file_name);

int
mtcp_offload_close(mctx_t mctx, int sockid, int offload_fid);

ssize_t
mtcp_offload_write(mctx_t mctx, int sockid, int offload_fid,
									 off_t *offset, size_t len);

int
mtcp_offload_fstat(mctx_t mctx, const int sockid, const int offload_fid,
					   struct mtcp_stat *buf);
int
mtcp_offload_stat(mctx_t mctx, const char *file_name,
					   struct mtcp_stat *buf);

#endif /* MTCP_API_H */
