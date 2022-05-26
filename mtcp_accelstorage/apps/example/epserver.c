#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>

#include <mtcp_api.h>
#include <mtcp_epoll.h>

#include "cpu.h"
#include "http_parsing.h"
#include "netlib.h"
#include "debug.h"

#define MAX_FLOW_NUM  (10000)

#define RCVBUF_SIZE (2*1024)
#define SNDBUF_SIZE (8*1024)

#define MAX_EVENTS (MAX_FLOW_NUM * 3)

#define HTTP_HEADER_LEN 1024
#define URL_LEN 128

#define NAME_LIMIT 256
#define FULLNAME_LIMIT 512

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define HT_SUPPORT FALSE

#ifndef MAX_CPUS
#define MAX_CPUS		16
#endif

/*----------------------------------------------------------------------------*/
struct server_vars
{
	char     request[HTTP_HEADER_LEN];
	int      recv_len;
	int      requests;
	int      offload_fd;
	off_t    offset;
	uint64_t total_sent;
	uint64_t fsize;					// file size
	uint8_t  done:1,
	         rspheader_sent:1,
	         keep_alive:1,
	         offload_ready:1;
};
/*----------------------------------------------------------------------------*/
struct thread_context
{
	mctx_t mctx;
	int ep;
	struct server_vars *svars;
};
/*----------------------------------------------------------------------------*/
static int num_cores;
static int core_limit;
static pthread_t app_thread[MAX_CPUS];
static int done[MAX_CPUS];
static char *conf_file = NULL;
static int backlog = -1;
/*----------------------------------------------------------------------------*/
const char *www_main;
/*----------------------------------------------------------------------------*/
static int finished;
/*----------------------------------------------------------------------------*/
static int max_keep_alive_requests = 100;
/*----------------------------------------------------------------------------*/
static char *
StatusCodeToString(int scode)
{
	switch (scode) {
		case 200:
			return "OK";
			break;

		case 404:
			return "Not Found";
			break;
	}

	return NULL;
}
/*----------------------------------------------------------------------------*/
void
CleanServerVariable(struct server_vars *sv)
{
	sv->recv_len = 0;
	sv->total_sent = 0;
	sv->done = 0;
	sv->rspheader_sent = 0;
	sv->keep_alive = 0;
	sv->offload_ready = 0;
	sv->offload_fd = 0;
	sv->offset = 0;
}
/*----------------------------------------------------------------------------*/
void 
CloseConnection(struct thread_context *ctx, int sockid, struct server_vars *sv)
{
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_DEL, sockid, NULL);
	mtcp_close(ctx->mctx, sockid);
}
/*----------------------------------------------------------------------------*/
static size_t 
SendUntilAvailable(struct thread_context *ctx,
				   int sockid, struct server_vars *sv)
{
	int ret;
	size_t sent;
	size_t len;
	struct mtcp_epoll_event ev;

	assert(sv->offload_ready);
	if (sv->done || !sv->rspheader_sent) {
		return 0;
	}

	sent = 0;
	len = sv->fsize - sv->total_sent;
	if (len > 0) {
		ret = mtcp_offload_write(ctx->mctx, sockid, sv->offload_fd,
								 &sv->offset, len);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				return sent;
			} else {
				/* If not EAGAIN or EINTR, close connection */
				TRACE_ERROR("Connection closed with client. errno=%d\n", errno);
				CloseConnection(ctx, sockid, sv);
				return sent;
			}
		}
		sent += ret;
		len  -= ret;
		sv->total_sent += ret;
	}

	/* if len > 0, this means that the send buffer is full, so when
	   you call mtcp_offload_write() again, it will return EAGAIN, so
	   no need to call it */
	if (len > 0) 
		return sent;

	assert(len == 0);
	sv->done = TRUE;
	finished++;
	
	mtcp_offload_close(ctx->mctx, sockid, sv->offload_fd);
	
	if (sv->keep_alive && 
		(max_keep_alive_requests < 0 ||
		 sv->requests < max_keep_alive_requests)) {
		/* if keep-alive connection, wait for the incoming request */
		ev.events = MTCP_EPOLLIN;
		ev.data.sockid = sockid;
		mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);
		CleanServerVariable(sv);
	}
	else {
		/* else, close connection */
		CloseConnection(ctx, sockid, sv);
	}

	return sent;
}
/*----------------------------------------------------------------------------*/
static int 
HandleReadEvent(struct thread_context *ctx, int sockid, struct server_vars *sv)
{
	struct mtcp_epoll_event ev;
	char url[URL_LEN];
	char response[HTTP_HEADER_LEN];
	char fname[FULLNAME_LIMIT];
	int scode;						// status code
	time_t t_now;
	char t_str[128];
	char keepalive_str[128];
	int ret;
	int left, len, request_len, sent, rd;
	struct stat sb; // 

	/* HTTP request handling */
	left = HTTP_HEADER_LEN - sv->recv_len - 1;
	ret = mtcp_read(ctx->mctx, sockid, sv->request + sv->recv_len, left);
	if (ret <= 0) {
		return ret;
	}
	sv->recv_len += ret;
	sv->request[sv->recv_len] = 0;
	request_len = find_http_header(sv->request, sv->recv_len);
	if (request_len <= 0) {
		TRACE_ERROR("Socket %d: Failed to parse HTTP request header.\n"
					"read bytes: %d, recv_len: %d, "
					"request_len: %d, strlen: %ld, request: \n%s\n", 
					sockid, ret, sv->recv_len, 
					request_len, strlen(sv->request), sv->request);
		return ret;
	}

	http_get_url(sv->request, request_len, url, URL_LEN);
	TRACE_APP("Socket %d URL: %s\n", sockid, url);
	sprintf(fname, "%s%s", www_main, url);
	TRACE_APP("Socket %d File name: %s\n", sockid, fname);

	sv->keep_alive = TRUE;
	if (http_header_str_val(sv->request, "Connection: ", 
				strlen("Connection: "), keepalive_str, 128)) {	
		if (strstr(keepalive_str, "Close") || strstr(keepalive_str, "close")) {
			sv->keep_alive = FALSE;
		}
	}

	/* Find file in cache */
	scode = 404;
	/* get the file size, see if it's accessible */
	rd = stat(fname, &sb);
	//	fprintf(stderr, "fname=%s\n", fname);
	if (rd == -1 || !S_ISREG(sb.st_mode) || !(sb.st_mode & S_IRUSR)) {
		sv->fsize = -1;
		/* should close the connection */
		TRACE_ERROR("File %s either not exist, not a regular file, "
					"or unreadable. Closing the connection\n", fname);
		return 0;
	} else {
		scode = 200;
		sv->fsize = sb.st_size;
		TRACE_APP("Socket %d File size: %ld (%ldMB)\n", 
				  sockid, sv->fsize, sv->fsize / 1024 / 1024);
	}

	sv->requests++;

	/* Response header handling */
	time(&t_now);
	strftime(t_str, 128, "%a, %d %b %Y %X GMT", gmtime(&t_now));
	if (sv->keep_alive)
		sprintf(keepalive_str, "keep-alive");
	else
		sprintf(keepalive_str, "close");

	if (max_keep_alive_requests > 0 &&
		sv->requests >= max_keep_alive_requests) {
		sprintf(keepalive_str, "close");
	}

	len = sprintf(response, "HTTP/1.1 %d %s\r\n"
				  "Date: %s\r\n"
				  "Server: Webserver on mTCP (Ubuntu)\r\n"
				  "Content-Length: %ld\r\n"
				  "Connection: %s\r\n\r\n", 
				  scode, StatusCodeToString(scode),
				  t_str, sv->fsize, keepalive_str);
	TRACE_APP("Socket %d HTTP Response: \n%s", sockid, response);
	sent = mtcp_write(ctx->mctx, sockid, response, len);
	TRACE_APP("Socket %d Sent response header: try: %d, sent: %d\n", 
			  sockid, len, sent);
	assert(sent == len);
	sv->rspheader_sent = TRUE;

	/* open the file */
	assert(!sv->offload_ready);
	rd = mtcp_offload_open(ctx->mctx, sockid, fname);
	if (rd < 0) {
		TRACE_ERROR("Error in offloading file: %s\n", fname);
		CloseConnection(ctx, sockid, sv);
		exit(-1); // better stop here for debugging
	}
	sv->offload_fd = rd;
	sv->offload_ready = TRUE;
	
	ev.events = MTCP_EPOLLIN | MTCP_EPOLLOUT;
	ev.data.sockid = sockid;
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);

	SendUntilAvailable(ctx, sockid, sv);

	return ret;
}
/*----------------------------------------------------------------------------*/
int 
AcceptConnection(struct thread_context *ctx, int listener)
{
	mctx_t mctx = ctx->mctx;
	struct server_vars *sv;
	struct mtcp_epoll_event ev;
	int c;

	c = mtcp_accept(mctx, listener, NULL, NULL);

	if (c >= 0) {
		if (c >= MAX_FLOW_NUM) {
			TRACE_ERROR("Invalid socket id %d.\n", c);
			return -1;
		}

		sv = &ctx->svars[c];
		CleanServerVariable(sv);
		sv->requests = 0;
		TRACE_APP("New connection %d accepted.\n", c);
		ev.events = MTCP_EPOLLIN;
		ev.data.sockid = c;
		mtcp_setsock_nonblock(ctx->mctx, c);
		mtcp_epoll_ctl(mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, c, &ev);
		TRACE_APP("Socket %d registered.\n", c);

	} else {
		if (errno != EAGAIN) {
			TRACE_ERROR("mtcp_accept() error %s\n", 
					strerror(errno));
		}
	}

	return c;
}
/*----------------------------------------------------------------------------*/
struct thread_context *
InitializeServerThread(int core)
{
	struct thread_context *ctx;

	/* affinitize application thread to a CPU core */
#if HT_SUPPORT
	mtcp_core_affinitize(core + (num_cores / 2));
#else
	mtcp_core_affinitize(core);
#endif /* HT_SUPPORT */

	ctx = (struct thread_context *)calloc(1, sizeof(struct thread_context));
	if (!ctx) {
		TRACE_ERROR("Failed to create thread context!\n");
		return NULL;
	}

	/* create mtcp context: this will spawn an mtcp thread */
	ctx->mctx = mtcp_create_context(core);
	if (!ctx->mctx) {
		TRACE_ERROR("Failed to create mtcp context!\n");
		free(ctx);
		return NULL;
	}

	/* create epoll descriptor */
	ctx->ep = mtcp_epoll_create(ctx->mctx, MAX_EVENTS);
	if (ctx->ep < 0) {
		mtcp_destroy_context(ctx->mctx);
		free(ctx);
		TRACE_ERROR("Failed to create epoll descriptor!\n");
		return NULL;
	}

	/* allocate memory for server variables */
	ctx->svars = (struct server_vars *)
			calloc(MAX_FLOW_NUM, sizeof(struct server_vars));
	if (!ctx->svars) {
		mtcp_close(ctx->mctx, ctx->ep);
		mtcp_destroy_context(ctx->mctx);
		free(ctx);
		TRACE_ERROR("Failed to create server_vars struct!\n");
		return NULL;
	}

	return ctx;
}
/*----------------------------------------------------------------------------*/
int 
CreateListeningSocket(struct thread_context *ctx)
{
	int listener;
	struct mtcp_epoll_event ev;
	struct sockaddr_in saddr;
	int ret;

	/* create socket and set it as nonblocking */
	listener = mtcp_socket(ctx->mctx, AF_INET, SOCK_STREAM, 0);
	if (listener < 0) {
		TRACE_ERROR("Failed to create listening socket!\n");
		return -1;
	}
	ret = mtcp_setsock_nonblock(ctx->mctx, listener);
	if (ret < 0) {
		TRACE_ERROR("Failed to set socket in nonblocking mode.\n");
		return -1;
	}

	/* bind to port 80 */
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(80);
	ret = mtcp_bind(ctx->mctx, listener, 
			(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		TRACE_ERROR("Failed to bind to the listening socket!\n");
		return -1;
	}

	/* listen (backlog: can be configured) */
	ret = mtcp_listen(ctx->mctx, listener, backlog);
	if (ret < 0) {
		TRACE_ERROR("mtcp_listen() failed!\n");
		return -1;
	}
	
	/* wait for incoming accept events */
	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = listener;
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, listener, &ev);

	return listener;
}
/*----------------------------------------------------------------------------*/
void *
RunServerThread(void *arg)
{
	int core = *(int *)arg;
	struct thread_context *ctx;
	mctx_t mctx;
	int listener;
	int ep;
	struct mtcp_epoll_event *events;
	int nevents;
	int i, ret;
	int do_accept;
	
	/* initialization */
	ctx = InitializeServerThread(core);
	if (!ctx) {
		TRACE_ERROR("Failed to initialize server thread.\n");
		return NULL;
	}
	mctx = ctx->mctx;
	ep = ctx->ep;

	events = (struct mtcp_epoll_event *)
			calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
	if (!events) {
		TRACE_ERROR("Failed to create event struct!\n");
		exit(-1);
	}

	listener = CreateListeningSocket(ctx);
	if (listener < 0) {
		TRACE_ERROR("Failed to create listening socket.\n");
		exit(-1);
	}

	while (!done[core]) {
		nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);
		if (nevents < 0) {
			if (errno != EINTR)
				perror("mtcp_epoll_wait");
			break;
		}
		do_accept = FALSE;
		for (i = 0; i < nevents; i++) {

			if (events[i].data.sockid == listener) {
				/* if the event is for the listener, accept connection */
				do_accept = TRUE;

			} else if (events[i].events & MTCP_EPOLLERR) {
				int err;
				socklen_t len = sizeof(err);

				/* error on the connection */
				TRACE_APP("[CPU %d] Error on socket %d\n", 
						core, events[i].data.sockid);
				if (mtcp_getsockopt(mctx, events[i].data.sockid, 
						SOL_SOCKET, SO_ERROR, (void *)&err, &len) == 0) {
					if (err != ETIMEDOUT) {
						fprintf(stderr, "Error on socket %d: %s\n", 
								events[i].data.sockid, strerror(err));
					}
				} else {
					perror("mtcp_getsockopt");
				}
				CloseConnection(ctx, events[i].data.sockid, 
						&ctx->svars[events[i].data.sockid]);

			} else if (events[i].events & MTCP_EPOLLIN) {
				ret = HandleReadEvent(ctx, events[i].data.sockid, 
						&ctx->svars[events[i].data.sockid]);

				if (ret == 0) {
					/* connection closed by remote host */
					CloseConnection(ctx, events[i].data.sockid, 
							&ctx->svars[events[i].data.sockid]);
				} else if (ret < 0) {
					/* if not EAGAIN, it's an error */
					if (errno != EAGAIN) {
						CloseConnection(ctx, events[i].data.sockid, 
								&ctx->svars[events[i].data.sockid]);
					}
				}

			} else if (events[i].events & MTCP_EPOLLOUT) {
				struct server_vars *sv = &ctx->svars[events[i].data.sockid];
				if (sv->rspheader_sent) {
					SendUntilAvailable(ctx, events[i].data.sockid, sv);
				} else {
					TRACE_APP("Socket %d: Response header not sent yet.\n", 
							events[i].data.sockid);
				}

			} else {
				assert(0);
			}
		}

		/* if do_accept flag is set, accept connections */
		if (do_accept) {
			while (1) {
				ret = AcceptConnection(ctx, listener);
				if (ret < 0)
					break;
			}
		}

	}

	/* destroy mtcp context: this will kill the mtcp thread */
	mtcp_destroy_context(mctx);
	pthread_exit(NULL);

	return NULL;
}
/*----------------------------------------------------------------------------*/
void
SignalHandler(int signum)
{
	int i;

	for (i = 0; i < core_limit; i++) {
		if (app_thread[i] == pthread_self()) {
			//TRACE_INFO("Server thread %d got SIGINT\n", i);
			done[i] = TRUE;
		} else {
			if (!done[i]) {
				pthread_kill(app_thread[i], signum);
			}
		}
	}
}
/*----------------------------------------------------------------------------*/
static void
printHelp(const char *prog_name)
{
	TRACE_CONFIG("%s -p <path_to_www/> -f <mtcp_conf_file> "
		     "[-N num_cores] [-c <per-process core_id>] "
				 "[-k max_keep_alive_requests (default: 100, infinite: -1)] [-h]\n",
		     prog_name);
	exit(EXIT_SUCCESS);
}
/*----------------------------------------------------------------------------*/
int 
main(int argc, char **argv)
{
	DIR *dir;
	int ret;
	struct mtcp_conf mcfg;
	int cores[MAX_CPUS];
	int process_cpu;
	int i, o;

	num_cores = GetNumCPUs();
	core_limit = num_cores;
	process_cpu = -1;
	dir = NULL;

	if (argc < 2) {
		TRACE_CONFIG("$%s directory_to_service\n", argv[0]);
		return FALSE;
	}

	while (-1 != (o = getopt(argc, argv, "N:f:p:c:b:k:h"))) {
		switch (o) {
		case 'p':
			/* open the directory to serve */
			www_main = optarg;
			dir = opendir(www_main);
			if (!dir) {
				TRACE_CONFIG("Failed to open %s.\n", www_main);
				perror("opendir");
				return FALSE;
			}
			break;
		case 'N':
			core_limit = mystrtol(optarg, 10);
			if (core_limit > num_cores) {
				TRACE_CONFIG("CPU limit should be smaller than the "
					     "number of CPUs: %d\n", num_cores);
				return FALSE;
			}
			/** 
			 * it is important that core limit is set 
			 * before mtcp_init() is called. You can
			 * not set core_limit after mtcp_init()
			 */
			mtcp_getconf(&mcfg);
			mcfg.num_cores = core_limit;
			mtcp_setconf(&mcfg);
			break;
		case 'f':
			conf_file = optarg;
			break;
		case 'c':
			process_cpu = mystrtol(optarg, 10);
			if (process_cpu > core_limit) {
				TRACE_CONFIG("Starting CPU is way off limits!\n");
				return FALSE;
			}
			break;
		case 'b':
			backlog = mystrtol(optarg, 10);
			break;
		case 'k':
			max_keep_alive_requests = mystrtol(optarg, 10);
			break;
		case 'h':
			printHelp(argv[0]);
			break;
		}
	}
	
	if (dir == NULL) {
		TRACE_CONFIG("You did not pass a valid www_path!\n");
		exit(EXIT_FAILURE);
	}

	finished = 0;

	/* initialize mtcp */
	if (conf_file == NULL) {
		TRACE_CONFIG("You forgot to pass the mTCP startup config file!\n");
		exit(EXIT_FAILURE);
	}

	ret = mtcp_init(conf_file);
	if (ret) {
		TRACE_CONFIG("Failed to initialize mtcp\n");
		exit(EXIT_FAILURE);
	}

	mtcp_getconf(&mcfg);
	if (backlog > mcfg.max_concurrency) {
		TRACE_CONFIG("backlog can not be set larger than CONFIG.max_concurrency\n");
		return FALSE;
	}

	/* if backlog is not specified, set it to 128 */
	if (backlog == -1) {
		backlog = 128;
	}
	
	/* register signal handler to mtcp */
	mtcp_register_signal(SIGINT, SignalHandler);

	TRACE_INFO("Application initialization finished.\n");

	for (i = ((process_cpu == -1) ? 0 : process_cpu); i < core_limit; i++) {
		cores[i] = i;
		done[i] = FALSE;
		
		if (pthread_create(&app_thread[i], 
				   NULL, RunServerThread, (void *)&cores[i])) {
			perror("pthread_create");
			TRACE_CONFIG("Failed to create server thread.\n");
				exit(EXIT_FAILURE);
		}
		if (process_cpu != -1)
			break;
	}
	
	for (i = ((process_cpu == -1) ? 0 : process_cpu); i < core_limit; i++) {
		pthread_join(app_thread[i], NULL);

		if (process_cpu != -1)
			break;
	}
	
	mtcp_destroy();
	closedir(dir);
	return 0;
}
