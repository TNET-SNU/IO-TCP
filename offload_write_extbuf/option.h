#ifndef __OPTION_H__
#define __OPTION_H__

#include "string.h"

#define VERBOSE_INIT FALSE
#define VERBOSE_TCP FALSE
#define VERBOSE_STATE FALSE
#define VERBOSE_CHUNK FALSE
#define VERBOSE_MAC FALSE
#define VERBOSE_DATA FALSE
#define VERBOSE_STAT FALSE

#define UNUSED(x) (void)(x)

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define MAX_THREAD_NUM 8

#define NO_HARDWARE_TSO FALSE

#define DEBUG_LOG FALSE
#define ERROR_LOG FALSE
#define PACKET_LOG FALSE

#define SHOW_STATS 0

#define NO_FS_PERFTEST FALSE
#define NICTOHOST_FSTAT TRUE
#define WHOLE_FSTAT TRUE
#define HOSTTONIC_FSTAT FALSE // Not Implemented
#define INDEPENDENT_FSTAT FALSE

#endif /* __OPTION_H__ */
