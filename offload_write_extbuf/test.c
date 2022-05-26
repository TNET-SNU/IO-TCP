#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <elf.h>

#define HZ 1000
#define TIME_TICK (1000000/HZ) // in us
#define TIMEVAL_TO_TS(t) (uint32_t)((t)->tv_sec * HZ + \
									((t)->tv_usec / TIME_TICK))

#define TIMEVAL_TO_DOUBLE(t) ((t)->tv_sec * 1e3 + (t)->tv_usec * 1e-3)

int main(int argc, char** argv)
{
	struct timeval tv, old_tv;
	double old, now;
	
	while (1) {

		gettimeofday(&tv, NULL);

		now = TIMEVAL_TO_DOUBLE(&tv);
		printf("diff_d=%.1f diff_u=%u tv = (%ld, %ld), tv_ms (double) = %.1f tv_ms (float) = %.1f TIME_TS: %u\n",
			   now - old,
			   (uint32_t)(now - old),
			   tv.tv_sec, tv.tv_usec,
			   tv.tv_sec * 1e3 + tv.tv_usec * 1e-3,
			   (float)(tv.tv_sec * 1e3 + tv.tv_usec * 1e-3),
			   TIMEVAL_TO_TS(&tv));
		old = now;
		sleep(1);
	}

}
