#ifndef _MEMALLOC_H_
#define _MEMALLOC_H_

int balloc(int core, uint8_t** pblks, int num);
void bfree(int core, uint8_t *pblk);

void AllocateCacheMemory(int64_t size, int ncores);
rte_iova_t getIOVA(int core, uint8_t* ptr);

#endif
