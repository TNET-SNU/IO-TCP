#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "memorypool.h"

#ifndef max
#define max(a,b) ((a)<(b)?(b):(a))
#endif

void poolInitialize(pool *p, const uint32_t elementSize, const uint32_t blockSize)
{
	uint32_t i;

	p->elementSize = max(elementSize, sizeof(poolFreed));
	p->blockSize = blockSize;
	
	poolFreeAll(p);

	p->blocksUsed = POOL_BLOCKS_INITIAL;
	p->blocks = malloc(sizeof(uint8_t*)* p->blocksUsed);
	if (p->blocks == NULL) {
		fprintf(stderr, "poolInitialize failed\n");
		exit(1);
	}
	memset(p->blocks, 0, sizeof(uint8_t*)* p->blocksUsed);

	for(i = 0; i < p->blocksUsed; ++i)
		p->blocks[i] = NULL;
}

void poolFreePool(pool *p)
{
	uint32_t i;
	for(i = 0; i < p->blocksUsed; ++i) {
		if(p->blocks[i] == NULL)
			break;
		else
			free(p->blocks[i]);
	}

	free(p->blocks);
}

#ifndef DISABLE_MEMORY_POOLING
void *poolMalloc(pool *p)
{
	//fprintf(stderr, "poolMalloc start\n");
	if(p->freed != NULL) {
		void *recycle = p->freed;
		p->freed = p->freed->nextFree;
	        //fprintf(stderr, "poolMalloc end\n");
		return recycle;
	}

	if(++p->used == p->blockSize) {
		p->used = 0;
		if(++p->block == (int32_t)p->blocksUsed) {
			uint32_t i;

			p->blocksUsed <<= 1;
			p->blocks = realloc(p->blocks, sizeof(uint8_t*)* p->blocksUsed);
			fprintf(stderr, "poolMalloc realloc\n");
			if (p->blocks == NULL) {
				fprintf(stderr, "poolMalloc failed\n");
				exit(1);
			}

			for(i = p->blocksUsed >> 1; i < p->blocksUsed; ++i)
				p->blocks[i] = NULL;
		}

		if(p->blocks[p->block] == NULL) {
			p->blocks[p->block] = malloc(p->elementSize * p->blockSize);
			fprintf(stderr, "poolMalloc malloc\n");
			if (p->blocks[p->block] == NULL) {
				fprintf(stderr, "poolMalloc failed\n");
				exit(1);
			}
		}
	}
	
	//fprintf(stderr, "poolMalloc end\n");
	return p->blocks[p->block] + p->used * p->elementSize;
}

void poolFree(pool *p, void *ptr)
{
	//fprintf(stderr, "poolFree start\n");
	poolFreed *pFreed = p->freed;

	p->freed = ptr;
	p->freed->nextFree = pFreed;
	memset(ptr, 0, p->elementSize);
	//fprintf(stderr, "poolFree end\n");
}
#endif

void poolFreeAll(pool *p)
{
	p->used = p->blockSize - 1;
	p->block = -1;
	p->freed = NULL;
}
