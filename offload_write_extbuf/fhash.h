#ifndef _FHASH_H_
#define _FHASH_H_

#include <sys/queue.h>
#include "offload_write.h"

struct fc_hashtable;

struct fc_hashtable *create_fc_ht(void);
void  destroy_fc_ht(struct fc_hashtable *ht);
void  fc_ht_insert(struct fc_hashtable *ht, struct file_cache *);
void  fc_ht_remove(struct fc_hashtable *ht, struct file_cache *);
void *fc_ht_search(struct fc_hashtable *ht, uint32_t fid);

#endif // _FHASH_H_
