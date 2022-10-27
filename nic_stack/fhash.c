#include <stdio.h>

#include "fhash.h"

#define NUM_BINS  8192            /* # of hash bins of a connection table */

typedef struct fc_hash_bucket_head {
    struct file_cache *tqh_first;
    struct file_cache **tqh_last;
} fc_hash_bucket_head;

struct fc_hashtable {
  fc_hash_bucket_head *ht_table;
};

/*-----------------------------------------------------------------------*/
static inline int
fc_calculate_hash(uint32_t x)
{
	x = ((x >> 16) ^ x) * 0x45d9f3b;
	x = ((x >> 16) ^ x) * 0x45d9f3b;
	x = (x >> 16) ^ x;
	return ((x) & (NUM_BINS - 1));
}
/*-----------------------------------------------------------------------*/
struct fc_hashtable *
create_fc_ht(void)
{
  int i;
  struct fc_hashtable *ht;

  ht = calloc(1, sizeof(struct fc_hashtable));
  if (!ht) {
    TRACE_ERROR("calloc: create_fc_ht");
    return NULL;
  }

  /* creating bins */
  ht->ht_table = calloc(NUM_BINS, sizeof(fc_hash_bucket_head));
  if (!ht->ht_table) {
    TRACE_ERROR("calloc: create_fc_ht bins!\n");
    free(ht);
    return NULL;
  }
  
  /* init the tables */
  for (i = 0; i < NUM_BINS; i++)
    TAILQ_INIT(&ht->ht_table[i]);

  return ht;
}
/*-----------------------------------------------------------------------*/
void
destroy_fc_ht(struct fc_hashtable *ht)
{
  free(ht->ht_table);
  free(ht);
}
/*-----------------------------------------------------------------------*/
void
fc_ht_insert(struct fc_hashtable *ht, struct file_cache *fc)
{
  /* create an entry*/
  int idx;

  assert(ht);
  idx = fc_calculate_hash(fc->fc_fid);
  assert(idx >= 0 && idx < NUM_BINS);

  TRACE_DBG("Insert on index: %d\n", idx);
  TAILQ_INSERT_TAIL(&ht->ht_table[idx], fc, file_cache_link);
}
/*-----------------------------------------------------------------------*/
void
fc_ht_remove(struct fc_hashtable *ht, struct file_cache *fc)
{
  fc_hash_bucket_head *head;
  int idx = fc_calculate_hash(fc->fc_fid);
  head = &ht->ht_table[idx];
  TAILQ_REMOVE(head, fc, file_cache_link);
}
/*-----------------------------------------------------------------------*/
void *
fc_ht_search(struct fc_hashtable *ht, uint32_t fid)
{
  struct file_cache *walk;
  fc_hash_bucket_head *head;
  
  head = &ht->ht_table[fc_calculate_hash(fid)];
  TAILQ_FOREACH(walk, head, file_cache_link) {
	  if (walk->fc_fid == fid)
		  return walk;
  }
  return NULL;
}
