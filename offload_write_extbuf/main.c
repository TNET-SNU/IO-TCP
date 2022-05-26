/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include "fhash.h"
#include "offload_write.h"
#include "option.h"

extern struct fc_hashtable *file_cache_ht[MAX_CPUS];

static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh =
      {
        .pthresh = RX_PTHRESH,
        .hthresh = RX_HTHRESH,
        .wthresh = RX_WTHRESH,
      },
    .rx_free_thresh = 32,
};

static const struct rte_eth_txconf tx_conf = {
    .tx_thresh =
      {
        .pthresh = TX_PTHRESH,
        .hthresh = TX_HTHRESH,
        .wthresh = TX_WTHRESH,
      },
    .tx_free_thresh = 0,
    .tx_rs_thresh = 0,
#if RTE_VERSION < RTE_VERSION_NUM(18, 5, 0, 0)
    .txq_flags = 0x0,
#endif
};

static struct rte_eth_conf port_conf = {
  .rxmode =
    {
      .mq_mode = ETH_MQ_RX_RSS,
      .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
      .offloads = DEV_RX_OFFLOAD_CHECKSUM,
      .split_hdr_size = 0,
    },
  .rx_adv_conf =
    {
      .rss_conf = {.rss_key = NULL,
      .rss_hf = ETH_RSS_TCP | ETH_RSS_UDP | ETH_RSS_IP |
          ETH_RSS_L2_PAYLOAD},
    },
  .txmode = 
    {
      .mq_mode = ETH_MQ_TX_NONE,
      .offloads = DEV_TX_OFFLOAD_IPV4_CKSUM |
        DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM |
        DEV_TX_OFFLOAD_TCP_TSO
    },
};

struct rte_mempool *pktmbuf_pool[MAX_CPUS] = {NULL};
struct thread_context *ctx_array[MAX_CPUS] = {NULL};

#if NO_HARDWARE_TSO
struct rte_mempool *gso_pool[MAX_CPUS] = {NULL};
struct rte_gso_ctx *gso_ctx_array[MAX_CPUS] = {NULL};
#endif

static struct rte_eth_dev_info dev_info[RTE_MAX_ETHPORTS];
struct rte_mempool *shinfo_pool[MAX_CPUS] = {NULL};
struct rte_mempool *fc_pool[MAX_CPUS] = {NULL};
struct rte_mempool *frr_pool[MAX_CPUS] = {NULL};
static const uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static const uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

static void
zero_obj_init(struct rte_mempool *mp, __attribute__((unused)) void *arg,
	    void *obj, unsigned i)
{
	memset(obj, 0, mp->elt_size);
}

static void global_init(void)
{
  int nb_ports, num_core, portid, rxlcore_id, ret;
  struct rte_eth_fc_conf fc_conf;
  char if_name[RTE_ETH_NAME_MAX_LEN];

  static uint8_t key[] = {
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05
  };

  num_core = rte_lcore_count();
  if (num_core <= 0) {
    fprintf(stderr, "Zero or negative number of cores activated.\n");
    exit(EXIT_FAILURE);
  }

  nb_ports = rte_eth_dev_count_avail();
  if (nb_ports <= 0) {
    fprintf(stderr, "Zero or negative number of ports activated.\n");
    exit(EXIT_FAILURE);
  }

  /* Setting RSS Key */
  port_conf.rx_adv_conf.rss_conf.rss_key = (uint8_t *)key;
  port_conf.rx_adv_conf.rss_conf.rss_key_len = sizeof(key);

  /* Packet mbuf pool Creation */
  for (rxlcore_id = 0; rxlcore_id < num_core; rxlcore_id++) {
    char name[RTE_MEMPOOL_NAMESIZE];
    sprintf(name, "mbuf_pool-%d", rxlcore_id);

    pktmbuf_pool[rxlcore_id] =
        rte_pktmbuf_pool_create(name,
								NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
								RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
								// MAX_TSO_PKTSIZE, rte_socket_id());
    
    if (pktmbuf_pool[rxlcore_id] == NULL) {
		rte_exit(EXIT_FAILURE,
				 "Cannot init mbuf pool, errno: %d\n", rte_errno);
		fflush(stdout);
    }

#if NO_HARDWARE_TSO
    sprintf(name, "gso_pool-%d", rxlcore_id);

    /* TODO: Memory optimization? */
    gso_pool[rxlcore_id] =
        rte_pktmbuf_pool_create(name,
								NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
								RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (gso_pool[rxlcore_id] == NULL) {
		rte_exit(EXIT_FAILURE,
			   "Cannot init GSO mbuf pool, errno: %d\n", rte_errno);
		fflush(stdout);
    }
#endif

    sprintf(name, "shinfo_pool-%d", rxlcore_id);
    shinfo_pool[rxlcore_id] =
        rte_mempool_create(name, NUM_MBUFS * nb_ports,
              sizeof(struct shinfo_ctx), 0, 0,
              NULL, NULL, NULL, NULL,
              rte_socket_id(), 0);
    if (shinfo_pool[rxlcore_id] == NULL) {
      rte_exit(EXIT_FAILURE,
               "Cannot init shinfo pool, errno: %d\n", rte_errno);
      fflush(stdout);
    }
    /*
    sprintf(name, "fc_pool-%d", rxlcore_id);
    fc_pool[rxlcore_id] =
        rte_mempool_create(name, 1024*128-1,
              sizeof(struct file_cache), 0, 0,
              NULL, NULL, zero_obj_init, NULL,
              rte_socket_id(), 0);
    if (fc_pool[rxlcore_id] == NULL) {
      rte_exit(EXIT_FAILURE,
               "Cannot init fc pool, errno: %d\n", rte_errno);
      fflush(stdout);
    }
    size_t sizeof_FRR = sizeof(off_t) * 2 + sizeof(struct iovec) * MAX_IOV + sizeof(int) * 6 + sizeof(struct freadreq*) * 2 + sizeof (double) + sizeof(struct file_cache *) + sizeof(uint8_t) * MAX_HDRLEN;
    sprintf(name, "frr_pool-%d", rxlcore_id);
    frr_pool[rxlcore_id] =
        rte_mempool_create(name, 1024*128-1,
              sizeof_FRR, 0, 0,
              NULL, NULL, zero_obj_init, NULL,
              rte_socket_id(), 0);
    if (frr_pool[rxlcore_id] == NULL) {
      rte_exit(EXIT_FAILURE,
               "Cannot init frr pool, errno: %d\n", rte_errno);
      fflush(stdout);
    }
    fprintf(stderr, "size shinfo_ctx:%d, file_cache:%d, FReadReq:%d\n",sizeof(struct shinfo_ctx), sizeof(struct file_cache), sizeof_FRR);
    */
  }
  fprintf(stderr, "mbuf_pool Created\n");

  /* Port Configuration and Activation */
  RTE_ETH_FOREACH_DEV(portid) {
    rte_eth_dev_get_name_by_port(portid, if_name);
    rte_eth_dev_info_get(portid, &dev_info[portid]);
#if RTE_VERSION >= RTE_VERSION_NUM(18, 5, 0, 0)
    port_conf.rx_adv_conf.rss_conf.rss_hf &=
		dev_info[portid].flow_type_rss_offloads;
#endif
    fprintf(stderr, "Initializaing port %u (%s) ... for %d cores\n",
	    (unsigned)portid, if_name, num_core);
    
    ret = rte_eth_dev_configure(portid, num_core, num_core, &port_conf);
    
    if (ret < 0)
		rte_exit(EXIT_FAILURE,
				 "Cannot configure device: err=%d, port=%u, cores: %d\n",
				 ret, (unsigned)portid, num_core);
	
    for (rxlcore_id = 0; rxlcore_id < num_core; rxlcore_id++) {
		ret = rte_eth_rx_queue_setup(portid, rxlcore_id, nb_rxd,
									 rte_eth_dev_socket_id(portid),
									 &rx_conf,
									 pktmbuf_pool[rxlcore_id]);
		
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
					 "rte_eth_rx_queue_setup: "
					 "err=%d, port=%u, queueid: %d\n",
					 ret, (unsigned)portid, rxlcore_id);
    }
	
    for (rxlcore_id = 0; rxlcore_id < num_core; rxlcore_id++) {
		ret = rte_eth_tx_queue_setup(portid, rxlcore_id, nb_txd,
									 rte_eth_dev_socket_id(portid),
									 &tx_conf);
		
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
					 "rte_eth_tx_queue_setup: "
					 "err=%d, port=%u, queueid: %d\n",
					 ret, (unsigned)portid, rxlcore_id);
    }
	
    ret = rte_eth_dev_start(portid);
	
    if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret,
	       (unsigned)portid);

    rte_eth_promiscuous_enable(portid);

    memset(&fc_conf, 0, sizeof(fc_conf));
    ret = rte_eth_dev_flow_ctrl_get(portid, &fc_conf);
    if (ret != 0)
      fprintf(stderr, "Failed to get flow control info!\n");

    fc_conf.mode = RTE_FC_NONE;
    ret = rte_eth_dev_flow_ctrl_set(portid, &fc_conf);
    if (ret != 0)
      fprintf(stderr, "Failed to set flow control info!: errno: %d\n", ret);
  }

  fprintf(stderr, "Port Initialization Complete\n");
}

void global_destroy(void)
{
  int portid;

  RTE_ETH_FOREACH_DEV(portid) {
    rte_eth_dev_stop(portid);
    rte_eth_dev_close(portid);
  }
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[])
{
  unsigned lcore_id;
  unsigned i;
  int ret;

  /* Initialize the hash table for the file cache */

  for (i = 0; i < MAX_CPUS; i ++) {
	  file_cache_ht[i] = create_fc_ht();
	  if (!file_cache_ht[i]) {
		  fprintf(stderr, "Initializing CC Hash Table Failed\n");
	  }
  }

  /* Initialize the Environment Abstraction Layer (EAL). */
  ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  argc -= ret;
  argv += ret;

  fprintf(stderr, "\nRTE EAL Initialization Complete\n");
  fprintf(stderr, "---------------------------------------------------\n\n");

  fprintf(stderr, "\nArgument Parsing Complete\n");
  fprintf(stderr, "---------------------------------------------------\n\n");

  global_init();

  fprintf(stderr, "\nGlobal Initialization Complete\n");
  fprintf(stderr, "---------------------------------------------------\n\n");

  fprintf(stderr, "Use Following Cores for Forwarding\n");
  for (i = 0; i < rte_lcore_count(); i++) {
    fprintf(stderr, "%d", i);
    if (i != rte_lcore_count() - 1)
      fprintf(stderr, ", ");
  }
  fprintf(stderr, "\n\n");

  /* Call lcore_main on the master core only. */
  rte_eal_mp_remote_launch(forward_main_loop, NULL, CALL_MASTER);
  RTE_LCORE_FOREACH_SLAVE(lcore_id) {
    if (rte_eal_wait_lcore(lcore_id) < 0) {
      ret = -1;
      break;
    }
  }

  global_destroy();

  return 0;
}
