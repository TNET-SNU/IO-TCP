#include <rte_hexdump.h>
#include "offload_write.h"

/*-----------------------------------------------------------------------*/
inline void
free_pkts(struct rte_mbuf **mtable, unsigned len)
{
  unsigned i;

  for (i = 0; i < len; i++) {
    rte_pktmbuf_free(mtable[i]);
    RTE_MBUF_PREFETCH_TO_FREE(mtable[i + 1]);
  }
}
/*-----------------------------------------------------------------------*/
inline int32_t
recv_pkts(uint16_t core_id, uint16_t port)
{
  struct dpdk_private_context *dpc;
  struct mbuf_table *rmbuf;
  int ret;

  dpc   = ctx_array[core_id]->dpc;
  rmbuf = &dpc->rmbufs[port];

  if (rmbuf->len != 0) {
    free_pkts(rmbuf->m_table, rmbuf->len);
    rmbuf->len = 0;
  }

  ret = rte_eth_rx_burst((uint8_t)port, core_id,
                          dpc->pkts_burst, MAX_PKT_BURST);

#if VERBOSE_TCP
  if(ret > 0) {
    struct rte_mbuf *m;
    uint8_t *ptr;
    int i;

    fprintf(stderr, "\nRECEIVING %d PACKETS\n", ret);

    for (i = 0; i < ret; i++) {
      m = dpc->pkts_burst[i];
      ptr = (void *)rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
      dump_pkt(ptr, m->pkt_len);
	}
  }
#endif /* VERBOSE_TCP */

  dpc->rx_idle = (ret != 0) ? 0 : dpc->rx_idle + 1;
  rmbuf->len = ret;

  return ret;
}
/*-----------------------------------------------------------------------*/
inline uint8_t *
get_rptr(uint16_t core_id, uint16_t port, int index, uint16_t *len)
{
  struct dpdk_private_context *dpc;
  struct rte_mbuf *m;
  uint8_t *pktbuf;

  dpc = ctx_array[core_id]->dpc;

  m = dpc->pkts_burst[index];

  *len = m->pkt_len;
  pktbuf = rte_pktmbuf_mtod(m, uint8_t *);

  dpc->rmbufs[port].m_table[index] = m;

  if ((m->ol_flags & (PKT_RX_L4_CKSUM_BAD | PKT_RX_IP_CKSUM_BAD)) != 0) {
    TRACE_ERROR("[CPU %d][Port %d] mbuf(index: %d) with invalid checksum: "
	    "%p(%lu);\n", core_id, port, index, m, m->ol_flags);
    pktbuf = NULL;
  }

  return pktbuf;
}
/*-----------------------------------------------------------------------*/
inline struct rte_mbuf *
get_wptr(uint16_t core_id, uint16_t port, uint16_t pktsize)
{
  struct dpdk_private_context *dpc;
  struct rte_mbuf *m;
  struct mbuf_table *wmbuf;
  int len_mbuf;
  int send_cnt;

  dpc   = ctx_array[core_id]->dpc;
  wmbuf = &dpc->wmbufs[port];

  if (wmbuf->len == MAX_PKT_BURST) {
    while (1) {
      send_cnt = send_pkts(core_id, port);
      if (send_cnt)
        break;
    }
  }

  len_mbuf = wmbuf->len;
  m = wmbuf->m_table[len_mbuf];

  m->pkt_len = m->data_len = pktsize;
  m->nb_segs = 1;
  m->next    = NULL;
  wmbuf->len = len_mbuf + 1;

  return m;
}
/*-----------------------------------------------------------------------*/
inline int
send_pkts(uint16_t core_id, uint16_t port)
{
  struct dpdk_private_context *dpc;
  struct mbuf_table *wmbuf;
  int ret, i;

  dpc   = ctx_array[core_id]->dpc;
  wmbuf = &dpc->wmbufs[port];
  ret   = 0;

  if (wmbuf->len > 0) {
    struct rte_mbuf **pkts;
    int cnt = wmbuf->len;
    pkts = wmbuf->m_table;

#if VERBOSE_TCP
    struct rte_mbuf *m;
    uint8_t *ptr;

    fprintf(stderr, "\nSENDING %d PACKETS\n", cnt);

    for (i = 0; i < wmbuf->len; i++) {
       m = pkts[i];
       ptr = (void *)rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
       fprintf(stderr, "Sending pkt_len: %u m->nb_segs %u\n", m->pkt_len, m->nb_segs);
       dump_pkt(ptr, m->data_len);
    }
 #endif /* VERBOSE_TCP */

    do {
      ret   = rte_eth_tx_burst(port, core_id, pkts, cnt);
      pkts += ret;
      cnt  -= ret;
    } while (cnt > 0);

    // fprintf(stderr, "rte_eth return:%d \n", ret);

    for (i = 0; i < wmbuf->len; i++) {
      wmbuf->m_table[i] = rte_pktmbuf_alloc(pktmbuf_pool[core_id]);
      if (wmbuf->m_table[i] == NULL) {
        rte_exit(EXIT_FAILURE,
				 "[CPU %d] Failed to allocate wmbuf[%d] on port %d\n", core_id,
				 i, port);
        fflush(stdout);
      }
    }
    wmbuf->len = 0;
  }

  return ret;
}

void dump_pkt(uint8_t *pktbuf, uint16_t pkt_len)
{
#if PACKET_LOG
  char send_dst_hw[20];
  char send_src_hw[20];
  struct rte_ether_hdr *ethh;
  struct rte_ipv4_hdr *iph;
  struct rte_tcp_hdr *tcph;
  
  ethh = (struct rte_ether_hdr *)pktbuf;
  iph = (struct rte_ipv4_hdr *)(ethh + 1);
  tcph = (struct rte_tcp_hdr *)(iph + 1);

  memset(send_dst_hw, 0, 10);
  memset(send_src_hw, 0, 10);

  sprintf(send_dst_hw, "%x:%x:%x:%x:%x:%x", ethh->d_addr.addr_bytes[0],
    ethh->d_addr.addr_bytes[1], ethh->d_addr.addr_bytes[2],
    ethh->d_addr.addr_bytes[3], ethh->d_addr.addr_bytes[4],
    ethh->d_addr.addr_bytes[5]);

  sprintf(send_src_hw, "%x:%x:%x:%x:%x:%x", ethh->s_addr.addr_bytes[0],
    ethh->s_addr.addr_bytes[1], ethh->s_addr.addr_bytes[2],
    ethh->s_addr.addr_bytes[3], ethh->s_addr.addr_bytes[4],
    ethh->s_addr.addr_bytes[5]);

  fprintf(stderr,
    "Packet Info---------------------------------\n"
    "dest hwaddr: %s\n"
    "source hwaddr: %s\n"
    "%u.%u.%u.%u : %u -> %u.%u.%u.%u : %u, id: %u\n"
    "seq: %u, ack: %u, flag: %x\n"
    "total len: %u\n",
    send_dst_hw, send_src_hw, ((ntohl(iph->src_addr) >> 24) & 0xff),
    ((ntohl(iph->src_addr) >> 16) & 0xff),
    ((ntohl(iph->src_addr) >> 8) & 0xff), ((ntohl(iph->src_addr)) & 0xff),
    ntohs(tcph->src_port), ((ntohl(iph->dst_addr) >> 24) & 0xff),
    ((ntohl(iph->dst_addr) >> 16) & 0xff),
    ((ntohl(iph->dst_addr) >> 8) & 0xff), ((ntohl(iph->dst_addr)) & 0xff),
    ntohs(tcph->dst_port), ntohs(iph->packet_id), ntohl(tcph->sent_seq),
    ntohl(tcph->recv_ack), tcph->tcp_flags, pkt_len);

  rte_hexdump(stderr, "Packet Hex Dump", pktbuf, MIN(100,pkt_len));
#endif

  return;
}
