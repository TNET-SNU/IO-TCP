#include <unistd.h>
#include "tcp_out.h"
#include "tcp_util.h"
#include "mtcp.h"
#include "ip_out.h"
#include "tcp_in.h"
#include "tcp_stream.h"
#include "eventpoll.h"
#include "timer.h"
#include "debug.h"
#if RATE_LIMIT_ENABLED || PACING_ENABLED
#include "pacing.h"
#endif
#include "arp.h"

#define TCP_CALCULATE_CHECKSUM      TRUE
#define ACK_PIGGYBACK				TRUE
#define TRY_SEND_BEFORE_QUEUE		FALSE

#define TCP_MAX_WINDOW 65535

/*----------------------------------------------------------------------------*/
static inline uint16_t
CalculateOptionLength(uint8_t flags)
{
	uint16_t optlen = 0;

	if (flags & TCP_FLAG_SYN) {
		optlen += TCP_OPT_MSS_LEN;
#if TCP_OPT_SACK_ENABLED
		optlen += TCP_OPT_SACK_PERMIT_LEN;
#if !TCP_OPT_TIMESTAMP_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
#endif /* TCP_OPT_SACK_ENABLED */

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN;
#if !TCP_OPT_SACK_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_SACK_ENABLED */
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		optlen += TCP_OPT_WSCALE_LEN + 1;

	} else {

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN + 2;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_FLAG_SACK) {
			optlen += TCP_OPT_SACK_LEN + 2;
		}
#endif
	}

	return optlen;
}
/*----------------------------------------------------------------------------*/
static inline void
GenerateTCPTimestamp(tcp_stream *cur_stream, uint8_t *tcpopt, uint32_t cur_ts)
{
	uint32_t *ts = (uint32_t *)(tcpopt + 2);

	tcpopt[0] = TCP_OPT_TIMESTAMP;
	tcpopt[1] = TCP_OPT_TIMESTAMP_LEN;
	ts[0] = htonl(cur_ts);
	ts[1] = htonl(cur_stream->rcvvar->ts_recent);
}
/*----------------------------------------------------------------------------*/
static inline void
GenerateTCPOptions(tcp_stream *cur_stream, uint32_t cur_ts, 
		uint8_t flags, uint8_t *tcpopt, uint16_t optlen)
{
	int i = 0;

	if (flags & TCP_FLAG_SYN) {
		uint16_t mss;

		/* MSS option */
		mss = cur_stream->sndvar->mss;
		tcpopt[i++] = TCP_OPT_MSS;
		tcpopt[i++] = TCP_OPT_MSS_LEN;
		tcpopt[i++] = mss >> 8;
		tcpopt[i++] = mss % 256;

		/* SACK permit */
#if TCP_OPT_SACK_ENABLED
#if !TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
		tcpopt[i++] = TCP_OPT_SACK_PERMIT;
		tcpopt[i++] = TCP_OPT_SACK_PERMIT_LEN;
		TRACE_SACK("Local SACK permited.\n");
#endif /* TCP_OPT_SACK_ENABLED */

		/* Timestamp */
#if TCP_OPT_TIMESTAMP_ENABLED
#if !TCP_OPT_SACK_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_SACK_ENABLED */
		GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		/* Window scale */
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_WSCALE;
		tcpopt[i++] = TCP_OPT_WSCALE_LEN;
		tcpopt[i++] = cur_stream->sndvar->wscale_mine;

	} else {

#if TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
		GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_OPT_SACK) {
			// i += GenerateSACKOption(cur_stream, tcpopt + i);
		}
#endif
	}

	assert (i == optlen);
}
/*----------------------------------------------------------------------------*/
int
SendTCPPacketStandalone(struct mtcp_manager *mtcp, 
		uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, 
		uint32_t seq, uint32_t ack_seq, uint16_t window, uint8_t flags, 
		uint8_t *payload, uint16_t payloadlen, 
		uint32_t cur_ts, uint32_t echo_ts)
{
	struct tcphdr *tcph;
	uint8_t *tcpopt;
	uint32_t *ts;
	uint16_t optlen;
	int rc = -1;

	optlen = CalculateOptionLength(flags);
	if (payloadlen + optlen > TCP_DEFAULT_MSS) {
		TRACE_ERROR("Payload size exceeds MSS.\n");
		assert(0);
		return ERROR;
	}

	tcph = (struct tcphdr *)IPOutputStandalone(mtcp, IPPROTO_TCP, 0, 
			saddr, daddr, TCP_HEADER_LEN + optlen + payloadlen);
	if (tcph == NULL) {
		return ERROR;
	}
	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = sport;
	tcph->dest = dport;

	if (flags & TCP_FLAG_SYN)
		tcph->syn = TRUE;
	if (flags & TCP_FLAG_FIN)
		tcph->fin = TRUE;
	if (flags & TCP_FLAG_RST)
		tcph->rst = TRUE;
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	tcph->seq = htonl(seq);
	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(ack_seq);
	}

	tcph->window = htons(MIN(window, TCP_MAX_WINDOW));

	tcpopt = (uint8_t *)tcph + TCP_HEADER_LEN;
	ts = (uint32_t *)(tcpopt + 4);

	tcpopt[0] = TCP_OPT_NOP;
	tcpopt[1] = TCP_OPT_NOP;
	tcpopt[2] = TCP_OPT_TIMESTAMP;
	tcpopt[3] = TCP_OPT_TIMESTAMP_LEN;
	ts[0] = htonl(cur_ts);
	ts[1] = htonl(echo_ts);

	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
	// copy payload if exist
	if (payloadlen > 0) {
		memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
#if defined(NETSTAT) && defined(ENABLELRO)
		mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
	}
		
#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
	uint8_t is_external;
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, GetOutputInterface(daddr, &is_external),
					  PKT_TX_TCPIP_CSUM, NULL);
	UNUSED(is_external);
#endif
	if (rc == -1)
		tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
					      TCP_HEADER_LEN + optlen + payloadlen,
					      saddr, daddr);
#endif

	if (tcph->syn || tcph->fin) {
		payloadlen++;
	}

	return payloadlen;
}
/*----------------------------------------------------------------------------*/
int
SendTCPPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t flags, uint8_t *payload, uint16_t payloadlen)
{
	struct tcphdr *tcph;
	uint16_t optlen;
	uint8_t wscale = 0;
	uint32_t window32 = 0;
	int rc = -1;

	optlen = CalculateOptionLength(flags);
	if (payloadlen + optlen > cur_stream->sndvar->mss) {
		TRACE_ERROR("Payload size exceeds MSS (%u)\n", payloadlen + optlen);
		return ERROR;
	}

	tcph = (struct tcphdr *)IPOutput(mtcp, cur_stream, 
		TCP_HEADER_LEN + optlen + payloadlen);

	if (tcph == NULL) {
		return -2;
	}
	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = cur_stream->sport;
	tcph->dest = cur_stream->dport;

	if (flags & TCP_FLAG_SYN) {
		tcph->syn = TRUE;
		if (cur_stream->snd_nxt != cur_stream->sndvar->iss) {
			TRACE_DBG("Stream %d: weird SYN sequence. "
					"snd_nxt: %u, iss: %u\n", cur_stream->id, 
					cur_stream->snd_nxt, cur_stream->sndvar->iss);
		}
#if 0
		TRACE_FIN("Stream %d: Sending SYN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
#endif
	}
	if (flags & TCP_FLAG_RST) {
		TRACE_FIN("Stream %d: Sending RST.\n", cur_stream->id);
		tcph->rst = TRUE;
	}
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	if (flags & TCP_FLAG_WACK) {
		tcph->seq = htonl(cur_stream->snd_nxt - 1);
		TRACE_CLWND("%u Sending ACK to get new window advertisement. "
				"seq: %u, peer_wnd: %u, snd_nxt - snd_una: %u\n", 
				cur_stream->id,
				cur_stream->snd_nxt - 1, cur_stream->sndvar->peer_wnd, 
				cur_stream->snd_nxt - cur_stream->sndvar->snd_una);
	} else if (flags & TCP_FLAG_FIN) {
		tcph->fin = TRUE;
		
		if (cur_stream->sndvar->fss == 0) {
			TRACE_ERROR("Stream %u: not fss set. closed: %u\n", 
					cur_stream->id, cur_stream->closed);
		}
		tcph->seq = htonl(cur_stream->sndvar->fss);
		cur_stream->sndvar->is_fin_sent = TRUE;
		TRACE_FIN("Stream %d: Sending FIN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
	} else {
		tcph->seq = htonl(cur_stream->snd_nxt);
	}

	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(cur_stream->rcv_nxt);
		cur_stream->sndvar->ts_lastack_sent = cur_ts;
		cur_stream->last_active_ts = cur_ts;
		UpdateTimeoutList(mtcp, cur_stream);
	}

	if (flags & TCP_FLAG_SYN) {
		wscale = 0;
	} else {
		wscale = cur_stream->sndvar->wscale_mine;
	}

	window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
	tcph->window = htons((uint16_t)MIN(window32, TCP_MAX_WINDOW));
	/* if the advertised window is 0, we need to advertise again later */
	if (window32 == 0) {
		cur_stream->need_wnd_adv = TRUE;
	}

	GenerateTCPOptions(cur_stream, cur_ts, flags, 
			(uint8_t *)tcph + TCP_HEADER_LEN, optlen);
	
	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
	// copy payload if exist

	if (payloadlen > 0) {
		memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
#if defined(NETSTAT) && defined(ENABLELRO)
		mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
	}

#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
					  PKT_TX_TCPIP_CSUM, NULL);
#endif
	if (rc == -1)
		tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
					      TCP_HEADER_LEN + optlen + payloadlen, 
					      cur_stream->saddr, cur_stream->daddr);
#endif
	
	if (payloadlen > 0) {
		cur_stream->snd_nxt += payloadlen;
	}

	if (tcph->syn || tcph->fin) {
		cur_stream->snd_nxt++;
		payloadlen++;
	}

	if (payloadlen > 0) {
		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("Payload after ESTABLISHED: length: %d, snd_nxt: %u\n", 
					payloadlen, cur_stream->snd_nxt);
		}

		/* update retransmission timer if have payload */
		cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		TRACE_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n", 
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);
		AddtoRTOList(mtcp, cur_stream);
	}

	return payloadlen;
}
/*----------------------------------------------------------------------------*/
static int
FlushTCPSendingBuffer(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	struct offload_vars *offload_vars = NULL;
	struct offload_vars *_o;
	struct offload_buffer *ob, *_ob;
	uint8_t *data;
	uint32_t seq = 0;
	uint64_t offset = 0;
	int remaining_window;
	int sndlen;
	int len;
	int pkt_len;
	int packets = 0;
	uint8_t wack_sent = 0;
	int write_offloading;

	if (!sndvar->sndbuf) {
		TRACE_ERROR("Stream %d: No send buffer available.\n", cur_stream->id);
		assert(0);
		return 0;
	}

	SBUF_LOCK(&sndvar->write_lock);

	if (sndvar->sndbuf->len == 0) {
		packets = 0;
		goto out;
	}
	
	while (1) {
#if USE_CCP
		if (sndvar->missing_seq) {
			seq = sndvar->missing_seq;
		} else {
#endif
			seq = cur_stream->snd_nxt;
#if USE_CCP
		}
#endif
		write_offloading = FALSE;
		// Get the offload buffer with the initial SEQ
		// closest to the current SEQ
		ob = NULL;
		TAILQ_FOREACH(_ob, &sndvar->offload_buffer_list, offload_buffer_link) {
			if (!IS_SEQ_GTE(seq, _ob->head_seq))
				break;
			
			if (_ob != NULL)
				ob = _ob;
		}

		if (!ob)
			ob = TAILQ_FIRST(&sndvar->offload_buffer_list);

		if (ob && TCP_SEQ_GT(ob->head_seq + ob->len, seq)
				&& TCP_SEQ_GEQ(seq, ob->head_seq))
				write_offloading = TRUE;

		data = sndvar->sndbuf->head + (seq - sndvar->sndbuf->head_seq);

		if (write_offloading) {
			len = ob->len - (seq - ob->head_seq);
			offset = ob->offset + (seq - ob->head_seq);
		} else if ((ob && !write_offloading) &&
					!TCP_SEQ_GEQ(seq, ob->head_seq)) {
			// Send data in write buffer first
			len = ob->head_seq - seq;
		} else {
			len = sndvar->sndbuf->len - (seq - sndvar->sndbuf->head_seq);
		}

		if (write_offloading) {
			TAILQ_FOREACH(_o, &sndvar->offload_vars_list, offload_vars_link) {
				if (_o->fid == ob->fid) {
					offload_vars = _o;
					break;
				}
			}
		}

		if (write_offloading && !offload_vars->offload_ready) 
			break;

		// Wait for ECHO
		if (write_offloading) {
			if (cur_stream->snd_nxt_echo_set 
				&& TCP_SEQ_GT(seq, cur_stream->snd_nxt_echo)) {
				break;
			}
		}

		/* if there is no buffered data */
		if (len <= 0)
			break;

		if(write_offloading) {
			assert(offset < (uint64_t) offload_vars->file_len);
			assert(len <= offload_vars->file_len);
		}

#if USE_CCP
		// Without this, mm continually drops packets (not sure why, bursting?) -> mtcp sees lots of losses -> throughput dies
		if(cur_stream->wait_for_acks &&
		   TCP_SEQ_GT(cur_stream->snd_nxt, cur_stream->rcvvar->last_ack_seq)) {
			goto out;
		}
#endif
		/* sanity check */
		if (!write_offloading) {
			if (TCP_SEQ_LT(seq, sndvar->sndbuf->head_seq)) {
				TRACE_ERROR("Stream %d: Invalid sequence to send. "
							"state: %s, seq: %u, head_seq: %u.\n",
							cur_stream->id, TCPStateToString(cur_stream),
							seq, sndvar->sndbuf->head_seq);
				assert(0);
				break;
			}
			if (TCP_SEQ_LT(seq, sndvar->snd_una)) {
				TRACE_ERROR("Stream %d: Invalid sequence to send. "
							"state: %s, seq: %u, snd_una: %u.\n",
							cur_stream->id, TCPStateToString(cur_stream),
							seq, sndvar->snd_una);
				assert(0);
				break;
			}
			if (sndvar->sndbuf->len < (seq - sndvar->sndbuf->head_seq)) {
				TRACE_ERROR("Stream %d: len (%u) < 0 (%u) (SEQ: %u, HU %u)\n",
							cur_stream->id, sndvar->sndbuf->len,
							seq - sndvar->sndbuf->head_seq,
							seq, sndvar->sndbuf->head_seq);
				assert(0);
				break;
			}
		}
			
#if TCP_OPT_SACK_ENABLED
		uint32_t sacked_seq, skipped_bytes;
		if ((sacked_seq = SeqIsSacked(cur_stream, seq))) {
			TRACE_DBG("!! SKIPPING %u\n", seq - sndvar->iss);
			skipped_bytes = sacked_seq - cur_stream->snd_nxt;
			cur_stream->snd_nxt += skipped_bytes;
			continue;
		}
#endif

		remaining_window = MIN(sndvar->cwnd, sndvar->peer_wnd)
			               - (seq - sndvar->snd_una);		
		/* if there is no space in the window */
		if (remaining_window <= 0 ||
		    (remaining_window < sndvar->mss && seq - sndvar->snd_una > 0)) {
			/* if peer window is full, send ACK and let its peer advertises new one */
			if (sndvar->peer_wnd <= sndvar->cwnd) {
#if 0
				TRACE_CLWND("Full peer window. "
							"peer_wnd: %u, (snd_nxt-snd_una): %u\n",
							sndvar->peer_wnd, seq - sndvar->snd_una);
#endif
				if (!wack_sent && TS_TO_MSEC(cur_ts - sndvar->ts_lastack_sent) > 500)
					EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_WACK);
				else
					wack_sent = 1;
			}
			packets = -3;
			goto out;
		}
		
		uint32_t buffer_len = len;
		/* payload size limited by remaining window space */
		len = MIN(len, remaining_window);
		/* payload size limited by TCP MSS */
		if (write_offloading) {
			pkt_len = len;

			/* MSS align packets that are bigger than MSS */
			if (pkt_len + CalculateOptionLength(TCP_FLAG_ACK) > sndvar->mss)
				pkt_len -= pkt_len % (sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK));

			/* If remaining buffer is smaller than MSS, just send as much as we can */
			if (buffer_len - pkt_len < sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK))
				pkt_len = len;
		} else {
			pkt_len = MIN(len, sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK));
		}

#if RATE_LIMIT_ENABLED
		// update rate
		if (cur_stream->rcvvar->srtt) {
			cur_stream->bucket->rate = 
                (uint32_t)(
                    SECONDS_TO_USECS(                                                      // bits / s = mbps
                        BYTES_TO_BITS(                                                     // bits / us 
                            (double)sndvar->cwnd / UNSHIFT_SRTT(cur_stream->rcvvar->srtt)  // bytes / us
                        )
                    )
                );
		}
		if (cur_stream->bucket->rate != 0 && (SufficientTokens(cur_stream->bucket, pkt_len*8) < 0)) {
			packets = -3;
			goto out;
		}
#endif
    
#if PACING_ENABLED
                if (!CanSendNow(cur_stream->pacer)) {
                    packets = -3;
                    goto out;
                }
#endif

		if(pkt_len <= 0)
			break;

		if (write_offloading) {
			// printf("Sent OFFLOAD packet with length: %u\n", pkt_len);
			if ((sndlen = SendOffloadTCPPacket(mtcp, cur_stream, cur_ts,
								TCP_FLAG_ACK, pkt_len, offload_vars->fid, offset)) < 0) {
				/* there is no available tx buf */
				packets = -3;
				goto out;
			}
			mtcp->nstat.tx_offload_bytes[0] += pkt_len;
			assert(seq + sndlen == cur_stream->snd_nxt);
			// Set highest non-ECHOed SEQ to snd_nxt_echo
			if (!cur_stream->snd_nxt_echo_set) {
				cur_stream->snd_nxt_echo = seq;
				cur_stream->snd_nxt_echo_set = TRUE;
			}
		} else {
			// printf("Sent packet with length: %u\n", pkt_len);
			if ((sndlen = SendTCPPacket(mtcp, cur_stream, cur_ts,
								TCP_FLAG_ACK, data, pkt_len)) < 0) {
				/* there is no available tx buf */
				packets = -3;
				goto out;
			}
			cur_stream->snd_nxt_echo_set = FALSE;
		}

#if USE_CCP
		if (sndvar->missing_seq) {
			sndvar->missing_seq = 0;
		}
#endif
		packets++;
	}

 out:
	SBUF_UNLOCK(&sndvar->write_lock);	
	return packets;	
}
/*----------------------------------------------------------------------------*/
static inline int 
SendControlPacket(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	int ret = 0;

	if (cur_stream->state == TCP_ST_SYN_SENT) {
		/* Send SYN here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_SYN, NULL, 0);

	} else if (cur_stream->state == TCP_ST_SYN_RCVD) {
		/* Send SYN/ACK here */
		cur_stream->snd_nxt = sndvar->iss;
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
				TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_ESTABLISHED) {
		/* Send ACK here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_CLOSE_WAIT) {
		/* Send ACK for the FIN here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_LAST_ACK) {
		/* if it is on ack_list, send it after sending ack */
		if (sndvar->on_send_list || sndvar->on_ack_list) {
			ret = -1;
		} else {
			/* Send FIN/ACK here */
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
					TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
		}
	} else if (cur_stream->state == TCP_ST_FIN_WAIT_1) {
		/* if it is on ack_list, send it after sending ack */
		if (sndvar->on_send_list || sndvar->on_ack_list) {
			ret = -1;
		} else {
			/* Send FIN/ACK here */
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
					TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
		}

	} else if (cur_stream->state == TCP_ST_FIN_WAIT_2) {
		/* Send ACK here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_CLOSING) {
		if (sndvar->is_fin_sent) {
			/* if the sequence is for FIN, send FIN */
			if (cur_stream->snd_nxt == sndvar->fss) {
				ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
						TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
			} else {
				ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
						TCP_FLAG_ACK, NULL, 0);
			}
		} else {
			/* if FIN is not sent, send fin with ack */
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
					TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0);
		}

	} else if (cur_stream->state == TCP_ST_TIME_WAIT) {
		/* Send ACK here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0);

	} else if (cur_stream->state == TCP_ST_CLOSED) {
		/* Send RST here */
		TRACE_DBG("Stream %d: Try sending RST (TCP_ST_CLOSED)\n", 
				cur_stream->id);
		/* first flush the data and ack */
		if (sndvar->on_send_list || sndvar->on_ack_list) {
			ret = -1;
		} else {
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_RST, NULL, 0);
			if (ret >= 0) {
				DestroyTCPStream(mtcp, cur_stream);
			}
		}
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
inline int 
WriteTCPControlList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int cnt = 0;
	int ret;

	thresh = MIN(thresh, sender->control_list_cnt);

	/* Send TCP control messages */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->control_list);
	last = TAILQ_LAST(&sender->control_list, control_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside control loop. cnt: %u, stream: %d\n", 
				cnt, cur_stream->id);
		next = TAILQ_NEXT(cur_stream, sndvar->control_link);

		TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
		sender->control_list_cnt--;

		if (cur_stream->sndvar->on_control_list) {
			cur_stream->sndvar->on_control_list = FALSE;
			//TRACE_DBG("Stream %u: Sending control packet\n", cur_stream->id);
			ret = SendControlPacket(mtcp, cur_stream, cur_ts);
			if (ret == -2) {
				TAILQ_INSERT_HEAD(&sender->control_list, 
						cur_stream, sndvar->control_link);
				cur_stream->sndvar->on_control_list = TRUE;
				sender->control_list_cnt++;
				/* since there is no available write buffer, break */
				break;
			} else if (ret < 0) {
				/* try again after handling other streams */
				TAILQ_INSERT_TAIL(&sender->control_list,
						  cur_stream, sndvar->control_link);
				cur_stream->sndvar->on_control_list = TRUE;
				sender->control_list_cnt++;
			}
		} else {
			TRACE_ERROR("Stream %d: not on control list.\n", cur_stream->id);
		}

		if (cur_stream == last) 
			break;
		cur_stream = next;
	}

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline int 
WriteTCPDataList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int cnt = 0;
	int ret;

	/* Send data */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->send_list);
	last = TAILQ_LAST(&sender->send_list, send_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside send loop. cnt: %u, stream: %d\n", 
				cnt, cur_stream->id);
		next = TAILQ_NEXT(cur_stream, sndvar->send_link);

		TAILQ_REMOVE(&sender->send_list, cur_stream, sndvar->send_link);
		if (cur_stream->sndvar->on_send_list) {
			ret = 0;

			/* Send data here */
			/* Only can send data when ESTABLISHED or CLOSE_WAIT */
			if (cur_stream->state == TCP_ST_ESTABLISHED) {
				if (cur_stream->sndvar->on_control_list) {
					/* delay sending data after until on_control_list becomes off */
					//TRACE_DBG("Stream %u: delay sending data.\n", cur_stream->id);
					ret = -1;
				} else {
					ret = FlushTCPSendingBuffer(mtcp, cur_stream, cur_ts);
				}
			} else if (cur_stream->state == TCP_ST_CLOSE_WAIT || 
					cur_stream->state == TCP_ST_FIN_WAIT_1 || 
					cur_stream->state == TCP_ST_LAST_ACK) {
				ret = FlushTCPSendingBuffer(mtcp, cur_stream, cur_ts);
			} else {
				TRACE_DBG("Stream %d: on_send_list at state %s\n", 
						cur_stream->id, TCPStateToString(cur_stream));
#if DUMP_STREAM
				DumpStream(mtcp, cur_stream);
#endif
			}

			if (ret < 0) {
				TAILQ_INSERT_TAIL(&sender->send_list, cur_stream, sndvar->send_link);
				/* since there is no available write buffer, break */
				break;

			} else {
				cur_stream->sndvar->on_send_list = FALSE;
				sender->send_list_cnt--;
				/* the ret value is the number of packets sent. */
				/* decrease ack_cnt for the piggybacked acks */
#if ACK_PIGGYBACK
				if (cur_stream->sndvar->ack_cnt > 0) {
					if (cur_stream->sndvar->ack_cnt > ret) {
						cur_stream->sndvar->ack_cnt -= ret;
					} else {
						cur_stream->sndvar->ack_cnt = 0;
					}
				}
#endif
#if 1
				if (cur_stream->control_list_waiting) {
					if (!cur_stream->sndvar->on_ack_list) {
						cur_stream->control_list_waiting = FALSE;
						AddtoControlList(mtcp, cur_stream, cur_ts);
					}
				}
#endif
			}
		} else {
			TRACE_ERROR("Stream %d: not on send list.\n", cur_stream->id);
#ifdef DUMP_STREAM
			DumpStream(mtcp, cur_stream);
#endif
		}

		if (cur_stream == last) 
			break;
		cur_stream = next;
	}

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline int 
WriteTCPACKList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int to_ack;
	int cnt = 0;
	int ret;

	/* Send aggregated acks */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->ack_list);
	last = TAILQ_LAST(&sender->ack_list, ack_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside ack loop. cnt: %u\n", cnt);
		next = TAILQ_NEXT(cur_stream, sndvar->ack_link);

		if (cur_stream->sndvar->on_ack_list) {
			/* this list is only to ack the data packets */
			/* if the ack is not data ack, then it will not process here */
			to_ack = FALSE;
			if (cur_stream->state == TCP_ST_ESTABLISHED || 
					cur_stream->state == TCP_ST_CLOSE_WAIT || 
					cur_stream->state == TCP_ST_FIN_WAIT_1 || 
					cur_stream->state == TCP_ST_FIN_WAIT_2 || 
					cur_stream->state == TCP_ST_TIME_WAIT) {
				/* TIMEWAIT is possible since the ack is queued 
				   at FIN_WAIT_2 */
				if (cur_stream->rcvvar->rcvbuf) {
					if (TCP_SEQ_LEQ(cur_stream->rcv_nxt, 
								cur_stream->rcvvar->rcvbuf->head_seq + 
								cur_stream->rcvvar->rcvbuf->merged_len)) {
						to_ack = TRUE;
					}
				}
			} else {
				TRACE_DBG("Stream %u (%s): "
						"Try sending ack at not proper state. "
						"seq: %u, ack_seq: %u, on_control_list: %u\n", 
						cur_stream->id, TCPStateToString(cur_stream), 
						cur_stream->snd_nxt, cur_stream->rcv_nxt, 
						cur_stream->sndvar->on_control_list);
#ifdef DUMP_STREAM
				DumpStream(mtcp, cur_stream);
#endif
			}

			if (to_ack) {
				/* send the queued ack packets */
				while (cur_stream->sndvar->ack_cnt > 0) {
					ret = SendTCPPacket(mtcp, cur_stream, 
							cur_ts, TCP_FLAG_ACK, NULL, 0);
					if (ret < 0) {
						/* since there is no available write buffer, break */
						break;
					}
					cur_stream->sndvar->ack_cnt--;
				}

				/* if is_wack is set, send packet to get window advertisement */
				if (cur_stream->sndvar->is_wack) {
					cur_stream->sndvar->is_wack = FALSE;
					ret = SendTCPPacket(mtcp, cur_stream, 
							cur_ts, TCP_FLAG_ACK | TCP_FLAG_WACK, NULL, 0);
					if (ret < 0) {
						/* since there is no available write buffer, break */
						cur_stream->sndvar->is_wack = TRUE;
					}
				}

				if (!(cur_stream->sndvar->ack_cnt || cur_stream->sndvar->is_wack)) {
					cur_stream->sndvar->on_ack_list = FALSE;
					TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
					sender->ack_list_cnt--;
				}
			} else {
				cur_stream->sndvar->on_ack_list = FALSE;
				cur_stream->sndvar->ack_cnt = 0;
				cur_stream->sndvar->is_wack = 0;
				TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
				sender->ack_list_cnt--;
			}

			if (cur_stream->control_list_waiting) {
				if (!cur_stream->sndvar->on_send_list) {
					cur_stream->control_list_waiting = FALSE;
					AddtoControlList(mtcp, cur_stream, cur_ts);
				}
			}
		} else {
			TRACE_ERROR("Stream %d: not on ack list.\n", cur_stream->id);
			TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
			sender->ack_list_cnt--;
#ifdef DUMP_STREAM
			thread_printf(mtcp, mtcp->log_fp, 
					"Stream %u: not on ack list.\n", cur_stream->id);
			DumpStream(mtcp, cur_stream);
#endif
		}

		if (cur_stream == last)
			break;
		cur_stream = next;
	}

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline struct mtcp_sender *
GetSender(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	if (cur_stream->sndvar->nif_out < 0) {
		return mtcp->g_sender;
	}

	int eidx = CONFIG.nif_to_eidx[cur_stream->sndvar->nif_out];
	if (eidx < 0 || eidx >= CONFIG.eths_num) {
		TRACE_ERROR("(NEVER HAPPEN) Failed to find appropriate sender.\n");
		return NULL;
	}

	return mtcp->n_sender[eidx];
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoControlList(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
#if TRY_SEND_BEFORE_QUEUE
	int ret;
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	ret = SendControlPacket(mtcp, cur_stream, cur_ts);
	if (ret < 0) {
#endif
		if (!cur_stream->sndvar->on_control_list) {
			struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
			assert(sender != NULL);

			cur_stream->sndvar->on_control_list = TRUE;
			TAILQ_INSERT_TAIL(&sender->control_list, cur_stream, sndvar->control_link);
			sender->control_list_cnt++;
			//TRACE_DBG("Stream %u: added to control list (cnt: %d)\n", 
			//		cur_stream->id, sender->control_list_cnt);
		}
#if TRY_SEND_BEFORE_QUEUE
	} else {
		if (cur_stream->sndvar->on_control_list) {
			cur_stream->sndvar->on_control_list = FALSE;
			TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
			sender->control_list_cnt--;
		}
	}
#endif
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoSendList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if(!cur_stream->sndvar->sndbuf) {
		TRACE_ERROR("[%d] Stream %d: No send buffer available.\n", 
				mtcp->ctx->cpu,
				cur_stream->id);
		assert(0);
		return;
	}

	if (!cur_stream->sndvar->on_send_list) {
		cur_stream->sndvar->on_send_list = TRUE;
		TAILQ_INSERT_TAIL(&sender->send_list, cur_stream, sndvar->send_link);
		sender->send_list_cnt++;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoACKList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (!cur_stream->sndvar->on_ack_list) {
		cur_stream->sndvar->on_ack_list = TRUE;
		TAILQ_INSERT_TAIL(&sender->ack_list, cur_stream, sndvar->ack_link);
		sender->ack_list_cnt++;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
RemoveFromControlList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (cur_stream->sndvar->on_control_list) {
		cur_stream->sndvar->on_control_list = FALSE;
		TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
		sender->control_list_cnt--;
		//TRACE_DBG("Stream %u: Removed from control list (cnt: %d)\n", 
		//		cur_stream->id, sender->control_list_cnt);
	}
}
/*----------------------------------------------------------------------------*/
inline void 
RemoveFromSendList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (cur_stream->sndvar->on_send_list) {
		cur_stream->sndvar->on_send_list = FALSE;
		TAILQ_REMOVE(&sender->send_list, cur_stream, sndvar->send_link);
		sender->send_list_cnt--;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
RemoveFromACKList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (cur_stream->sndvar->on_ack_list) {
		cur_stream->sndvar->on_ack_list = FALSE;
		TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
		sender->ack_list_cnt--;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
EnqueueACK(mtcp_manager_t mtcp, 
		tcp_stream *cur_stream, uint32_t cur_ts, uint8_t opt)
{
	if (!(cur_stream->state == TCP_ST_ESTABLISHED || 
			cur_stream->state == TCP_ST_CLOSE_WAIT || 
			cur_stream->state == TCP_ST_FIN_WAIT_1 || 
			cur_stream->state == TCP_ST_FIN_WAIT_2)) {
		TRACE_DBG("Stream %u: Enqueueing ack at state %s\n", 
				cur_stream->id, TCPStateToString(cur_stream));
	}

	if (opt == ACK_OPT_NOW) {
		if (cur_stream->sndvar->ack_cnt < cur_stream->sndvar->ack_cnt + 1) {
			cur_stream->sndvar->ack_cnt++;
		}
	} else if (opt == ACK_OPT_AGGREGATE) {
		if (cur_stream->sndvar->ack_cnt == 0) {
			cur_stream->sndvar->ack_cnt = 1;
		}
	} else if (opt == ACK_OPT_WACK) {
		cur_stream->sndvar->is_wack = TRUE;
	}
	AddtoACKList(mtcp, cur_stream);
}
/*----------------------------------------------------------------------------*/
inline void 
DumpControlList(mtcp_manager_t mtcp, struct mtcp_sender *sender)
{
	tcp_stream *stream;

	TRACE_DBG("Dumping control list (count: %d):\n", sender->control_list_cnt);
	TAILQ_FOREACH(stream, &sender->control_list, sndvar->control_link) {
		TRACE_DBG("Stream id: %u in control list\n", stream->id);
	}
}
/*----------------------------------------------------------------------------*/
int
SendOffloadMetaPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream,
						char *payload, int payloadlen)
{

	struct tcphdr *tcph;

	if (payloadlen < 0) {
		TRACE_ERROR("Offload command invalid");
		return -2;
	}
		
	tcph = (struct tcphdr *)IPOffloadOutput(mtcp, cur_stream, 
			TCP_HEADER_LEN + payloadlen);

	if (tcph == NULL) {
		return -2;
	}
	memset(tcph, 0, TCP_HEADER_LEN);

	tcph->source = cur_stream->sport;
	tcph->dest = cur_stream->dport;
	
	tcph->doff = (TCP_HEADER_LEN) >> 2;
	
	if (payloadlen > 0) {
		memcpy((uint8_t *)tcph + TCP_HEADER_LEN,
					 payload, payloadlen);
	}

	return 0;
}
/*----------------------------------------------------------------------------*/
inline int
WriteTCPOffloadFileList(mtcp_manager_t mtcp, struct mtcp_sender *sender,
												uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	struct tcp_send_vars *sndvar;
	struct offload_vars *ov, *_o;
	char payload[OFFLOAD_META_PAYLOAD_LIMIT];
	int cnt = 0;
	int ret;
	int flag_to_send = 0;
	int remove_stream;
	int payloadlen;
	unsigned char *haddr;

	if (sender->offload_file_list_cnt <= 0)
		return cnt;

	/* Send TCP offload file messages */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->offload_file_list);
	last = TAILQ_LAST(&sender->offload_file_list, offload_file_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside offload file loop. cnt: %u, stream: %d\n", 
				cnt, cur_stream->id);
		next = TAILQ_NEXT(cur_stream, sndvar->offload_file_link);

		sndvar = cur_stream->sndvar;

		remove_stream = TRUE;

		haddr = GetDestinationHWaddr(cur_stream->daddr, cur_stream->is_external);
		if (!haddr) {
			// TCP setup should've received the haddr
			break;
		}

		SBUF_LOCK(&sndvar->write_lock);

		TAILQ_FOREACH_SAFE(ov, &sndvar->offload_vars_list,
											 offload_vars_link, _o) {
			// Only check offload vars with flags
			if (!ov->offload_flags)
				continue;

			flag_to_send = 0;
			if (ov->offload_flags & OFFLOAD_FLAG_OPEN)
				flag_to_send = OFFLOAD_FLAG_OPEN;

			ov->offload_flags -= flag_to_send;
			
			if (flag_to_send) {				
				//TRACE_DBG("Stream %u: Sending offload file packet\n", cur_stream->id);
				payloadlen = sprintf(payload, 
					"OPEN %u %s %02x:%02x:%02x:%02x:%02x:%02x",
		 			ov->fid, ov->offload_fn, haddr[0], haddr[1], 
					haddr[2], haddr[3], haddr[4], haddr[5]);
#if !NO_FS_PERFTEST
				ret = SendOffloadMetaPacket(mtcp, cur_stream,
									payload, payloadlen);
				if (ret < 0) {
					ov->offload_flags += flag_to_send;
					cur_stream->sndvar->on_offload_file_list = TRUE;
					remove_stream = FALSE;
					continue;
				}
#else
				(void)(ret);
				(void)(payloadlen);
#endif

				ov->offload_ready = TRUE;
				/* Put the stream back on the send queue */
				if (cur_stream->sndvar->sndbuf->len > 0 &&
						!(cur_stream->sndvar->on_sendq ||
						cur_stream->sndvar->on_send_list)) {
					SQ_LOCK(&mtcp->ctx->sendq_lock);
					cur_stream->sndvar->on_sendq = TRUE;
					StreamEnqueue(mtcp->sendq, cur_stream);		/* this always success */
					SQ_UNLOCK(&mtcp->ctx->sendq_lock);
					mtcp->wakeup_flag = TRUE;
				}
			} else {
				// Another OV needs to send the open
				continue;
			}

			// Don't remove stream from offload send list if there are still flags
			if (ov->offload_flags & OFFLOAD_FLAG_OPEN) {
				remove_stream = FALSE;
			}
		}

		if(remove_stream) {
			TAILQ_REMOVE(&sender->offload_file_list, cur_stream,
									 sndvar->offload_file_link);
			sender->offload_file_list_cnt--;
			cur_stream->sndvar->on_offload_file_list = FALSE;
		}

		SBUF_UNLOCK(&sndvar->write_lock);

		if (cur_stream == last) 
			break;
		cur_stream = next;
	}

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoOffloadFileList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	if (!cur_stream->sndvar->on_offload_file_list) {
		struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
		assert(sender != NULL);

		cur_stream->sndvar->on_offload_file_list = TRUE;
		TAILQ_INSERT_TAIL(&sender->offload_file_list, cur_stream,
											sndvar->offload_file_link);
		sender->offload_file_list_cnt++;
		//TRACE_DBG("Stream %u: added to offload file list (cnt: %d)\n", 
		//		cur_stream->id, sender->offload_file_list_cnt);
	}
}
/*----------------------------------------------------------------------------*/
int
SendOffloadTCPPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t flags, int payloadlen,
		uint32_t fid, uint64_t offset)
{
	struct tcphdr *tcph;
	uint16_t optlen;
	uint8_t wscale = 0;
	uint32_t window32 = 0;
	uint16_t tcp_payloadlen;
	char payload[OFFLOAD_NAME_LIMIT];

	optlen = CalculateOptionLength(flags);

	tcp_payloadlen = sprintf(payload, "SEND %u %ld %d",
								fid, offset,payloadlen);

	tcph = (struct tcphdr *)IPOffloadOutput(mtcp, cur_stream, 
		TCP_HEADER_LEN + optlen + tcp_payloadlen);
	
	if (tcph == NULL) {
		return -2;
	}
	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = cur_stream->sport;
	tcph->dest = cur_stream->dport;

	if (flags & TCP_FLAG_SYN) {
		tcph->syn = TRUE;
		if (cur_stream->snd_nxt != cur_stream->sndvar->iss) {
			TRACE_DBG("Stream %d: weird SYN sequence. "
					"snd_nxt: %u, iss: %u\n", cur_stream->id, 
					cur_stream->snd_nxt, cur_stream->sndvar->iss);
		}
#if 0
		TRACE_FIN("Stream %d: Sending SYN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
#endif
	}
	if (flags & TCP_FLAG_RST) {
		TRACE_FIN("Stream %d: Sending RST.\n", cur_stream->id);
		tcph->rst = TRUE;
	}
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	if (flags & TCP_FLAG_WACK) {
		tcph->seq = htonl(cur_stream->snd_nxt - 1);
		TRACE_CLWND("%u Sending ACK to get new window advertisement. "
				"seq: %u, peer_wnd: %u, snd_nxt - snd_una: %u\n", 
				cur_stream->id,
				cur_stream->snd_nxt - 1, cur_stream->sndvar->peer_wnd, 
				cur_stream->snd_nxt - cur_stream->sndvar->snd_una);
	} else if (flags & TCP_FLAG_FIN) {
		tcph->fin = TRUE;
		
		if (cur_stream->sndvar->fss == 0) {
			TRACE_ERROR("Stream %u: not fss set. closed: %u\n", 
					cur_stream->id, cur_stream->closed);
		}
		tcph->seq = htonl(cur_stream->sndvar->fss);
		cur_stream->sndvar->is_fin_sent = TRUE;
		TRACE_FIN("Stream %d: Sending FIN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
	} else {
		tcph->seq = htonl(cur_stream->snd_nxt);
	}

	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(cur_stream->rcv_nxt);
		cur_stream->sndvar->ts_lastack_sent = cur_ts;
		cur_stream->last_active_ts = cur_ts;
		UpdateTimeoutList(mtcp, cur_stream);
	}

	if (flags & TCP_FLAG_SYN) {
		wscale = 0;
	} else {
		wscale = cur_stream->sndvar->wscale_mine;
	}

	window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
	tcph->window = htons((uint16_t)MIN(window32, TCP_MAX_WINDOW));
	/* if the advertised window is 0, we need to advertise again later */
	if (window32 == 0) {
		cur_stream->need_wnd_adv = TRUE;
	}

	GenerateTCPOptions(cur_stream, cur_ts, flags, 
			(uint8_t *)tcph + TCP_HEADER_LEN, optlen);
	
	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;

	if (tcp_payloadlen > 0) {
		memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, tcp_payloadlen);
	}

	if (payloadlen > 0) {
		cur_stream->snd_nxt += payloadlen;
	}

	if (tcph->syn || tcph->fin) {
		cur_stream->snd_nxt++;
		payloadlen++;
	}

	if (payloadlen > 0) {
		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("Payload after ESTABLISHED: length: %d, snd_nxt: %u\n", 
					payloadlen, cur_stream->snd_nxt);
		}
	}

	// Remove from RTO list if already in there
	if (cur_stream->on_rto_idx >= 0) {
		RemoveFromRTOList(mtcp, cur_stream);
	}

	return payloadlen;
}
