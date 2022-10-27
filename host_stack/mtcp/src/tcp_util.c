#include <assert.h>

#include "tcp_util.h"
#include "tcp_ring_buffer.h"
#include "eventpoll.h"
#include "debug.h"
#include "timer.h"
#include "ip_in.h"

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

/*---------------------------------------------------------------------------*/
void 
ParseTCPOptions(tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t *tcpopt, int len)
{
	int i;
	unsigned int opt, optlen;

	for (i = 0; i < len; ) {
		opt = *(tcpopt + i++);
		
		if (opt == TCP_OPT_END) {	// end of option field
			break;
		} else if (opt == TCP_OPT_NOP) {	// no option
			continue;
		} else {

			optlen = *(tcpopt + i++);
			if (i + optlen - 2 > len) {
				break;
			}

			if (opt == TCP_OPT_MSS) {
				cur_stream->sndvar->mss = *(tcpopt + i++) << 8;
				cur_stream->sndvar->mss += *(tcpopt + i++);
				cur_stream->sndvar->eff_mss = cur_stream->sndvar->mss;
#if TCP_OPT_TIMESTAMP_ENABLED
				cur_stream->sndvar->eff_mss -= (TCP_OPT_TIMESTAMP_LEN + 2);
#endif
			} else if (opt == TCP_OPT_WSCALE) {
				cur_stream->sndvar->wscale_peer = *(tcpopt + i++);
			} else if (opt == TCP_OPT_SACK_PERMIT) {
				cur_stream->sack_permit = TRUE;
				TRACE_SACK("Remote SACK permited.\n");
			} else if (opt == TCP_OPT_TIMESTAMP) {
				TRACE_TSTAMP("Saw peer timestamp!\n");
				cur_stream->saw_timestamp = TRUE;
				cur_stream->rcvvar->ts_recent = ntohl(*(uint32_t *)(tcpopt + i));
				cur_stream->rcvvar->ts_last_ts_upd = cur_ts;
				i += 8;
			} else {
				// not handle
				i += optlen - 2;
			}
		}
	}
}
/*---------------------------------------------------------------------------*/
inline int  
ParseTCPTimestamp(tcp_stream *cur_stream, 
		struct tcp_timestamp *ts, uint8_t *tcpopt, int len)
{
	int i;
	unsigned int opt, optlen;

	for (i = 0; i < len; ) {
		opt = *(tcpopt + i++);
		
		if (opt == TCP_OPT_END) {	// end of option field
			break;
		} else if (opt == TCP_OPT_NOP) {	// no option
			continue;
		} else {
			optlen = *(tcpopt + i++);
			if (i + optlen - 2 > len) {
				break;
			}

			if (opt == TCP_OPT_TIMESTAMP) {
				ts->ts_val = ntohl(*(uint32_t *)(tcpopt + i));
				ts->ts_ref = ntohl(*(uint32_t *)(tcpopt + i + 4));
				return TRUE;
			} else {
				// not handle
				i += optlen - 2;
			}
		}
	}
	return FALSE;
}
#if TCP_OPT_SACK_ENABLED
/*----------------------------------------------------------------------------*/
uint32_t
SeqIsSacked(tcp_stream *cur_stream, uint32_t seq)
{
	uint8_t i;
	uint32_t left, right;
	struct sack_entry *ptable = cur_stream->rcvvar->sack_table;
	
	for (i = 0; i < MAX_SACK_ENTRY; i++) {
		left = ptable[i].left_edge;
		right = ptable[i].right_edge;
		if (seq >= left && seq < right) {
			// fprintf(stderr, "Found seq=%u in (%u,%u)\n", seq - cur_stream->sndvar->iss, left - cur_stream->sndvar->iss, right - cur_stream->sndvar->iss);
			return right;
		} 
	}
	return FALSE;
}
/*----------------------------------------------------------------------------*/
void
_update_sack_table(tcp_stream *cur_stream,
				   uint32_t left_edge, uint32_t right_edge)
{
	uint8_t i, j;
	uint32_t newly_sacked = 0;
	// long int ld, rd, lrd, rld;
	long int ld, rd;
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	struct sack_entry *ptable = rcvvar->sack_table;
	int cursacks = rcvvar->sacks;

	// updated by KS
	
	for (i = 0; i < cursacks; i++) {
		// if block already in table, don't need to do anything
		ld = (long int) left_edge - ptable[i].left_edge;
		rd = (long int) right_edge - ptable[i].right_edge;
		if (ld >= 0 && rd <= 0) {
			return;
		}

		// if block does not overlap i at all, skip
		// rld = (long int) right_edge - ptable[i].left_edge;
		// if (rld < 0) {
		if (right_edge < ptable[i].left_edge) {
			// no overlap, and the range is left to the current entry
			// we need to insert the new entry at the current position
			// 1. move the entrys [i..cursacks-1] to [i+1..cursacks]
			// 2. store the new entry at the current position
			// 3. increment sacks by one and return
			// - assume we have enough space (cursacks < MAX_SACK_ENTRY)
			assert(cursacks < MAX_SACK_ENTRY);
			memmove(&ptable[i+1], &ptable[i],
					sizeof(struct sack_entry) * (cursacks - i));
			ptable[i].left_edge = left_edge;
			ptable[i].right_edge = right_edge;
			rcvvar->sacks++;
			return;
		}
		// lrd = (long int) left_edge - ptable[i].right_edge;
		// if (lrd > 0)  // no overlap so far, see if there's overlap with
		if (left_edge > ptable[i].right_edge) // no overlap so far, see if there's overlap with
			continue; // the next entry
					  
		// left_edge is further left than i.left_edge
		if (ld < 0) {
			newly_sacked += (-ld);
			ptable[i].left_edge = left_edge;
		}
		
		// right edge is further right than i.right_edge
		if (rd > 0) {
			int merged = 0; /* # of merged entries */
			
			newly_sacked += rd;
			// expand i to account for this extra space, and merge with any
			// blocks whose left_edge = i.right (i.e. blocks are touching)
			ptable[i].right_edge = right_edge;
			for (j = i+1; j < cursacks; j++) {
				if (right_edge >= ptable[j].left_edge) {
					/* entry j must be merged */
					merged++;
					if (right_edge <= ptable[j].right_edge) {
						/* merge until entry j */
						/* will stop at the next interation */
						ptable[i].right_edge = ptable[j].right_edge;

						/* subtract the existing range */
						newly_sacked -= (right_edge - ptable[j].left_edge + 1);
					}
					else {
						/* subtract the existing range */
						newly_sacked -=
							(ptable[j].right_edge - ptable[j].left_edge + 1);
					}
				} else {
					/* right_edge < ptable[j].left_edge */
					/* so stop here */
					break;
				} 
			}
			/* merge entries [i+1..j-1] into entry i */
			/* move [j..cursacks-1] into [i+1..(cursacks-merged-1)] */
			/* zero init into [(cursacks-merged)..cursacks-1] */
			/* merged == (j - i - 1) */
			if (merged > 0) {
				if (j < cursacks) 
					memmove(&ptable[i+1], &ptable[j],
							sizeof(struct sack_entry) * (cursacks - j));
				
				memset(&ptable[cursacks-merged],
					   0, sizeof(struct sack_entry) * merged);
				rcvvar->sacks -= merged;
			}
		}
		break;
	}

	if (newly_sacked == 0) {
		ptable[rcvvar->sacks].left_edge = left_edge;
		ptable[rcvvar->sacks].right_edge = right_edge;
		rcvvar->sacks++;
		newly_sacked = (right_edge - left_edge + 1);
	}

	// fprintf(stderr, "SACK (DST: %u) (%u,%u)->%u/%u\n", ntohs(cur_stream->dport), left_edge, right_edge, newly_sacked, newly_sacked / 1448);
	rcvvar->sacked_pkts += (newly_sacked / cur_stream->sndvar->mss);
}
/*----------------------------------------------------------------------------*/
int
GenerateSACKOption(tcp_stream *cur_stream, uint8_t *tcpopt)
{
	// TODO
	return 0;
}
/*----------------------------------------------------------------------------*/
void
ParseSACKOption(tcp_stream *cur_stream, 
		uint32_t ack_seq, uint8_t *tcpopt, int len)
{
	int i, j;
	unsigned int opt, optlen;
	uint32_t left_edge, right_edge;

	for (i = 0; i < len; ) {
		opt = *(tcpopt + i++);
		
		if (opt == TCP_OPT_END) {	// end of option field
			break;
		} else if (opt == TCP_OPT_NOP) {	// no option
			continue;
		} else {
			optlen = *(tcpopt + i++);
			if (i + optlen - 2 > len) {
				break;
			}

            if (opt == TCP_OPT_SACK) {
                j = 0;
                while (j < optlen - 2) {
                    left_edge = ntohl(*(uint32_t *)(tcpopt + i + j));
                    right_edge = ntohl(*(uint32_t *)(tcpopt + i + j + 4));

					/* fixed by KS */
					if (left_edge <= right_edge) {
						_update_sack_table(cur_stream, left_edge, right_edge);
					}
					else {
						/* range wraps around? split it into two entries */
						_update_sack_table(cur_stream, left_edge, 0xFFFFFFFF);
						_update_sack_table(cur_stream, 0, right_edge);
					}

                    j += 8;
#if RTM_STAT
                    cur_stream->rstat->sack_cnt++;
                    cur_stream->rstat->sack_bytes += (right_edge - left_edge);
#endif
                    if (cur_stream->rcvvar->dup_acks == 3) {
#if RTM_STAT
                        cur_stream->rstat->tdp_sack_cnt++;
                        cur_stream->rstat->tdp_sack_bytes += (right_edge - left_edge);
#endif
                        TRACE_LOSS("SACK entry. "
                                    "left_edge: %u, right_edge: %u (ack_seq: %u)\n",
                                    left_edge, right_edge, ack_seq);

                    }
                    TRACE_SACK("Found SACK entry. "
                                "left_edge: %u, right_edge: %u\n", 
                                left_edge, right_edge);
                }
                i += j;
            } else {
                // not handle
                i += optlen - 2;
            }
        }
	}
}
/*---------------------------------------------------------------------------*/
void
ClearSACKTable(tcp_stream *cur_stream, uint32_t ack_seq)
{
	int i, cursacks;
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	struct sack_entry *ptable = rcvvar->sack_table;
	
	cursacks = rcvvar->sacks;
	for (i = 0; i < cursacks; i++) {
		if (!IS_SEQ_GT(ack_seq, ptable[i].right_edge))
			break;
	}

	if (i > 0) {
		if (cursacks > i)
			memmove(ptable,	&ptable[i],
					sizeof(struct sack_entry) * (cursacks - i));

		memset(&ptable[cursacks-i], 0, sizeof(struct sack_entry) * i);

		rcvvar->sacks = cursacks - i;
	}
}
#endif /* TCP_OPT_SACK_ENABLED */
/*---------------------------------------------------------------------------*/
uint16_t
TCPCalcChecksum(uint16_t *buf, uint16_t len, uint32_t saddr, uint32_t daddr)
{
	uint32_t sum;
	uint16_t *w;
	int nleft;
	
	sum = 0;
	nleft = len;
	w = buf;
	
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}
	
	// add padding for odd length
	if (nleft)
		sum += *w & ntohs(0xFF00);
	
	// add pseudo header
	sum += (saddr & 0x0000FFFF) + (saddr >> 16);
	sum += (daddr & 0x0000FFFF) + (daddr >> 16);
	sum += htons(len);
	sum += htons(IPPROTO_TCP);
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	
	sum = ~sum;
	
	return (uint16_t)sum;
}
/*---------------------------------------------------------------------------*/
void 
PrintTCPOptions(uint8_t *tcpopt, int len)
{
	int i;
	unsigned int opt, optlen;

	for (i = 0; i < len; i++) {
		printf("%u ", tcpopt[i]);
	}
	printf("\n");

	for (i = 0; i < len; ) {
		opt = *(tcpopt + i++);
		
		if (opt == TCP_OPT_END) {	// end of option field
			break;
		} else if (opt == TCP_OPT_NOP) {	// no option
			continue;
		} else {

			optlen = *(tcpopt + i++);

			printf("Option: %d", opt);
			printf(", length: %d", optlen);

			if (opt == TCP_OPT_MSS) {
				uint16_t mss;
				mss = *(tcpopt + i++) << 8;
				mss += *(tcpopt + i++);
				printf(", MSS: %u", mss);
			} else if (opt == TCP_OPT_SACK_PERMIT) {
				printf(", SACK permit");
			} else if (opt == TCP_OPT_TIMESTAMP) {
				uint32_t ts_val, ts_ref;
				ts_val = *(uint32_t *)(tcpopt + i);
				i += 4;
				ts_ref = *(uint32_t *)(tcpopt + i);
				i += 4;
				printf(", TSval: %u, TSref: %u", ts_val, ts_ref);
			} else if (opt == TCP_OPT_WSCALE) {
				uint8_t wscale;
				wscale = *(tcpopt + i++);
				printf(", Wscale: %u", wscale);
			} else {
				// not handle
				i += optlen - 2;
			}
			printf("\n");
		}
	}
}