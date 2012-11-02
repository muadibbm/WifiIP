#include "igmp.h"

void IGMPProcessPacket(gpacket_t *in_pkt)
{
	ip_packet_t *ip_pkt = (ip_packet_t *)in_pkt->data.data;
	int iphdrlen = ip_pkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *)((uchar *)ip_pkt + iphdrlen);

	switch (igmphdr->type)
	{
		case IGMP_ECHO_REQUEST:
			verbose(2, "[IGMPProcessPacket]:: IGMP processing for ECHO request");
			IGMPProcessEchoRequest(in_pkt);
			break;

		case IGMP_ECHO_REPLY:
			verbose(2, "[IGMPProcessPacket]:: IGMP processing for ECHO reply");
			IGMPProcessEchoReply(in_pkt);
			break;

		case IGMP_REDIRECT:
		case IGMP_SOURCE_QUENCH:
		case IGMP_TIMESTAMP:
		case IGMP_TIMESTAMPREPLY:
		case IGMP_INFO_REQUEST:
		case IGMP_INFO_REPLY:
			verbose(2, "[IGMPProcessPacket]:: IGMP processing for type %d not implemented ", igmphdr->type);
			break;
	}
}

/* Send a membership request maybe??
*/
void IGMPSendMReq(uchar *ipaddr, int pkt_size, int retries)
{
	static int ping_active = 0;
	int i;
	char tmpbuf[64];

	// initialize the ping statistics structure
	pstat.tmin = LARGE_REAL_NUMBER;
	pstat.tmax = SMALL_REAL_NUMBER;
	pstat.tsum = 0;
	pstat.ntransmitted = 0;
	pstat.nreceived = 0;

	if (ping_active == 0)
	{
		printf("Pinging IP Address [%s]\n", IP2Dot(tmpbuf, ipaddr));
		ping_active = 1;
		
		for(i=0; i < retries; i++)
			IGMPSendReqPacket(ipaddr, pkt_size, i);

		ping_active = 0;
	}

}

// Send the request packet
void IGMPSendReqPacket(uchar *dst_ip, int size, int seq)
{
	gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
	ip_packet_t *ipkt = (ip_packet_t *)(out_pkt->data.data);
	ipkt->ip_hdr_len = 5;                                  // no IP header options!!
	igmphdr_t *igmphdr = (igmphdr_t *)((uchar *)ipkt + ipkt->ip_hdr_len*4);
	ushort cksum;
	struct timeval *tp = (struct timeval *)((uchar *)igmphdr + 8);
	struct timezone tz;
	uchar *dataptr;
	int i;
	char tmpbuf[64];

	pstat.ntransmitted++;

	igmphdr->type = IGMP_ECHO_REQUEST;
	igmphdr->code = 0;
	igmphdr->checksum = 0;
	igmphdr->un.echo.id = getpid() & 0xFFFF;
	igmphdr->un.echo.sequence = seq;
	gettimeofday(tp, &tz);

	dataptr = ((uchar *)igmphdr + 8 +  sizeof(struct timeval));
	// pad data...
	for (i = 8; i < size; i++)
		*dataptr++ = i;

	cksum = checksum((uchar *)igmphdr, size/2);  // size = payload (given) + IGMP_header
	igmphdr->checksum = htons(cksum);

	verbose(2, "[sendPingPacket]:: Sending... IGMP ping to  %s", IP2Dot(tmpbuf, dst_ip));

	// send the message to the IP routine for further processing
	// the IP should create new header .. provide needed information from here.
	// tag the message as new packet
	// IPOutgoingPacket(/context, packet, IPaddr, size, newflag, source)
	IPOutgoingPacket(out_pkt, dst_ip, size, 1, IGMP_PROTOCOL);
}

void IGMPProcessTTLExpired(gpacket_t *in_pkt)
{
	ip_packet_t *ipkt = (ip_packet_t *)in_pkt->data.data;
	int iphdrlen = ipkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *)((uchar *)ipkt + iphdrlen);
	ushort cksum;
	char tmpbuf[MAX_TMPBUF_LEN];
	int iprevlen = iphdrlen + 8;  // IP header + 64 bits
	uchar prevbytes[MAX_IPREVLENGTH_IGMP];

	memcpy(prevbytes, (uchar *)ipkt, iprevlen);

	/*
	 * form an IGMP TTL expired message and fill in IGMP
	 * header ...
	 */
	igmphdr->type = IGMP_TTL_EXPIRED;
	igmphdr->code = 0; 
	igmphdr->checksum = 0;
	bzero((void *)&(igmphdr->un), sizeof(igmphdr->un));
	memcpy(((uchar *)igmphdr + 8), prevbytes, iprevlen);    /* ip header + 64 bits of original pkt */
	cksum = checksum((uchar *)igmphdr, (8 + iprevlen)/2 );
	igmphdr->checksum = htons(cksum);

	verbose(2, "[IGMPProcessTTLExpired]:: Sending... IGMP TTL expired message ");
	printf("Checksum at IGMP routine (TTL expired):  %x\n", cksum);

	// send the message back to the IP module for further processing ..
	// set the messsage as REPLY_PACKET
	IPOutgoingPacket(in_pkt, gNtohl(tmpbuf, ipkt->ip_src), 8+iprevlen, 1, IGMP_PROTOCOL);
}

void IGMPProcessEchoRequest(gpacket_t *in_pkt)
{
	ip_packet_t *ipkt = (ip_packet_t *)in_pkt->data.data;
	int iphdrlen = ipkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *)((uchar *)ipkt + iphdrlen);
	uchar *icmppkt_b = (uchar *)igmphdr;

	ushort cksum;
	int ilen = ntohs(ipkt->ip_pkt_len) - iphdrlen;


	igmphdr->type = ICMP_ECHO_REPLY;
	igmphdr->checksum = 0;
	if (IS_ODD(ilen))
	{
		// pad with a zero byte.. IP packet length remains the same 
		icmppkt_b[ilen] = 0x0;
		ilen++;
	}
	cksum = checksum(icmppkt_b, (ilen/2));
	igmphdr->checksum = htons(cksum);
	
	// send the message back to the IP routine for further processing ..
	// set the messsage as REPLY_PACKET..
	// destination IP and size need not be set. they can be obtained from the original packet
	
	IPOutgoingPacket(in_pkt, NULL, 0, 0, IGMP_PROTOCOL);
}

void IGMPProcessEchoReply(gpacket_t *in_pkt)
{
	ip_packet_t *ipkt = (ip_packet_t *)in_pkt->data.data;
	int iphdrlen = ipkt->ip_hdr_len *4;
	igmphdr_t *igmphdr = (igmphdr_t *)((uchar *)ipkt + iphdrlen);
	uchar *IGMPpkt_b = (uchar *)igmphdr;

	struct timeval tv;
	struct timezone tz;
	char tmpbuf[MAX_TMPBUF_LEN];
	double elapsed_time;

	if (igmphdr->type == IGMP_ECHO_REPLY)
	{
		pstat.nreceived++;

		gettimeofday(&tv, &tz);
		elapsed_time = subTimeVal(&tv, (struct timeval *)(IGMPpkt_b + 8));
		printf("%d bytes from %s: igmp_seq=%d ttl=%d time=%6.3f ms\n", 
		       (ntohs(ipkt->ip_pkt_len) - iphdrlen - 8),
		       IP2Dot(tmpbuf, gNtohl((tmpbuf+20), ipkt->ip_src)), 
		       ntohs(igmphdr->un.echo.sequence), ipkt->ip_ttl, elapsed_time);
	}
}

//function to receive the datagram with IP multicast "1110"

//function to check the TTL, compare it with the router threshold value; if acceptabe increment the TTL and call forwarding function