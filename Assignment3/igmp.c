#include "igmp.h"

// state information on outstanding ping..
pingstat_t pstat;

// Andrey comment: We are implementing the IGMPv1 protocol as there will be no leave messages to deal with.
void IGMPProcessPacket(gpacket_t *in_pkt)
{
	ip_packet_t *ip_pkt = (ip_packet_t *)in_pkt->data.data;
	int iphdrlen = ip_pkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *)((uchar *)ip_pkt + iphdrlen);

	switch (igmphdr->type)
	{
		case IGMP_MEMBERSHIP_QUERY:
			verbose(2, "[IGMPProcessPacket]:: IGMP processing for membership query request");
			IGMPProcessMembershipQuery(in_pkt);
			break;

		case IGMP_MEMBERSHIP_REPORT:
			verbose(2, "[IGMPProcessPacket]:: IGMP processing for membership report request");
			IGMPProcessMembershipReport(in_pkt);
			break;
	}
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

// The router requests to see who is in the group
void IGMPProcessMembershipQuery(gpacket_t *in_pkt)
{
	ip_packet_t *ipkt = (ip_packet_t *)in_pkt->data.data;
	int iphdrlen = ipkt->ip_hdr_len * 4;
	igmphdr_t *igmphdr = (igmphdr_t *)((uchar *)ipkt + iphdrlen);
	uchar *icmppkt_b = (uchar *)igmphdr;

	ushort cksum;
	int ilen = ntohs(ipkt->ip_pkt_len) - iphdrlen;

	igmphdr->type = IGMP_HOST_MEMBERSHIP_QUERY;
	igmphdr->checksum = 0;
	if (IS_ODD(ilen))
	{
		// pad with a zero byte.. IP packet length remains the same 
		icmppkt_b[ilen] = 0x0;
		ilen++;
	}
	cksum = checksum(igmppkt_b, (ilen / 2));
	igmphdr->checksum = htons(cksum);
	
	// send the message back to the IP routine for further processing ..
	// set the messsage as REPLY_PACKET..
	// destination IP and size need not be set. they can be obtained from the original packet
	IPOutgoingPacket(in_pkt, NULL, 0, 0, IGMP_PROTOCOL);
}

// Report == Client Responce
void IGMPProcessMembershipReport(gpacket_t *in_pkt)
{
	ip_packet_t *ipkt = (ip_packet_t *)in_pkt->data.data;
	int iphdrlen = ipkt->ip_hdr_len *4;
	igmphdr_t *igmphdr = (igmphdr_t *)((uchar *)ipkt + iphdrlen);
	uchar *igmppkt_b = (uchar *)igmphdr;

	struct timeval tv;
	struct timezone tz;
	char tmpbuf[MAX_TMPBUF_LEN];
	double elapsed_time;

	if (igmphdr->type == IGMP_HOST_MEMBERSHIP_REPORT)
	{
		pstat.nreceived++;

		gettimeofday(&tv, &tz);
		elapsed_time = subTimeVal(&tv, (struct timeval *)(igmppkt_b + 8));
		printf("%d bytes from %s: igmp_seq=%d ttl=%d time=%6.3f ms\n", 
		       (ntohs(ipkt->ip_pkt_len) - iphdrlen - 8),
		       IP2Dot(tmpbuf, gNtohl((tmpbuf + 20), ipkt->ip_src)), 
		       ntohs(igmphdr->un.echo.sequence), ipkt->ip_ttl, elapsed_time);
	}
}

//function to receive the datagram with IP multicast "1110"

//function to check the TTL, compare it with the router threshold value; if acceptabe increment the TTL and call forwarding function