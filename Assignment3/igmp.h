
#ifndef __IGMP_H_
#define __IGMP_H_

#include <sys/types.h>
#include "protocol.h"
#include "ip.h"
#include "message.h"
#include "grouter.h"

#include <slack/err.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <endian.h>

/* Global variables, structs and constants */
#define IP_MAX_MEMBERSHIPS 		4
#define IGMP_V1_Router_timeout 	1 //TODO : what is threshold for TTL at each router ?

// Andrey comment: I don't know if the below info has any relevance to the IGMP protocol.
// Andrey comment: So, I will try to find some stuff online for those constants.

#define IGMP_HOST_MEMBERSHIP_QUERY   17
#define IGMP_HOST_MEMBERSHIP_REPORT  18

/* Codes for UNREACH. */
#define IGMP_NET_UNREACH        0       /* Network Unreachable          */
#define IGMP_HOST_UNREACH       1       /* Host Unreachable             */
#define IGMP_PROT_UNREACH       2       /* Protocol Unreachable         */
#define IGMP_PORT_UNREACH       3       /* Port Unreachable             */
#define IGMP_FRAG_NEEDED        4       /* Fragmentation Needed/DF set  */
#define IGMP_SR_FAILED          5       /* Source Route failed          */
#define IGMP_NET_UNKNOWN        6
#define IGMP_HOST_UNKNOWN       7

/* Codes for REDIRECT. */
#define IGMP_REDIR_NET          0       /* Redirect Net                 */
#define IGMP_REDIR_HOST         1       /* Redirect Host                */
#define IGMP_REDIR_NETTOS       2       /* Redirect Net for TOS         */
#define IGMP_REDIR_HOSTTOS      3       /* Redirect Host for TOS        */

/* Codes for TIME_EXCEEDED. */
#define IGMP_TTL_EXPIRED        11      /* Time Exceeded                */
#define IGMP_EXC_FRAGTIME       1       /* Fragment Reass time exceeded */

// IGMP structure definitions go here...
typedef struct _igmphdr_t
{
	uchar type;                  /* message type */
	uchar code;                  /* type sub-code */
	uchar group;
	ushort checksum;
	union _un
	{
		struct
		{
			ushort id;
			ushort sequence;
		} echo;                  /* echo datagram */
		
		uint   gateway;        	 /* gateway address */
		
		struct
		{
			ushort __unused;
			ushort mtu;
		} frag;                  /* path mtu discovery */
	} un;
} igmphdr_t;

/* TODO : prototype methods from igmp.c should be inserted here */
void IGMPProcessPacket(gpacket_t *in_pkt);
void IGMPSendMReq(uchar *ipaddr, int pkt_size, int retries);
void IGMPSendReqPacket(uchar *dst_ip, int size, int seq);
void IGMPProcessTTLExpired(gpacket_t *in_pkt);
void IGMPProcessEchoRequest(gpacket_t *in_pkt);
void IGMPProcessEchoReply(gpacket_t *in_pkt);
#endif