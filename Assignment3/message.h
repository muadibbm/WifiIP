/*
 * message.h (header for the messaging layer that goes with the modules)
 * AUTHOR: Muthucumaru Maheswaran
 * VERSION: Beta
 * DATE: December 19, 2004
 *
 */

#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <sys/types.h>
#include "grouter.h"


#define MAX_IPREVLENGTH_ICMP            50       // maximum previous header sent back


#define MAX_MESSAGE_SIZE                sizeof(gpacket_t)



// this is just an ethernet frame with
// a maximum payload definition.
// (TODO: revise it to use standard structures)
typedef struct _pkt_data_t
{
	struct
	{
		uchar dst[6];                // destination host's MAC address (filled by gnet)
		uchar src[6];                // source host's MAC address (filled by gnet)
		ushort prot;                // protocol field
	} header;
	uchar data[DEFAULT_MTU];             // payload (limited to maximum MTU)
} pkt_data_t;


// frame wrapping every packet... GINI specific (GINI metadata)
typedef struct _pkt_frame_t
{
	int src_interface;               // incoming interface number; filled in by gnet?
	uchar src_ip_addr[4];            // source IP address; required for ARP, IP, gnet
	uchar src_hw_addr[6];            // source MAC address; required for ARP, filled by gnet
	int dst_interface;               // outgoing interface, required by gnet; filled in by IP, ARP
	uchar nxth_ip_addr[4];           // destination interface IP address; required by ARP, filled IP
	int arp_valid;
	int arp_bcast;
} pkt_frame_t;


typedef struct _gpacket_t 
{
	pkt_frame_t frame;
	pkt_data_t data;
} gpacket_t;


gpacket_t *duplicatePacket(gpacket_t *inpkt);
void printSepLine(char *start, char *end, int count, char sep);
void printGPktFrame(gpacket_t *msg, char *routine);
void printGPacket(gpacket_t *msg, int level, char *routine);
void printGPktPayload(gpacket_t *msg, int level);
int printEthernetHeader(gpacket_t *msg);

int printIPPacket(gpacket_t *msg);
void printARPPacket(gpacket_t *msg);
void printICMPPacket(gpacket_t *msg);
void printUDPPacket(gpacket_t *msg);
void printTCPPacket(gpacket_t *msg);

#endif
