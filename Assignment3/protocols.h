/*
 * protocols.h (include file for protocol definitions)
 * AUTHOR: Muthucumaru Maheswaran
 * DATE: December 16, 2004
 * VERSION: 1.0
 * 
 */

#ifndef __PROTOCOLS_H__
#define __PROTOCOLS_H__

// From RFC 790-793 
#define ARP_PROTOCOL 	            0x0806
#define IP_PROTOCOL  		    0x0800
#define ETHERNET_PROTOCOL	    0x0001

// From IP RFC
#define ICMP_PROTOCOL 		    1
#define IGMP_PROTOCOL 		    2
#define TCP_PROTOCOL 		    6
#define UDP_PROTOCOL 		    17

#endif
