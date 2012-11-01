
#include "igmp.h"


struct ip_mreq
{
	struct in_addr imr_multiaddr;   /* IP multicast address of group */
	struct in_addr imr_interface;   /* local IP address of interface */
};

//function to receive the datagram with IP multicast "1110"

//function to check the TTL, compare it with the router threshold value; if acceptabe increment the TTL and call forwarding function

//forwarding function checks which groups the multicast will be forwarded to