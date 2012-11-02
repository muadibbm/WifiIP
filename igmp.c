
#include "igmp.h"


/* IPv4 */
// Create a socket for receiving IGMP messages
int mrouter_s4;
mrouter_s4 = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);

/* IPv4 */
int v = 1;        /* 1 to enable, or 0 to disable */
setsockopt(mrouter_s4, IPPROTO_IP, MRT_INIT, (void *)&v, sizeof(v));


//function to receive the datagram with IP multicast "1110"

//function to check the TTL, compare it with the router threshold value; if acceptabe increment the TTL and call forwarding function

//forwarding function checks which groups the multicast will be forwarded to