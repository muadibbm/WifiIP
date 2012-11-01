
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

/* TODO : any global variables and structs go here */

/* TODO : prototype methods from igmp.c should be inserted here */

struct ip_mreq
{
	struct in_addr imr_multiaddr;   /* IP multicast address of group */
	struct in_addr imr_interface;   /* local IP address of interface */
};