
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
#define IP_MAX_MEMBERSHIPS 4
#define IGMP_V1_Router_timeout 1 //TODO : what is threshold for TTL at each router ?

struct ip_mreq
{
	struct in_addr imr_multiaddr;   /* IP multicast address of group */
	struct in_addr imr_interface;   /* local IP address of interface */
};

/* TODO : prototype methods from igmp.c should be inserted here */