#ifndef TOPOR_H
#define TOPOR_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>

/* application error codes */
static const int ERR_PARAM      =  1;    /* invalid parameter(s) */
static const int ERR_REQ        =  2;    /* error parsing request */
static const int ERR_INTERNAL   =  3;    /* internal error */

/* max size of string with IPv4 address */
#define IPADDR_STR_SIZE 16

/* max size of string with TCP/UDP port */
#define PORT_STR_SIZE   6

static const int	ETHERNET_MTU	= 1500;
static const char	IPv4_ALL[]	= "0.0.0.0";
static const char	CONFIG_NAME[]	= "topor.cfg";

typedef u_short flag_t;
#if !defined( f_TRUE ) && !defined( f_FALSE )
    #define     f_TRUE  ((flag_t)1)
    #define     f_FALSE ((flag_t)0)
#else
    #error f_TRUE or f_FALSE already defined
#endif

#ifndef MAXPATHLEN
    #define MAXPATHLEN 1024
#endif

#endif
