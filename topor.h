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

#include "topor_ev.h"
#include "queue.h"
#include "ringbuffer.h"
#include "topor_opt.h"
#include "topor_config.h"
#include "util.h"

/* application error codes */
static const int ERR_PARAM      =  1;    /* invalid parameter(s) */
static const int ERR_REQ        =  2;    /* error parsing request */
static const int ERR_INTERNAL   =  3;    /* internal error */

/* max size of string with TCP/UDP port */
#define PORT_STR_SIZE   6

static const char	IPv4_ALL[]	= "0.0.0.0";
static const char	CONFIG_NAME[]	= "topor.cfg";

#ifndef MAXPATHLEN
    #define MAXPATHLEN 1024
#endif

#define DZ_STDIO_OPEN  1   /* do not close STDIN, STDOUT, STDERR */
#define TVSTAMP_GMT  1

/* channel stream states */
typedef enum {
	CH_STOP,
	CH_CONNECT,
	CH_SENDREQ,
	CH_READHEADER,
	CH_READ
} chanstate;

struct channel {
	ev_io io;
	int no;
	char *url;
	char *realurl;
	chanstate state;
	struct ringbuf *rb;
	size_t rbsize;
	time_t starttime;
	time_t lastclient;
	time_t lastdata;
	size_t bytes;
	int errors;
	LIST_HEAD(, client) clients;
	SLIST_ENTRY(channel) link;
};

struct client {
	ev_io io;
	char addr[IPADDR_STR_SIZE];
	struct channel *channel;
	char rbuf[256];
	int rbytes, rcapa;
	time_t starttime;
	size_t bytes;
	int errors;
	LIST_ENTRY(client) link;
};

#endif
