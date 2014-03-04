#ifndef TOPOR_OPT_H
#define TOPOR_OPT_H

#include "topor.h"
#include "util.h"

/* max size of string with IPv4 address */
#define IPADDR_STR_SIZE 16

typedef u_short flag_t;
#if !defined( f_TRUE ) && !defined( f_FALSE )
    #define     f_TRUE  ((flag_t)1)
    #define     f_FALSE ((flag_t)0)
#else
    #error f_TRUE or f_FALSE already defined
#endif


static const ssize_t SOCKBUF_LEN = (1024 * 1024);

/* options */
struct prog_opt {
	flag_t		is_foreground;
	char		listen_addr[IPADDR_STR_SIZE];
	int		listen_port;
	char*		logfile;
	char*		configfile;
	char*		pidfile;
	loglevel	loglevel;
};

#ifdef __cplusplus
    extern "C" {
#endif

/* populate options with default/initial values */
int
init_opt( struct prog_opt* opt );


/* release resources allocated for udpxy options */
void
free_opt( struct prog_opt* opt );

void
usage( const char* app, FILE* fp );

int
get_opt(int argc, char* const argv[], struct prog_opt *topor_opt);

#ifdef __cplusplus
} /* extern "C" */
#endif


#endif
