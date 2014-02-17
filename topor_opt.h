#ifndef STRM_OPT_H
#define STRM_OPT_H

#include "topor.h"


static const ssize_t SOCKBUF_LEN = (1024 * 1024);


/* options */
struct prog_opt {
	flag_t		is_foreground;
    flag_t		is_verbose;
    char		listen_addr[IPADDR_STR_SIZE];
    int			listen_port;
    char*		logfile;
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
