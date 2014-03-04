#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "topor.h"
#include "topor_opt.h"

/* convert input parameter into an IPv4-address string */
int
get_ipaddr( const char* s, char* buf, size_t len )
{
    struct sockaddr_in saddr;
    int rc = 0;

    assert( s && buf && len );

    if( 1 == inet_aton(s, &(saddr.sin_addr)) ) {
        (void) strncpy( buf, s, len );
    }

    buf[ len - 1 ] = 0;
    return rc;
}

/* populate options with default/initial values */
int
init_opt( struct prog_opt* so )
{
    int rc = 0;
    assert( so );
	so->is_foreground = 0;
	so->listen_addr[0] = 0;
	so->listen_port = 8888;
	so->logfile = so->configfile = so->pidfile = NULL;
	so->loglevel = L_ERROR;
    return rc;
}

/* release resources allocated for strmproxy options */
void
free_opt( struct prog_opt* so )
{
    assert( so );
    if( so->logfile ) 
        free(so->logfile);
    if( so->configfile ) 
        free(so->configfile);
    if( so->pidfile ) 
        free(so->pidfile);
}

void
usage( const char* app, FILE* fp )
{
    (void) fprintf (fp, "usage: %s [-f] [-v level] [-b listenaddr] [-p port] [-P pidfile]"
            "[-l logfile] [-c configfile]\n"
            , app );
    (void) fprintf(fp,
            "\t-v : set verbosity level 0-5 [default = 0]\n"
            "\t-f : run foreground, do NOT run as a daemon\n"
            "\t-b : (IPv4) address to listen on [default = %s]\n"
            "\t-p : port to listen on\n"
            "\t-l : log file name\n"
            "\t-c : config file name\n"
            "\t-P : pid file name\n"
            ,IPv4_ALL);
    (void) fprintf( fp, "Examples:\n"
            "  %s -p 4022 \n"
            "\tlisten for HTTP requests on port 4022, all network interfaces\n"
            "  %s -b 192.168.1.1 -p 4022\n"
            "\tlisten for HTTP requests on IP 192.168.1.1, port 4022;\n",
            app, app);
    return;
}

int
get_opt(int argc, char* const argv[], struct prog_opt *topor_opt)
{
	int rc = 0, ch = 0;
	static const char OPTMASK[] = "fv:b:l:p:c:P:";

	rc = init_opt( topor_opt );
	while( (0 == rc) && (-1 != (ch = getopt(argc, argv, OPTMASK))) ) {
		switch( ch ) {
			case 'v': if (optarg) {
				  	int lvl = atoi( optarg );
					switch (lvl) {
						case 0: topor_opt->loglevel = L_ERROR;
							break;
						case 1: topor_opt->loglevel = L_WARNING;
							break;
						case 2: topor_opt->loglevel = L_NOTICE;
							break;
						case 3: topor_opt->loglevel = L_INFO;
							break;
						case 4: topor_opt->loglevel = L_DEBUG;
							break;
						case 5: topor_opt->loglevel = L_ANNOY;
							break;
						default: fprintf(stderr, "Bad verbosity level %s\n", optarg);
							 rc = ERR_PARAM;
					}
					if (rc) {
						free_opt( topor_opt );
						return rc;
					}
				  }
				  else {
					topor_opt->loglevel = L_WARNING;
				  }
				  break;
			case 'f': topor_opt->is_foreground = f_TRUE;
				  break;
			case 'b':
				  rc = get_ipaddr( optarg, topor_opt->listen_addr, sizeof(topor_opt->listen_addr) );
				  if( 0 != rc ) {
					  (void) fprintf( stderr, "Invalid address: [%s]\n",
							  optarg );
					  rc = ERR_PARAM;
				  }
				  break;

			case 'p':
				  topor_opt->listen_port = atoi( optarg );
				  if( topor_opt->listen_port <= 0 || topor_opt->listen_port >= 65536) {
					  (void) fprintf( stderr, "Invalid port number: [%d]\n",
							  topor_opt->listen_port );
					  rc = ERR_PARAM;
				  }
				  break;

			case 'l':
				  topor_opt->logfile = strdup(optarg);
				  break;

			case 'c':
				  topor_opt->configfile = strdup(optarg);
				  break;

			case 'P':
				  topor_opt->pidfile = strdup(optarg);
				  break;

			case ':':
				  (void) fprintf( stderr,
						  "Option [-%c] requires an argument\n",
						  optopt );
				  rc = ERR_PARAM;
				  break;
			case '?':
				  (void) fprintf( stderr,
						  "Unrecognized option: [-%c]\n", optopt );
				  usage( argv[0], stderr );
				  rc = ERR_PARAM;
				  break;

			default:
				  usage( argv[0], stderr );
				  rc = ERR_PARAM;
				  break;
		}
	} /* while getopt */

	if (rc) {
		free_opt( topor_opt );
		return rc;
	}
	return rc;
}

/* __EOF__ */
