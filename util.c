#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "topor.h"

extern struct prog_opt topor_opt;
extern FILE *logfp;

/* make current process run as a daemon
 */
int
daemonize(int options)
{
	pid_t pid;
	int rc = 0, fh = -1;

	if( (pid = fork()) < 0 ) {
		perror("fork");
		return -1;
	}
	else if( 0 != pid ) {
		exit(0);
	}

	do {
		if( -1 == (rc = setsid()) ) {
			perror("setsid");
			break;
		}

		if( -1 == (rc = chdir("/")) ) {
			perror("chdir");
			break;
		}

		(void) umask(0);

		if( !(options & DZ_STDIO_OPEN) ) {
			for( fh = 0; fh < 3; ++fh )
				if( -1 == (rc = close(fh)) ) {
					perror("close");
					break;
				}
		}

		if( SIG_ERR == signal(SIGHUP, SIG_IGN) ) {
			perror("signal");
			rc = 2;
			break;
		}

	} while(0);

	if( 0 != rc ) return rc;

	/* child exits to avoid session leader's re-acquiring
	 * control terminal */
	if( (pid = fork()) < 0 ) {
		perror("fork");
		return -1;
	}
	else if( 0 != pid )
		exit(0);

	return 0;
}

/* create timestamp string in YYYY-mm-dd HH24:MI:SS from struct timeval
 */
int
mk_tstamp( const struct timeval* tv, char* buf, size_t* len,
             int32_t flags )
{
	const char tmfmt_TZ[] = "%Y-%m-%d %H:%M:%S";

	int n = 0;
	struct tm src_tm, *p_tm;
	time_t clock;


	clock = tv->tv_sec;
	p_tm = (flags & TVSTAMP_GMT)
		? gmtime_r( &clock, &src_tm )
		: localtime_r( &clock, &src_tm );
	if( NULL == p_tm ) {
		perror("gmtime_r/localtime_r");
		return errno;
	}

	n = strftime( buf, *len, tmfmt_TZ, &src_tm );
	if( 0 == n ) {
		perror( "strftime" );
		return errno;
	}

	*len = (size_t)n;
	return 0;
}


int
wrlog(loglevel level, const char *format, ...)
{
	va_list ap;
	char tstamp[ 24 ] = {'\0'};
	size_t ts_len = sizeof(tstamp) - 1;
	struct timeval tv_now;
	int rc = 0, n = 0, total = 0;

	if (level > topor_opt.loglevel)
		return rc;

	if (!logfp) {
		va_start( ap, format );
		n = vfprintf( stderr, format, ap );
		va_end( ap );
		fputc('\n', stderr);
		return n;
	}

	(void)gettimeofday( &tv_now, NULL );
	errno = 0;
	do {
		rc = mk_tstamp( &tv_now, tstamp, &ts_len, 0 );
		if( 0 != rc )
			break;

		n = fprintf( logfp, "%s ", tstamp );
		if( n <= 0 )
			break;
		total += n;

		va_start( ap, format );
		n = vfprintf( logfp, format, ap );
		va_end( ap );

		if( n <= 0 ) break;
		total += n;

	} while(0);

	if( n <= 0 ) {
		perror( "fprintf/vfprintf" );
		return -1;
	}
	fputc('\n', logfp);

	return (0 != rc) ? -1 : total;
}

/* error output to custom log
 * and syslog
 */
void
error_log( int err, const char* format, ... )
{
	char buf[ 256 ] = { '\0' };
	va_list ap;
	int n = 0;

	va_start( ap, format );
	n = vsnprintf( buf, sizeof(buf) - 1, format, ap );
	va_end( ap );

	if( n <= 0 || n >= ((int)sizeof(buf) - 1) ) return;

	snprintf( buf + n, sizeof(buf) - n - 1, ": %s",
			strerror(err) );

	syslog( LOG_ERR | LOG_LOCAL0, "%s", buf );
	if( logfp ) (void) wrlog( L_EMERGENCY, "%s", buf );
	else fprintf(stderr, "%s\n", buf);

	return;
}

