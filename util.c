#include <errno.h>
#include <fcntl.h>
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
			error_log(errno, "setsid");
			break;
		}

		if( -1 == (rc = chdir("/")) ) {
			error_log(errno, "chdir");
			break;
		}

		(void) umask(0);

		if( !(options & DZ_STDIO_OPEN) ) {
			for( fh = 0; fh < 3; ++fh )
				if( -1 == (rc = close(fh)) ) {
					error_log(errno, "close");
					break;
				}
		}

		if( SIG_ERR == signal(SIGHUP, SIG_IGN) ) {
			error_log(errno, "signal");
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

/* write-lock on a file handle
 */
static int
wlock_file( int fd )
{
	struct flock  lck;

	lck.l_type      = F_WRLCK;
	lck.l_start     = 0;
	lck.l_whence    = SEEK_SET;
	lck.l_len       = 0;

	return fcntl( fd, F_SETLK, &lck );
}

int
make_pidfile( const char* fpath, pid_t pid )
{
	int fd = -1, rc = 0, n = -1;
	ssize_t nwr = -1;

#define LLONG_MAX_DIGITS 21
	char buf[ LLONG_MAX_DIGITS + 1 ];

	mode_t fmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

	errno = 0;
	do {
		fd = open( fpath, O_CREAT | O_WRONLY | O_NOCTTY, fmode );
		if( -1 == fd ) {
			error_log(errno, "make_pidfile - open");
			rc = EXIT_FAILURE;
			break;
		}

		rc = wlock_file( fd );
		if( 0 != rc ) {
			if( (EACCES == errno) || (EAGAIN == errno) ) {
				(void) fprintf( stderr, "File [%s] is locked "
						"(another instance of daemon must be running)\n",
						fpath );
				exit(EXIT_FAILURE);
			}

			error_log(errno, "wlock_file");
			break;
		}

		rc = ftruncate( fd, 0 );
		if( 0 != rc ) {
			error_log(errno, "make_pidfile - ftruncate");
			break;
		}

		n = snprintf( buf, sizeof(buf) - 1, "%d", pid );
		if( n < 0 ) {
			error_log(errno, "make_pidfile - snprintf");
			rc = EXIT_FAILURE;
			break;
		}

		nwr = write( fd, buf, n );
		if( (ssize_t)n != nwr ) {
			error_log(errno, "make_pidfile - write");
			rc = EXIT_FAILURE;
			break;
		}

	} while(0);

	if( (0 != rc) && (fd > 0) ) {
		(void)close( fd );
	}

	return rc;
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
		error_log(errno, "gmtime_r/localtime_r");
		return errno;
	}

	n = strftime( buf, *len, tmfmt_TZ, &src_tm );
	if( 0 == n ) {
		error_log(errno, "strftime" );
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
		error_log(errno, "fprintf/vfprintf" );
		return -1;
	}
	fputc('\n', logfp);
	fflush(logfp);

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

	if( logfp ) (void) wrlog( L_EMERGENCY, "%s", buf );
	else fprintf(stderr, "%s\n", buf);

	return;
}

const char *
get_peerip(int fd)
{
    struct stat st;
    struct sockaddr_in addr;
    socklen_t len = 0;
    int rc = 0;

    if( -1 == (rc = fstat( fd, &st )) ) {
        error_log( errno, "%s: fstat", __func__ );
        return "Error";
    }

    if( S_ISREG( st.st_mode ) ) {
        return "File";
    }
    else if( S_ISSOCK( st.st_mode ) ) {
        len = sizeof(addr);
        rc = getpeername( fd, (struct sockaddr*)&addr, &len );
        if( 0 == rc ) {
            return inet_ntoa(addr.sin_addr);
        }
        else {
            error_log( errno, "%s: getpeername", __func__ );
            return "Error";
        }
    } /* S_ISSOCK */

    return "Unknown";
}

const char *
format_time(int interval)
{
	static char s[16];
	int min = interval / 60;
	int sec = interval % 60;
	if(min == 0) {
		sprintf(s, "%ds", sec);
		return s;
	}

	if(min < 60) {
		sprintf(s, "%dm %02ds", min, sec);
		return s;
	}

	int h = min / 60;
	min %= 60;

	sprintf(s, "%dh %02dm %02ds", h, min, sec);
	return s;
}

const char *
format_traf(unsigned long bytes)
{
	static char s[16];

	if(bytes < 2 * 1048576L) {
		bytes /= 1024;
		sprintf(s, "%luKb", bytes);
		return s;
	}

	if(bytes < 2048 * 1048576L) {
		bytes /= 1048576;
		sprintf(s, "%luMb", bytes);
		return s;
	}

	bytes /= 1073741824;
	sprintf(s, "%luGb", bytes);
	return s;
}

