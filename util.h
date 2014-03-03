#ifndef UTIL_H
#define UTIL_H

#include <sys/types.h>
#include <stdio.h>

typedef enum {
	L_EMERGENCY = 0,
	L_ALERT = 1,
	L_CRITICAL = 2,
	L_ERROR = 3,
	L_WARNING = 4,
	L_NOTICE = 5,
	L_INFO = 6,
	L_DEBUG = 7,
	L_ANNOY = 8
} loglevel;


#ifdef __cplusplus
extern "C" {
#endif

int daemonize(int options);
int wrlog( loglevel level, const char *format, ...);
void error_log( int err, const char* format, ... );

#ifdef __cplusplus
}
#endif

#endif /* UTIL_H */
