#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "topor.h"
extern SLIST_HEAD(, channel) channels;

static const char HTML_PAGE_HEADER[] =
        "HTTP/1.0 200 OK\n"
        "Content-type: text/plain\r\n\r\n";

void 
write_stat(int fd)
{
	char buf[1024];
	struct channel *chan;
	time_t curtime = time(NULL);
	int len;

	write(fd, HTML_PAGE_HEADER, sizeof(HTML_PAGE_HEADER)-1);	

	SLIST_FOREACH(chan, &channels, link) {
		if(chan->state == CH_READ) {
			len = snprintf(buf, sizeof(buf),
				"Channel:%-3d  State:active   Run:%-8s  Load:%-8s  Source:%s\n",
				chan->no, format_time(curtime - chan->starttime), format_traf(chan->bytes), chan->realurl
				);
		}
		else {
			len = snprintf(buf, sizeof(buf),
				"Channel:%-3d  State:inactive Run:%-8s  Load:%-8s  Source:\n",
				chan->no, "0", format_traf(chan->bytes)
				);
		}

		write(fd, buf, len);
	}
}
