#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "topor.h"

#define STATBUFSIZE 16384
extern SLIST_HEAD(, channel) channels;

static const char HTML_PAGE_HEADER[] =
        "HTTP/1.0 200 OK\n"
        "Content-type: text/plain\r\n\r\n";


void 
write_stat(int fd)
{
	struct printbuf *pb = prbuf_create(STATBUFSIZE);
	if (NULL == pb)
		return;
	struct channel *chan;
	time_t curtime = time(NULL);
	struct client *client, *tmp;
	int clinum;
	char *url;

	write(fd, HTML_PAGE_HEADER, sizeof(HTML_PAGE_HEADER)-1);	

	SLIST_FOREACH(chan, &channels, link) {
		clinum = 0;
		if( ! LIST_EMPTY(&chan->clients) ) {
			LIST_FOREACH_SAFE(client, &chan->clients, link, tmp) {
				clinum++;
			}
		}
		url = chan->url;
		if (chan->realurl)
			url = chan->realurl;
		if (chan->state == CH_READ) {
			prbuf_printf(pb,
				"Channel:%-3d  State:active   Clients:%-3d Run:%-8s  Load:%-8s  Source:%s\n",
				chan->no, clinum, format_time(curtime - chan->starttime), format_traf(chan->bytes), url
				);
		}
		else {
			prbuf_printf(pb,
				"Channel:%-3d  State:inactive Clients:%-3d Run:%-8s  Load:%-8s  Source:\n",
				chan->no, clinum, "0", format_traf(chan->bytes)
				);
		}
		if (prbuf_len(pb) > STATBUFSIZE - 1024) {
			write(fd, pb->buff, prbuf_len(pb));
			prbuf_reset(pb);
		}
	}
	if (prbuf_len(pb) > 0)
		write(fd, pb->buff, prbuf_len(pb));
	prbuf_close(pb);
}
