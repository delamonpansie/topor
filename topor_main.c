#define _GNU_SOURCE

#include  <netdb.h>

#include "topor.h"
#include "url_parser.h"

extern SLIST_HEAD(, channel) channels;
extern struct prog_opt topor_opt;
extern FILE *logfp;

void
channel_connect(struct channel *chan);

struct sockaddr_in *
sinsock(struct sockaddr_in *sin, struct prog_opt *topor_opt)
{
	memset(sin, 0, sizeof(struct sockaddr_in));
	sin->sin_family = AF_INET;
	sin->sin_port = htons(topor_opt->listen_port);
	if( 0 == topor_opt->listen_addr[0] ) {
		sin->sin_addr.s_addr = INADDR_ANY;
	}
	else {
		if( 0 == inet_aton(topor_opt->listen_addr, &sin->sin_addr) )
			return NULL;
	}
	return sin;
}

int
server_socket(struct sockaddr_in *sin)
{
	int fd;
	int one = 1;
	struct linger ling = { 0, 0 };
	int nonblock = 1;
	int sndbufsize = 1024*1024;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		error_log(errno , "Server socket create error");
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1 ||
			setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)) == -1 ||
			setsockopt(fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling)) == -1)
	{
		error_log(errno, "Server setsockopt error");
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbufsize, sizeof(sndbufsize)) == -1) {
		error_log(errno, "Sevrer socket sendbuf error");
		close(fd);
		return -1;
	}

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == -1) {
		error_log(errno, "Server tcp_nodelay set error");
		close(fd);
		return -1;
	}

	if (ioctl(fd, FIONBIO, &nonblock) < 0) {
		error_log(errno, "Server socket set nonblock error");
		close(fd);
		return -1;
	}


	if (bind(fd, (struct sockaddr *)sin, sizeof(*sin)) == -1) {
		error_log(errno, "Server socket bind error");
		close(fd);
		return -1;
	}


	if (listen(fd, 64) == -1) {
		error_log(errno, "Server socket listen error");
		close(fd);
		return -1;
	}

	return fd;
}

void
server_accept(ev_io *w, int revents)
{
	int fd = accept(w->fd, NULL, NULL);
	if (fd < 0) {
		wrlog(L_CRITICAL, "Client accept error: %s", strerror(errno));
		return;
	}

	int one = 1;
	if (ioctl(fd, FIONBIO, &one) < 0) {
		wrlog(L_CRITICAL, "Client nonblock ioctl error: %s", strerror(errno));
		close(fd);
		return;
	}

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == -1) {
		wrlog(L_CRITICAL, "Client tcp_nodelay setsockopt error: %s", strerror(errno));
		/* Do nothing, not a fatal error.  */
	}

	extern void client_read(ev_io *w, int revents);
	struct client *client = calloc(sizeof(*client), 1);
	ev_io_init(&client->io, (void *)client_read, fd, EV_READ);
	ev_io_start(&client->io);
}

void
client_close(struct client *c)
{
	close(c->io.fd);
	ev_io_stop(&c->io);
	if (c->link.le_prev != NULL)
		LIST_REMOVE(c, link);
	memset(c, 'a', sizeof(*c));
	free(c);
}

int
client_write(struct client *c, const char *buf, size_t len)
{
	for (;;) {
		ssize_t r = send(c->io.fd, buf, len, MSG_NOSIGNAL);
		if (r < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;

			wrlog(L_DEBUG, "Client send error: %s", strerror(errno)); // TODO add client address
			client_close(c);
			return -1;
		}
		return 0;
	}
}

int
client_parse_get(struct client *c)
{
	int ret = -1;
	char *url;
	if (sscanf(c->rbuf, "GET %as HTTP/1.1", &url) != 1)
		return -1;

	char *p = strrchr(url, '/');
	if (p)
		ret = atoi(p + 1);

	free(url);
	return ret;
}

const char *client_hdr = "HTTP/1.1 200 OK\r\nContent-Type:application/octet-stream\r\n\r\n";
void
client_read(ev_io *w, int revents)
{
	wrlog(L_ANNOY, "client_read fd %i", w->fd);
	struct client *c = (struct client *)w;
	int r = recv(w->fd, c->rbuf + c->rbytes, sizeof(c->rbuf) - c->rbytes, 0);
	if (r < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return;

		wrlog(L_ERROR, "Client receive error: %s", strerror(errno)); // TODO add client address
		client_close(c);
		return;
	}

	c->rbytes += r;
	char *lf = memmem(c->rbuf, c->rbytes, "\n", 1);
	if (!lf && c->rbytes < sizeof(c->rbuf))
		return;

	if (lf) {
		if (lf - 1 > c->rbuf && *(lf - 1) == '\r')
			lf--;
		*lf = 0;

		int cno = client_parse_get(c);
		if (cno >= 0) {
			if (client_write(c, client_hdr, strlen(client_hdr)) < 0)
				return;

			ev_io_stop(w);
			struct channel *chan;
			SLIST_FOREACH(chan, &channels, link) {
				if (chan->no == cno) {
					if(chan->state == CH_READ) {
						void *sbuf = malloc(chan->rbsize);
						if (sbuf) {
							rb_read(chan->rb, sbuf, chan->rbsize);
							int r = client_write(c, sbuf, chan->rbsize);
							free(sbuf);
							if (r < 0)
								return;
						}
						LIST_INSERT_HEAD(&chan->clients, c, link);
						return;
					}
					else if(chan->state == CH_STOP) {
						channel_connect(chan);
						LIST_INSERT_HEAD(&chan->clients, c, link);
						return;
					}
					else {
						LIST_INSERT_HEAD(&chan->clients, c, link);
						return;
					}
				}
			}
		}
	}

	wrlog(L_WARNING, "can't parse request");
	client_close(c);
}

int
http_sock(const char *url)
{
	struct sockaddr_in sin;
	int nonblock = 1;

	struct parsed_url *purl = parse_url(url);
	if (NULL == purl) {
		wrlog(L_ERROR, "bad url %s", url);
		return -1;
	}

	if( strcmp("http", purl->scheme)) {
		parsed_url_free(purl);
		wrlog(L_ERROR, "not http url %s", url);
		return -1;
	}

	int port = 80;
	if (NULL != purl->port)
		port = atoi(purl->port);

	if (port <= 0 || port >= 0xffff) {
		parsed_url_free(purl);
		wrlog(L_ERROR, "bad port %d in url %s", port, url);
		return -1;
	}

	struct  hostent *hp = gethostbyname(purl->host);
	if (NULL == hp) {
		parsed_url_free(purl);
		wrlog(L_ERROR, "cant resolve host %s", purl->host);
		return -1;
	}


	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	bcopy ( hp->h_addr, &(sin.sin_addr.s_addr), hp->h_length);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		wrlog(L_ERROR, "Create channel socket error: %s", strerror(errno));
		goto err;
	}

	if (ioctl(fd, FIONBIO, &nonblock) < 0) {
		wrlog(L_ERROR, "Channel socket set nonblock error: %s", strerror(errno));
		close(fd);
		goto err;
	}

	int r = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
	if (r < 0 && errno != EINPROGRESS) {
		wrlog(L_ERROR, "Channel socket connect error: %s", strerror(errno));
		goto err;
	}

	parsed_url_free(purl);
	return fd;
err:
	parsed_url_free(purl);
	close(fd);
	return -1;
}

void
channel_close(struct channel *chan)
{
	ev_io_stop(&chan->io);
	rb_free(chan->rb);
	if (chan->realurl) free(chan->realurl);
	chan->realurl = NULL;
	chan->rb = NULL;
	chan->state = CH_STOP;
	wrlog(L_INFO, "close channel %d", chan->no);
}

void
channel_cb(ev_io *w, int revents)
{
	char buf[1024] = {0};
	struct channel *chan = (struct channel *)w;
	struct client *client, *tmp;

	if (revents & EV_READ) {
		/* get pointer to ring buffer */
		char *buf = rb_writepointer(chan->rb);
		/* get buffer size available in ring buffer */
		size_t buflen = rb_writesize(chan->rb, 16384);

		ssize_t r = recv(w->fd, buf, buflen, 0);
		wrlog(L_ANNOY, "channel %d read %zi bytes", chan->no, r);

		if (r < 0) {
			wrlog(L_ERROR, "Channel receive error: %s", strerror(errno));
			abort(); // FIXME
		}

		if (0 == r) {
			/* eof */
			ev_io_stop(w);
			close(w->fd);
			LIST_FOREACH_SAFE(client, &chan->clients, link, tmp)
				client_close(client);
			channel_close(chan);
			return;
		}
		chan->lastdata = time(NULL);

		/* shift pointer in ring buffer by r */
		rb_write(chan->rb, NULL, r);

		if(chan->state == CH_SENDREQ) {
			int err;
			socklen_t len = sizeof(err);
			getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &err, &len);
			if (err) {
				// error happen
				wrlog(L_ERROR, "Channel connect error: %s", strerror(errno));
				ev_io_stop(w);
				close(w->fd);
				LIST_FOREACH_SAFE(client, &chan->clients, link, tmp)
					client_close(client);
				channel_close(chan);
				return;
			} else {
				chan->state = CH_READHEADER;
			}
		}
		if(chan->state == CH_READHEADER) {
			char *data = rb_head(chan->rb);
			char *lf = memmem(data, rb_can_read(chan->rb), "\r\n\r\n", 4);
			if (!lf) return;
			lf[4] = '\0';

			char *location = strstr(data, "Location: ");
			if (location) {
				char *crlf = strstr(location, "\r\n");
				if (!crlf)
					goto err;
				*crlf = 0;

				wrlog(L_INFO, "Redirect: %s", location);

				char *red_addr = NULL;
				if (sscanf(location, "Location: %as", &red_addr) != 1)
					goto err;

				ev_io_stop(&chan->io);
				close(w->fd);
				chan->state = CH_STOP;
				rb_reset(chan->rb);
				int fd = http_sock(red_addr);
				if (fd < 0) {
					return;
				}
				
				if (chan->realurl) free(chan->realurl);
				chan->realurl = strdup(red_addr);
				chan->state = CH_CONNECT;
				ev_io_init(&chan->io, channel_cb, fd, EV_READ | EV_WRITE);
				ev_io_start(&chan->io);
				free(red_addr);
				return;
err:
				ev_io_stop(&chan->io);
				close(w->fd);
				chan->state = CH_STOP;
				return;
			}
			rb_reset(chan->rb);
			chan->state = CH_READ;
			chan->lastdata = chan->lastclient = time(NULL);
			wrlog(L_INFO,"connect channel %d", chan->no);
		}
		if( ! LIST_EMPTY(&chan->clients) ) {
			chan->lastclient = time(NULL);
			LIST_FOREACH_SAFE(client, &chan->clients, link, tmp)
				client_write(client, buf, r);
		}
	}
	else if (revents & EV_WRITE) {
		if(chan->state == CH_CONNECT) {
			struct parsed_url *purl;
			if (chan->realurl) 
		       		purl = parse_url(chan->realurl);
			else
		       		purl = parse_url(chan->url);
			snprintf(buf, sizeof(buf) - 1, "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", purl->path, purl->host);
			if (send(w->fd, buf, strlen(buf), MSG_NOSIGNAL) != strlen(buf)) {
				wrlog(L_ERROR, "Channel send request error: %s", strerror(errno));
				return;
			}
			ev_io_stop(&chan->io);
			ev_io_init(&chan->io, channel_cb, w->fd, EV_READ);
			ev_io_start(&chan->io);
			chan->state = CH_SENDREQ;
			parsed_url_free(purl);
		}
	}
}

void
channel_connect(struct channel *chan)
{
	int fd = http_sock(chan->url);
	if (fd < 0)
		return;
	chan->rb = rb_new(chan->rbsize);	
	chan->state = CH_CONNECT;

	ev_io_init(&chan->io, channel_cb, fd, EV_READ | EV_WRITE);
	ev_io_start(&chan->io);

	return;
}

struct channel *
channel_init(int cno, const char *url, size_t bufsize)
{
	struct channel *chan = calloc(sizeof(*chan), 1);
	chan->no = cno;
	chan->url = strdup(url);
	chan->realurl = NULL;
	chan->rbsize = 512*1024;
	if(bufsize) chan->rbsize = bufsize * 1024;
	chan->state = CH_STOP;
	SLIST_INSERT_HEAD(&channels, chan, link);
	return chan;
}

void
timer_cb(struct ev_timer *w, int revents)
{
	time_t t = time(NULL);
	struct channel *chan;
	SLIST_FOREACH(chan, &channels, link) {
		if (chan->state == CH_READ) {
			if (t - chan->lastdata > 10 || t - chan->lastclient > 20) {
				close(chan->io.fd);
				channel_close(chan);
			}
		}
	}
}

int main(int argc, char* const argv[])
{
	char buf[1025];
	int rc;
	struct sockaddr_in sin, *ssin;

	ev_default_loop(ev_recommended_backends() | EVFLAG_SIGNALFD);
	char *evb = NULL;
	switch(ev_backend()) {
		case    EVBACKEND_SELECT:   evb = "select"; break;
		case    EVBACKEND_POLL:     evb = "poll"; break;
		case    EVBACKEND_EPOLL:    evb = "epoll"; break;
		case    EVBACKEND_KQUEUE:   evb = "kqueue"; break;
		case    EVBACKEND_DEVPOLL:  evb = "dev/poll"; break;
		case    EVBACKEND_PORT:     evb = "port"; break;
		default:                    evb = "unknown";
	}
	printf("ev_loop initialized using '%s' backend, libev version is %d.%d\n",
			evb, ev_version_major(), ev_version_minor());

	rc = get_opt(argc, argv, &topor_opt);
	if (rc) {
		free_opt( &topor_opt );
		return rc;
	}

	ssin = sinsock(&sin, &topor_opt);
	if(NULL == ssin) {
		error_log(errno, "Bad listen");
		abort();
	}
	int fd = server_socket(ssin);
	if (fd < 0) {
		exit(1);
	}

	const char *config = CONFIG_NAME;
	if(topor_opt.configfile) config = topor_opt.configfile;
	FILE *cf = fopen(config, "r");
	if(cf) {
		int r, i=0, cno=0;
		size_t bufsize;
		char *churl;
		while(!feof(cf)) {
			fgets(buf, sizeof(buf)-1, cf);
			++i;
			bufsize = 0;
			r = parseline(buf, &cno, &churl, &bufsize);
			if(0 == r) continue;
			if(1 == r) {
				fprintf(stderr,"No channel url on line %d\n",i);
				continue;
			}
			if(channel_init(cno, churl, bufsize) == NULL) abort(); //FIXME
		}
		fclose(cf);
	}
	else {
		fprintf(stderr,"Can't read file '%s'! %s\n", config, strerror(errno));
	}
	
	if(SLIST_EMPTY(&channels)) {
		fprintf(stderr,"No channels to relay!\n");
		exit(EXIT_FAILURE);
	}

	if (topor_opt.logfile) {
		logfp = fopen(topor_opt.logfile, "a");
		if (!logfp) {
			fprintf(stderr,"Can't open log '%s'! %s\n", topor_opt.logfile, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (! topor_opt.is_foreground) {
		if(NULL == logfp) {
			fprintf(stderr,"Must specify log file when run as daemon!\n");
			exit(EXIT_FAILURE);
		}
		if (0 != (rc = daemonize(0))) {
			fprintf(stderr,"Can't run as daemon!\n");
			exit(EXIT_FAILURE);
		}
	}
	wrlog(L_EMERGENCY, "Topor start");

	if( topor_opt.pidfile && 0 != (rc = make_pidfile( topor_opt.pidfile, getpid())) ) {
		fprintf(stderr, "Can't create pidfile %s!\n", topor_opt.pidfile);
		exit(EXIT_FAILURE);
	}

	ev_io io;
	ev_io_init(&io, server_accept, fd, EV_READ);
	ev_io_start(&io);

	ev_timer sectimer;
	ev_timer_init(&sectimer, timer_cb, 1., 1.);
	ev_timer_again(&sectimer);
	ev_run(0);

	wrlog(L_EMERGENCY, "Topor stopped");
	if (topor_opt.pidfile) {
		if( -1 == unlink(topor_opt.pidfile) ) {
			error_log(errno, "unlink [%s]", topor_opt.pidfile );
		}
	}

	free_opt(&topor_opt);
	if (logfp)
		fclose(logfp);
	return 0;
}
