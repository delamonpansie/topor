#define _GNU_SOURCE

#include "topor.h"
#include "topor_opt.h"
#include "topor_ev.h"
#include "queue.h"

SLIST_HEAD(, channel) channels;
struct prog_opt topor_opt;

struct channel {
	ev_io io;
	LIST_HEAD(, client) clients;
	SLIST_ENTRY(channel) link;
	int no;
	char *addr, *url;
};

struct client {
	ev_io io;
	struct channel *channel;
	LIST_ENTRY(client) link;
	char rbuf[256];
	int rbytes, rcapa;
};

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
atosin(const char *orig, struct sockaddr_in *addr)
{
	int port;
	char *str = strdupa(orig);
	char *colon = strchr(str, ':');
	addr->sin_family = AF_UNSPEC;

	if (colon != NULL) {
		*colon = 0;
		port = atoi(colon + 1); /* port is next after ':' */
	} else {
		port = atoi(str);
	}

	if (port <= 0 || port >= 0xffff) {
		fprintf(stderr, "bad port in addr: %s", orig);
		return -1;
	}

	memset(addr, 0, sizeof(*addr));

	if (colon == NULL || colon == str) { /* "33013" ":33013" */
		addr->sin_addr.s_addr = INADDR_ANY;
	} else {
		if (inet_aton(str, &addr->sin_addr) == 0) {
			perror("inet_aton");
			return -1;
		}
	}

	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);
	return 0;
}

int
server_socket(struct sockaddr_in *sin)
{
	int fd;
	int one = 1;
	struct linger ling = { 0, 0 };
	int nonblock = 1;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1 ||
	    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)) == -1 ||
	    setsockopt(fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling)) == -1)
	{
		perror("setsockopt");
		close(fd);
		return -1;
	}

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == -1) {
		perror("setsockopt");
		close(fd);
		return -1;
	}

	if (ioctl(fd, FIONBIO, &nonblock) < 0) {
		perror("ioctl");
		close(fd);
		return -1;
	}


	if (bind(fd, (struct sockaddr *)sin, sizeof(*sin)) == -1) {
		perror("bind");
		close(fd);
		return -1;
	}


	if (listen(fd, 64) == -1) {
		perror("listen");
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
		perror("accept");
		return;
	}

	int one = 1;
	if (ioctl(fd, FIONBIO, &one) < 0) {
		perror("ioctl");
		close(fd);
		return;
	}

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == -1) {
		perror("setsockopt");
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
			if (errno == EINTR)
				continue;

			perror("send");
			client_close(c);
			return -1;
		}
		printf("client write %zi bytes\n", r);
		return 0;
	}
}

int
client_parse_get(struct client *c)
{
	int ret = -1;
	char *url;
	if (sscanf(c->rbuf, "GET %as HTTP/1.1", &url) != 1) {
		return -1;
	}

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
	printf("client_read fd %i\n", w->fd);
	struct client *c = (struct client *)w;
	int r = recv(w->fd, c->rbuf + c->rbytes, sizeof(c->rbuf) - c->rbytes, 0);
	if (r < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return;

		perror("recv");
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
					LIST_INSERT_HEAD(&chan->clients, c, link);
					return;
				}
			}
		}
	}

	fprintf(stderr, "can't parse request\n");
	client_close(c);
}

void
channel_read(ev_io *w, int revents)
{
	struct channel *chan = (struct channel *)w;
	static char buf[16384];

	ssize_t r = recv(w->fd, buf, sizeof(buf), 0);
	if (r < 0) {
		perror("recv");
		abort(); // FIXME
	}

	printf("channel read %zi bytes\n", r);
	struct client *client, *tmp;
	LIST_FOREACH_SAFE(client, &chan->clients, link, tmp)
		client_write(client, buf, r);
}

int
http_req(const char *addr, const char *host, const char *url)
{
	struct sockaddr_in sin;
	char buf[1024] = {0};

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		goto err;
	}

	if (atosin(addr, &sin) < 0)
		goto err;

	if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("connect");
		goto err;
	}

	snprintf(buf, sizeof(buf) - 1, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", url, host);
	if (send(fd, buf, strlen(buf), MSG_NOSIGNAL) != strlen(buf)) {
		perror("send");
		goto err;
	}

	ssize_t r = recv(fd, buf, sizeof(buf) - 1, 0);
	if (r < 0) {
		perror("recv");
		goto err;
	}
	buf[r + 1] = 0;

	char *location = strstr(buf, "Location: ");
	if (location) {
		char *crlf = strstr(location, "\r\n");
		if (!crlf)
			goto err;
		*crlf = 0;

		printf("Redirect: %s\n", location);

		char *red_addr = NULL, *red_url = NULL;
		if (sscanf(location, "Location: http://%a[^/]%as", &red_addr, &red_url) != 2)
			goto err;
		close(fd);
		fd = http_req(red_addr, red_addr, red_url);
		free(red_addr);
		free(red_url);
	}

	return fd;
err:
	close(fd);
	return -1;
}

struct channel *
channel_init(int cno, const char *addr, const char *host, const char *url)
{
	struct channel *chan = calloc(sizeof(*chan), 1);
	chan->no = cno;


#if 0
	// FIXME: nonblocking connect & write
	int optval = 1;
	if (ioctl(fd, FIONBIO, &optval) < 0) {
		perror("ioctl");
		goto err;
	}
#endif

	int fd = http_req(addr, host, url);
	if (fd < 0)
		goto err;


	ev_io_init(&chan->io, channel_read, fd, EV_READ);
	ev_io_start(&chan->io);

	SLIST_INSERT_HEAD(&channels, chan, link);
	return chan;
err:
	free(chan->addr);
	free(chan->url);
	free(chan);
	return NULL;
}

int main(int argc, char* const argv[])
{
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
        perror("Bad listen");
        abort();
    }
	int fd = server_socket(ssin);
	if (fd < 0) {
        perror("Cannot bind");
		abort();
    }

	if (channel_init(3, "88.150.198.108:80", "clients.cdnet.tv", "/h/14/1/1/R1FBQTVIZkIwVks0bWFXTE5aZW1pOEdvbmh1ZGlGbEVSTjZnZ0VVQVloYUZYdGZ6YXdCSEZyc01aMEc0b3Z1NQ") == NULL)
		abort();

	ev_io io;
	ev_io_init(&io, server_accept, fd, EV_READ);
	ev_io_start(&io);

	ev_run(0);
	return 0;
}
