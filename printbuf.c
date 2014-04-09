#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "printbuf.h"

struct printbuf *
prbuf_create(size_t n)
{
	struct printbuf *pb = malloc(sizeof(struct printbuf));
	if (NULL == pb)
		return NULL;

	pb->buff = malloc(n);
	if (NULL == pb->buff) {
		free(pb);
		return NULL;
	}
	pb->len = n;
	pb->pos = 0;
	return pb;
}


void
prbuf_reset(struct printbuf *pb)
{
	pb->pos = 0;
	pb->buff[0] = '\0';
}



void
prbuf_close(struct printbuf *pb)
{
	free(pb->buff);
	free(pb);
}

size_t
prbuf_len(struct printbuf *pb)
{
	return pb->pos;
}

int
prbuf_printf(struct printbuf *pb, const char* format, ... )
{
	va_list ap;
	char* p = NULL;
	int n = -1;
	size_t left;

	if (pb->pos >= pb->len)
		return 0;

	left = pb->len - pb->pos - 1;
	p = pb->buff + pb->pos;

	va_start(ap, format);
	errno = 0;
	n = vsnprintf(p, left, format, ap);
	va_end(ap);

	if (n < 0)
		return -1;

	if ((size_t) n >= left)
		n = left;

	p[n] = '\0';
	pb->pos += (size_t) n;
	return n;
}


