#ifndef PRINTBUF_H
#define PRINTBUF_H

struct printbuf
{
	char*   buff;
	size_t  len, pos;
};


struct printbuf * prbuf_create(size_t n);
void prbuf_reset(struct printbuf *pb);
void prbuf_close(struct printbuf *pb);
size_t prbuf_len(struct printbuf *pb);
int prbuf_printf(struct printbuf *pb, const char* format, ... );

#endif

