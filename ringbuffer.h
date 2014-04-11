#ifndef RINGBUFFER_H
#define RINGBUFFER_H

#include <stdint.h>
struct iovec;

struct ringbuf {
	size_t capacity;
	size_t tail;
	char   over;
	char   buff[];
};

struct ringbuf *rb_new(size_t capacity);

void rb_reset(struct ringbuf *rb);
void rb_append(struct ringbuf *rb, const void *data, size_t count);
size_t rb_size(struct ringbuf *rb);
char * rb_tailptr(struct ringbuf *rb);
size_t rb_recv(int fd, struct ringbuf *rb, int flags);
void rb_iovec(struct ringbuf *rb, struct iovec *iov, ssize_t pos);
ssize_t rb_calcpos(struct ringbuf *rb, ssize_t pos, ssize_t offset);
void rb_shift(struct ringbuf *rb, char *to, size_t len);
#endif
