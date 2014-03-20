#ifndef RINGBUFFER_H
#define RINGBUFFER_H

#include <stdint.h>
struct iovec;

struct ringbuf {
	size_t capacity;
	char over;
	char  *tail;
	char  buff[];
};

struct ringbuf *rb_new(size_t capacity);

void rb_reset(struct ringbuf *rb);
void rb_append(struct ringbuf *rb, const void *data, size_t count);
size_t rb_size(struct ringbuf *rb);
size_t rb_recv(int fd, struct ringbuf *rb, int flags);
size_t rb_iovec(struct ringbuf *rb, struct iovec *iov, size_t count);
#endif
