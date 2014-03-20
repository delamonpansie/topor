#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <stdio.h>

#include "ringbuffer.h"

struct ringbuf *
rb_new(size_t capacity)
{
	struct ringbuf *rb = malloc(sizeof(*rb) + capacity);
	if (rb == NULL)
		return NULL;

	rb->capacity	= capacity;
	rb->tail	= rb->buff;
	rb->over	= 0;
	return rb;
};

void
rb_reset(struct ringbuf *rb)
{
	assert(rb != NULL);
	rb->tail = rb->buff;
	rb->over = 0;
}

size_t
rb_size(struct ringbuf *rb)
{
	return rb->tail - rb->buff;
}

void
rb_append(struct ringbuf *rb, const void *data, size_t count)
{
	ssize_t free = rb->capacity - rb_size(rb);
	if (count > free) {
		rb->over = 1;

		memcpy(rb->tail, data, free);
		rb->tail = rb->buff;
		data += free;
		count -= free;
	}

	memcpy(rb->tail, data, count);
}

size_t
rb_recv(int fd, struct ringbuf *rb, int flags)
{
	size_t free = rb->capacity - rb_size(rb);
	ssize_t r = recv(fd, rb->tail, free, flags);

	if (r <= 0)
		return r;

	if (r < free) {
		rb->tail += r;
	} else {
		rb->tail = rb->buff;
		rb->over = 1;
	}

//printf("recv:%zi rb_size:%zi over:%i\n", r, rb_size(rb), rb->over);

	return r;
}

size_t
rb_iovec(struct ringbuf *rb, struct iovec *iov, size_t count)
{
	assert(count >= 2);

	if (rb->over) {
		iov[0].iov_base = rb->tail;
		iov[0].iov_len = rb->capacity - rb_size(rb);
		iov[1].iov_base = rb->buff;
		iov[1].iov_len = rb_size(rb);
		return 2;
	} else {
		iov[0].iov_base = rb->buff;
		iov[0].iov_len = rb_size(rb);
		return 1;
	}
}
