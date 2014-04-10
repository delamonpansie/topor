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
	rb->tail	= 0;
	rb->over	= 0;
	return rb;
};

void
rb_reset(struct ringbuf *rb)
{
	assert(rb != NULL);
	rb->tail = 0;
	rb->over = 0;
}

size_t
rb_size(struct ringbuf *rb)
{
	return rb->tail;
}

char *
rb_tailptr(struct ringbuf *rb)
{
	return rb->buff + rb->tail;
}

void
rb_append(struct ringbuf *rb, const void *data, size_t count)
{
	ssize_t free = rb->capacity - rb->tail;
	if (count > free) {
		rb->over = 1;

		memcpy(rb->buff + rb->tail, data, free);
		rb->tail = 0;
		data += free;
		count -= free;
	}

	memcpy(rb->buff + rb->tail, data, count);
}

size_t
rb_recv(int fd, struct ringbuf *rb, int flags)
{
	size_t free = rb->capacity - rb->tail;
	ssize_t r = recv(fd, rb->buff + rb->tail, free, flags);

	if (r <= 0)
		return r;

	if (r < free) {
		rb->tail += r;
	} else {
		rb->tail = 0;
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
		iov[0].iov_base = rb->buff + rb->tail;
		iov[0].iov_len = rb->capacity - rb->tail;
		iov[1].iov_base = rb->buff;
		iov[1].iov_len = rb->tail;
		return 2;
	} else {
		iov[0].iov_base = rb->buff;
		iov[0].iov_len = rb->tail;
		return 1;
	}
}

void
rb_shift(struct ringbuf *rb, char *to, size_t len)
{
	char *from = to + len;
	size_t count = rb->tail - (to - rb->buff + len);
	memcpy(to, from, count);
	rb->tail -= len;
}
