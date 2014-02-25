#ifndef RINGBUFFER_H
#define RINGBUFFER_H

#include <stdlib.h>

typedef struct ringbuffer {
	size_t rb_capacity;
	size_t rb_size;;
	char  *rb_tail;
	char  *rb_buff;
} RingBuffer;

RingBuffer* rb_new(size_t capacity);
void	rb_free(RingBuffer *rb);

size_t	rb_capacity(RingBuffer *rb);
size_t	rb_can_read(RingBuffer *rb);
char*	rb_head(RingBuffer *rb);
void	rb_reset(RingBuffer *rb);
size_t	rb_read(RingBuffer *rb, void *data, size_t count);
size_t	rb_write(RingBuffer *rb, const void *data, size_t count);
size_t	rb_writesize(RingBuffer *rb, size_t count);
void*	rb_writepointer(RingBuffer *rb);

#endif
