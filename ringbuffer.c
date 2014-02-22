#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "ringbuffer.h"

#define min(a, b) (a)<(b)?(a):(b)

RingBuffer* 
rb_new(size_t capacity)
{
	RingBuffer *rb = (RingBuffer *) malloc(sizeof(RingBuffer) + capacity);
	if (rb == NULL) return NULL;

	rb->rb_capacity	= capacity;
	rb->rb_buff	= (char*)rb + sizeof(RingBuffer);
	rb->rb_tail	= rb->rb_buff;
	rb->rb_size	= 0;
	return rb;
};

void
rb_free(RingBuffer *rb)
{
	free((char*)rb);
}

size_t
rb_capacity(RingBuffer *rb)
{
	assert(rb != NULL);
	return rb->rb_capacity;
}

size_t
rb_can_read(RingBuffer *rb)
{
	assert(rb != NULL);
	return rb->rb_size;
}

size_t
rb_read(RingBuffer *rb, void *data, size_t count)
{
	assert(rb != NULL);
	assert(data != NULL);

	if(rb->rb_size < rb->rb_capacity) {
		memcpy(data, rb->rb_buff, min(count, rb->rb_size));
		return min(count, rb->rb_size);
	}

	int tail_avail_sz = rb->rb_capacity - (rb->rb_tail - rb->rb_buff);
	if(count > rb->rb_capacity)
		count = rb->rb_capacity;

	if (count <= tail_avail_sz) {
		memcpy(data, rb->rb_tail, count);
		return count;
	}
	else {
		memcpy(data, rb->rb_tail, tail_avail_sz);
		memcpy(rb->rb_buff, (char*)data+tail_avail_sz, count-tail_avail_sz);
		return count;
	}
}

size_t
rb_write(RingBuffer *rb, const void *data, size_t count)
{
	assert(rb != NULL);
	assert(data != NULL);

	if (count > rb->rb_capacity) return -1;

	int tail_avail_sz = rb->rb_capacity - (rb->rb_tail - rb->rb_buff);

	if (count <= tail_avail_sz) {
		memcpy(rb->rb_tail, data, count);
		rb->rb_tail += count;
		if (rb->rb_tail == rb->rb_buff+rb->rb_capacity)
			rb->rb_tail = rb->rb_buff;
	}
	else {
		memcpy(rb->rb_tail, data, tail_avail_sz);
		rb->rb_tail = rb->rb_buff;
		memcpy(rb->rb_tail, (char*)data+tail_avail_sz, count-tail_avail_sz);
		rb->rb_tail += count-tail_avail_sz;
	}
	rb->rb_size += count;
	if(rb->rb_size > rb->rb_capacity)
		rb->rb_size = rb->rb_capacity;
	return count;
}

