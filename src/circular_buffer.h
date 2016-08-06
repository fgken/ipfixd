#ifndef __CIRCULAR_BUFFER__
#define __CIRCULAR_BUFFER__

struct circular_buffer;

struct circular_buffer *
cbuf_create(size_t item_size);

uint32_t
cbuf_push(struct circular_buffer *cbuf, void *data);

void *
cbuf_pop(struct circular_buffer *cbuf);

void
cbuf_delete(struct circular_buffer *cbuf);

uint8_t
cbuf_is_full(struct circular_buffer *cbuf);

#endif
