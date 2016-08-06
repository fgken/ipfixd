#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "circular_buffer.h"
#include "log.h"

struct circular_buffer {
    void **buf;
    size_t capacity;    /* the number of items */
    size_t head;
    size_t tail;
};

struct circular_buffer *
cbuf_create(size_t item_count)
{
    if (item_count <= 0) {
        return NULL;
    }

    struct circular_buffer *cbuf = calloc(1, sizeof(struct circular_buffer));
    if (cbuf == NULL) {
        return NULL;
    }

    cbuf->buf = calloc(1, sizeof(void *) * (item_count + 1));
    if (cbuf->buf == NULL) {
        free(cbuf);
        return NULL;
    }

    cbuf->capacity = item_count + 1;
    cbuf->head = 0;
    cbuf->tail = 0;

    //log_debug("item_size = %zu, capcacity = %zu",
    //    sizeof(void *), cbuf->capacity);

    return cbuf;
}

uint32_t
cbuf_push(struct circular_buffer *cbuf, void *data)
{
    if (cbuf == NULL || data == NULL) {
        return -1;
    }

    // FIXME: producer lock
    //log_debug("head = %zu, tail = %zu", cbuf->head, cbuf->tail);

    uint32_t ret = -1;
    size_t next_tail = (cbuf->tail + 1) % cbuf->capacity;

    if (next_tail == cbuf->head) {
        ret = -1;   // Buffer is full
        log_debug("Buffer is full");
    } else {
        cbuf->buf[cbuf->tail] = data;
        cbuf->tail = next_tail;
        ret = 0;
    }

    //log_debug("head = %zu, tail = %zu", cbuf->head, cbuf->tail);
    //log_debug("tail - head = %ld", cbuf->tail - cbuf->head);

    return ret;
}

void *
cbuf_pop(struct circular_buffer *cbuf)
{
    if (cbuf == NULL) {
        return NULL;
    }

    // FIXME: consumer lock
    //log_debug("head = %zu, tail = %zu", cbuf->head, cbuf->tail);
    void *ret = NULL;
    if (cbuf->head == cbuf->tail) {
        ret = NULL;    // Buffer is empty
    } else {
        size_t next_head = (cbuf->head + 1) % cbuf->capacity;

        ret = cbuf->buf[cbuf->head];
        cbuf->head = next_head;
    }
    
    //log_debug("head = %zu, tail = %zu", cbuf->head, cbuf->tail);

    return ret;
}

void
cbuf_delete(struct circular_buffer *cbuf)
{
    free(cbuf->buf);
    free(cbuf);
}

uint8_t
cbuf_is_full(struct circular_buffer *cbuf)
{
    return (cbuf->head == ((cbuf->tail + 1) % cbuf->capacity));
}
