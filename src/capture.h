#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#include "circular_buffer.h"

void
start_capture(char *device, struct circular_buffer *cbuf);

#endif
