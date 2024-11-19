#ifndef RAW_SOCK_H_
#define RAW_SOCK_H_


 
//Dependencies
#include <stdlib.h>
#include "core/net.h"
#include "debug.h"


error_t RAW_open(int *psd);

error_t RAW_close(int sd);

int RAW_send(int sd, void* data, size_t length);

int RAW_recv(int sd, void *buf, size_t len);

#endif

