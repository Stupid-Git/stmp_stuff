
#ifndef SP1_H_
#define SP1_H_

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
    uint32_t sync_code;
} sync_word;

typedef struct {
    uint16_t opcode;
    uint16_t length;
} hdr;



void pabort(const char *s);
void hex_dump(const void *src, size_t length, size_t line_size, char *prefix);
void transfer(int fd, uint8_t const *tx, uint8_t const *rx, size_t len, int is_slave);


#endif // SPI1_H
