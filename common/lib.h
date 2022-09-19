// Copyright (C) 2022 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

#ifndef LIB_H
#define LIB_H

#include "types.h"

int putchar(uint8_t ch);
void lf();
void putinthex(const uint32_t n);
void puts(const char *s);
void puthex(uint8_t ch);
void hexdump(uint8_t *buf, int len);
void *memset(void *dest, int c, unsigned n);
void *memcpy(void *dest, const void *src, unsigned n);
void *wordcpy(void *dest, const void *src, unsigned n);

#endif
