#ifndef __CRYPTLIB_H__
#define __CRYPTLIB_H__

#include <stdint.h>

#define CRYPTLIB_KEY_SIZE 16
#define CRYPTLIB_TAG_SIZE 10

int cryptlib_auth(uint8_t *data, uint8_t size, uint8_t max_size,
		const uint8_t *key);
int cryptlib_verify(uint8_t *data, uint8_t size, const uint8_t *key);

#endif /* __CRYPTLIB_H__ */
