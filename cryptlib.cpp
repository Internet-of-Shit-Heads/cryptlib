#include <string.h>

#include "cryptlib.h"

#if defined(ESP8266)
/* This should already be linked into the coordinator code. */
extern void hmac_sha1(const uint8_t *msg, int length, const uint8_t *key,
		int key_len, uint8_t *digest);
#else
#include "crypto.h"
#endif

static uint8_t digest_buf[SHA1_SIZE];

int cryptlib_auth(uint8_t *data, uint8_t size, uint8_t max_size,
		const uint8_t *key)
{
	uint8_t final_size = size + CRYPTLIB_TAG_SIZE;
	if (final_size > max_size) {
		return -1;
	}

	hmac_sha1(data, size, key, CRYPTLIB_KEY_SIZE, digest_buf);
	memcpy(data + size, digest_buf, CRYPTLIB_TAG_SIZE);

	return final_size;
}

int cryptlib_verify(uint8_t *data, uint8_t size, const uint8_t *key)
{
	if (size <= CRYPTLIB_TAG_SIZE) {
		return -1;
	}

	uint8_t msg_size = size - CRYPTLIB_TAG_SIZE;

	hmac_sha1(data, msg_size, key, CRYPTLIB_KEY_SIZE, digest_buf);
	if (memcmp(data + msg_size, digest_buf, CRYPTLIB_TAG_SIZE) != 0){
		return -1;
	}

	return 0;
}
