/*
 * Copyright (c) 2007-2016, Cameron Rich
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, 
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice, 
 *   this list of conditions and the following disclaimer in the documentation 
 *   and/or other materials provided with the distribution.
 * * Neither the name of the axTLS project nor the names of its contributors 
 *   may be used to endorse or promote products derived from this software 
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* All of this code has been copied from https://github.com/igrr/axtls-8266 */

#include <string.h>
#include "cryptlib_hmac.h"

/*
 *  This structure will hold context information for the SHA-1
 *  hashing operation
 */
typedef struct 
{
    uint32_t Intermediate_Hash[SHA1_SIZE/4]; /* Message Digest */
    uint32_t Length_Low;            /* Message length in bits */
    uint32_t Length_High;           /* Message length in bits */
    uint16_t Message_Block_Index;   /* Index into message block array   */
    uint8_t Message_Block[64];      /* 512-bit message blocks */
} SHA1_CTX;

static void SHA1_Init(SHA1_CTX *);
static void SHA1_Update(SHA1_CTX *, const uint8_t * msg, int len);
static void SHA1_Final(uint8_t *digest, SHA1_CTX *);

static void hmac_sha1_v(const uint8_t **msg, int *length, int count,
        const uint8_t *key, int key_len, uint8_t *digest);

/*
 *  Define the SHA1 circular left shift macro
 */
#define SHA1CircularShift(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))

/* ----- static functions ----- */
static void SHA1PadMessage(SHA1_CTX *ctx);
static void SHA1ProcessMessageBlock(SHA1_CTX *ctx);

/**
 * Initialize the SHA1 context 
 */
static void SHA1_Init(SHA1_CTX *ctx)
{
    ctx->Length_Low             = 0;
    ctx->Length_High            = 0;
    ctx->Message_Block_Index    = 0;
    ctx->Intermediate_Hash[0]   = 0x67452301;
    ctx->Intermediate_Hash[1]   = 0xEFCDAB89;
    ctx->Intermediate_Hash[2]   = 0x98BADCFE;
    ctx->Intermediate_Hash[3]   = 0x10325476;
    ctx->Intermediate_Hash[4]   = 0xC3D2E1F0;
}

/**
 * Accepts an array of octets as the next portion of the message.
 */
static void SHA1_Update(SHA1_CTX *ctx, const uint8_t *msg, int len)
{
    while (len--)
    {
        ctx->Message_Block[ctx->Message_Block_Index++] = (*msg & 0xFF);
        ctx->Length_Low += 8;

        if (ctx->Length_Low == 0)
            ctx->Length_High++;

        if (ctx->Message_Block_Index == 64)
            SHA1ProcessMessageBlock(ctx);

        msg++;
    }
}

/**
 * Return the 160-bit message digest into the user's array
 */
static void SHA1_Final(uint8_t *digest, SHA1_CTX *ctx)
{
    int i;

    SHA1PadMessage(ctx);
    memset(ctx->Message_Block, 0, 64);
    ctx->Length_Low = 0;    /* and clear length */
    ctx->Length_High = 0;

    for  (i = 0; i < SHA1_SIZE; i++)
    {
        digest[i] = ctx->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) );
    }
}

/**
 * Process the next 512 bits of the message stored in the array.
 */
static void SHA1ProcessMessageBlock(SHA1_CTX *ctx)
{
    const uint32_t K[] =    {       /* Constants defined in SHA-1   */
                            0x5A827999,
                            0x6ED9EBA1,
                            0x8F1BBCDC,
                            0xCA62C1D6
                            };
    int        t;                 /* Loop counter                */
    uint32_t      temp;              /* Temporary word value        */
    uint32_t      W[80];             /* Word sequence               */
    uint32_t      A, B, C, D, E;     /* Word buffers                */

    /*
     *  Initialize the first 16 words in the array W
     */
    for  (t = 0; t < 16; t++)
    {
        W[t] = ((uint32_t)ctx->Message_Block[t * 4]) << 24;
        W[t] |= ((uint32_t)ctx->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((uint32_t)ctx->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((uint32_t)ctx->Message_Block[t * 4 + 3]);
    }

    for (t = 16; t < 80; t++)
    {
       W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    A = ctx->Intermediate_Hash[0];
    B = ctx->Intermediate_Hash[1];
    C = ctx->Intermediate_Hash[2];
    D = ctx->Intermediate_Hash[3];
    E = ctx->Intermediate_Hash[4];

    for (t = 0; t < 20; t++)
    {
        temp =  SHA1CircularShift(5,A) +
                ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);

        B = A;
        A = temp;
    }

    for (t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for (t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5,A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for (t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    ctx->Intermediate_Hash[0] += A;
    ctx->Intermediate_Hash[1] += B;
    ctx->Intermediate_Hash[2] += C;
    ctx->Intermediate_Hash[3] += D;
    ctx->Intermediate_Hash[4] += E;
    ctx->Message_Block_Index = 0;
}

/*
 * According to the standard, the message must be padded to an even
 * 512 bits.  The first padding bit must be a '1'.  The last 64
 * bits represent the length of the original message.  All bits in
 * between should be 0.  This function will pad the message
 * according to those rules by filling the Message_Block array
 * accordingly.  It will also call the ProcessMessageBlock function
 * provided appropriately.  When it returns, it can be assumed that
 * the message digest has been computed.
 *
 * @param ctx [in, out] The SHA1 context
 */
static void SHA1PadMessage(SHA1_CTX *ctx)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (ctx->Message_Block_Index > 55)
    {
        ctx->Message_Block[ctx->Message_Block_Index++] = 0x80;
        while(ctx->Message_Block_Index < 64)
        {
            ctx->Message_Block[ctx->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(ctx);

        while (ctx->Message_Block_Index < 56)
        {
            ctx->Message_Block[ctx->Message_Block_Index++] = 0;
        }
    }
    else
    {
        ctx->Message_Block[ctx->Message_Block_Index++] = 0x80;
        while(ctx->Message_Block_Index < 56)
        {

            ctx->Message_Block[ctx->Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    ctx->Message_Block[56] = ctx->Length_High >> 24;
    ctx->Message_Block[57] = ctx->Length_High >> 16;
    ctx->Message_Block[58] = ctx->Length_High >> 8;
    ctx->Message_Block[59] = ctx->Length_High;
    ctx->Message_Block[60] = ctx->Length_Low >> 24;
    ctx->Message_Block[61] = ctx->Length_Low >> 16;
    ctx->Message_Block[62] = ctx->Length_Low >> 8;
    ctx->Message_Block[63] = ctx->Length_Low;
    SHA1ProcessMessageBlock(ctx);
}

/**
 * Perform HMAC-SHA1
 * NOTE: does not handle keys larger than the block size.
 */
void hmac_sha1(const uint8_t *msg, int length, const uint8_t *key, 
        int key_len, uint8_t *digest)
{
    hmac_sha1_v(&msg, &length, 1, key, key_len, digest);
}

static void hmac_sha1_v(const uint8_t **msg, int *length, int count,
        const uint8_t *key, int key_len, uint8_t *digest)
{
    SHA1_CTX context;
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    int i;

    memset(k_ipad, 0, sizeof k_ipad);
    memset(k_opad, 0, sizeof k_opad);
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    for (i = 0; i < 64; i++) 
    {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    SHA1_Init(&context);
    SHA1_Update(&context, k_ipad, 64);
    for (i = 0; i < count; ++i) 
    {
        SHA1_Update(&context, msg[i], length[i]);
    }
    SHA1_Final(digest, &context);
    SHA1_Init(&context);
    SHA1_Update(&context, k_opad, 64);
    SHA1_Update(&context, digest, SHA1_SIZE);
    SHA1_Final(digest, &context);
}
