/*
chacha-ref.c version 20080118
D. J. Bernstein
Public domain.

Modified by infinigon 20210127
*/

#include "chacha.h"
#include <stddef.h>
#include <string.h>

#define U8TO32_LITTLE(p) \
  (((uint32_t)((p)[0])      ) | \
   ((uint32_t)((p)[1]) <<  8) | \
   ((uint32_t)((p)[2]) << 16) | \
   ((uint32_t)((p)[3]) << 24))

#define U32V(v) ((uint32_t)(v) & (uint32_t)(0xFFFFFFFFULL))
#define ROTATE(v, n)                            \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

static const char sigma[16] = "expand 32-byte k";

void chacha_8rounds_prng(uint32_t output[16], const uint8_t seed[32], uint64_t stream_id, uint64_t pos)
{
  uint32_t input[16], x[16];
  int i;

  input[0]  = x[0]  = U8TO32_LITTLE(sigma + 0);
  input[1]  = x[1]  = U8TO32_LITTLE(sigma + 4);
  input[2]  = x[2]  = U8TO32_LITTLE(sigma + 8);
  input[3]  = x[3]  = U8TO32_LITTLE(sigma + 12);
  input[4]  = x[4]  = U8TO32_LITTLE(seed + 0);
  input[5]  = x[5]  = U8TO32_LITTLE(seed + 4);
  input[6]  = x[6]  = U8TO32_LITTLE(seed + 8);
  input[7]  = x[7]  = U8TO32_LITTLE(seed + 12);
  input[8]  = x[8]  = U8TO32_LITTLE(seed + 16);
  input[9]  = x[9]  = U8TO32_LITTLE(seed + 20);
  input[10] = x[10] = U8TO32_LITTLE(seed + 24);
  input[11] = x[11] = U8TO32_LITTLE(seed + 28);
  input[12] = x[12] = U32V(pos);
  input[13] = x[13] = U32V(pos >> 32);
  input[14] = x[14] = U32V(stream_id);
  input[15] = x[15] = U32V(stream_id >> 32);

  for (i = 8;i > 0;i -= 2) {
    QUARTERROUND( 0, 4, 8,12)
    QUARTERROUND( 1, 5, 9,13)
    QUARTERROUND( 2, 6,10,14)
    QUARTERROUND( 3, 7,11,15)
    QUARTERROUND( 0, 5,10,15)
    QUARTERROUND( 1, 6,11,12)
    QUARTERROUND( 2, 7, 8,13)
    QUARTERROUND( 3, 4, 9,14)
  }
  for (i = 0;i < 16;++i) output[i] = PLUS(x[i],input[i]);
}

static const unsigned char b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define fill_bits(n) ((1 << n) - 1)
#define SEXTET 6
#define OCTET  8

/* pass only valid b64 chars */
unsigned char
reverse_b64_table(unsigned char c)
{
    size_t i;
    for (i = 0; i < strlen(b64_table); i++) {
        if (b64_table[i] == c) {
            return i;
        }
    }
    /* should not happen */
    return 255;
}

/* validate source is actually correct base64-encoded data, but allow missing/implicit padding */
unsigned char
is_valid_b64(char *src_s, size_t len)
{
  size_t i;
  unsigned char *src = (unsigned char *) src_s;

  /* truncate padding characters, at most the last two characters of a quartet */
  while (src[len-1] == '=') {
    if (len % 4 == 0) {
      len--;
    } else if (len % 4 == 3) {
      len--;
    } else {
      /* incorrect padding, invalid b64 */
      return 0;
    }
  }

  /* after truncating padding chars, ensure all remaining are correct B64 */
  for (i = 0; i < len; i++) {
    if (!is_valid_b64_char(src[i])) {
      return 0;
    }

    /* additional checks for the last character */
    if (i == len - 1) {
      unsigned char b64_val = reverse_b64_table(src[i]);
      switch (len % 4) {
        case 1:
          /* impossible - the minimum partial encode is two sextets */
          return 0;
        case 2:
          /* in this case the lowest 4 bits must be 0 */
          if (b64_val & 0xF) {
            return 0;
          }
          break;
        case 3:
          /* in this case the lowest 2 bits must be 0 */
          if (b64_val & 0x3) {
            return 0;
          }
          break;
        default:
          /* default is 0 which is good */
          break;
      }
    }
  }

  /* passed! */
  return 1;
}

size_t
b64_decode(char *src_s, char *dest, size_t len)
{
  size_t src_index, dest_index, dest_bitdex, b64_bitdex, shift, bits_wanted, bits_avail;
  unsigned char b64_val, u8_val, mask;

  /* probably easier to work with unsigned here */
  unsigned char *src = (unsigned char *) src_s;

  src_index = dest_index = dest_bitdex = b64_bitdex = 0;
  u8_val = b64_val = 0;
  /* if src_index == len but we have bits left over, we're not done */
  while (src_index < len || b64_bitdex) {
    /* we don't actually want or expect '=' in the seed set in OPTIONS,
     * but we'll treat them as padding here */
    if (!b64_bitdex) {
        if (src[src_index] == '=') {
            break;
        }
        b64_val = reverse_b64_table(src[src_index++]);
    }

    /* if we want 6 bits and 8 are still available, the mask will be shifted up 2 */
    bits_wanted = OCTET - dest_bitdex;
    bits_avail  = SEXTET - b64_bitdex;

    if (bits_avail >= bits_wanted) {
      shift = bits_avail - bits_wanted;
      mask = fill_bits(bits_wanted) << shift;
      u8_val |= (b64_val & mask) >> shift;
      b64_bitdex += bits_wanted;
      if (b64_bitdex == SEXTET) {
          b64_bitdex = 0;
      }
      dest_bitdex = 0;
      dest[dest_index++] = u8_val;
      u8_val = 0;
    } else {
      shift = bits_wanted - bits_avail;
      u8_val |= (b64_val & fill_bits(bits_avail)) << shift;
      dest_bitdex += bits_avail;
      b64_bitdex = 0;
    }
  }
  
  /* should raise an error/impossible here somehow, but validating
     input will also ensure only valid termination sequences are used */
  /*if (dest_bitdex && u8_val) {
     PANIC 
  }*/
  dest[dest_index] = 0;
  return dest_index;
}

/* this one assumes you better have correct data you scrubbins */
/* no padding '=' characters are added at the end */ 
size_t
b64_encode(char *src_s, char *dest, size_t len)
{
  size_t src_index, dest_index, src_bitdex, b64_bitdex, shift, bits_wanted, bits_avail;
  unsigned char b64_val, u8_val, mask;

  /* probably easier to work with unsigned here */
  unsigned char *src = (unsigned char *) src_s;

  src_index = dest_index = src_bitdex = b64_bitdex = 0;
  u8_val = b64_val = 0;

  /* need to handle leftover bits if src_index == len and src_bitdex is non-zero */
  while (src_index < len || src_bitdex) {
    if (!src_bitdex) {
        u8_val = src[src_index++];
    }

    /* if we want 6 bits and 8 are still available, the mask will be shifted up 2 */
    bits_wanted = SEXTET - b64_bitdex;
    bits_avail  = OCTET - src_bitdex;

    if (bits_avail >= bits_wanted) {
      shift = bits_avail - bits_wanted;
      mask = fill_bits(bits_wanted) << shift;
      b64_val |= (u8_val & mask) >> shift;
      src_bitdex += bits_wanted;
      if (src_bitdex == OCTET) {
          src_bitdex = 0;
      }
      dest[dest_index++] = b64_table[b64_val];
      b64_val = 0;
      b64_bitdex = 0;
    } else {
      shift = bits_wanted - bits_avail;
      b64_val |= (u8_val & fill_bits(bits_avail)) << shift;
      b64_bitdex += bits_avail;
      src_bitdex = 0;
    }
  }

  /* add any leftover bits in temp b64_val */
  if (b64_bitdex) {
      dest[dest_index++] = b64_table[b64_val];
  }

  /* add padding and finally null terminate the string */
  while (dest_index % 4) {
    dest[dest_index++] = '=';
  }
  dest[dest_index] = 0;
  return dest_index;
}