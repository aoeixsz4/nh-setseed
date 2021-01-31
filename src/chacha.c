/*
chacha-ref.c version 20080118
D. J. Bernstein
Public domain.

Modified by infinigon 20210127
*/

#include "chacha.h"

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
