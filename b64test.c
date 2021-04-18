#include <stdio.h>
#include <stddef.h>
#include <string.h>


#define is_valid_b64_char(c) (('A' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '+' || c == '/')
static const unsigned char b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define fill_bits(n) ((1 << n) - 1)
#define SEXTET 6
#define OCTET  8

/* pass only valid b64 chars */
static unsigned char
reverse_b64_table(unsigned char c)
{
    size_t i;
    for (i = 0; i < BASE64; i++) {
        if (b64_table[i] == c) {
            return i;
        }
    }
    /* should not happen */
    return 255;
}

/* lazy validation */
boolean
is_valid_b64(char *src_s, size_t len)
{
  size_t i;
  unsigned char *src = (unsigned char *) src_s;

  /* should also return true if strict validation succeeds */
  if (is_valid_b64_strict(src_s, len)) {
    return 1;
  }

  /* don't bother truncating padding chars. if they were used,
     then strict validation should apply */
  for (i = 0; i < len; i++) {
    if (!is_valid_b64_char(src[i])) {
      return 0;
    }
  }

  /* passed! */
  return 1;
}

/* validate source is actually correct base64-encoded data, but allow missing/implicit padding */
static boolean
is_valid_b64_strict(char *src_s, size_t len)
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

/* this function assumes weak validation succeeded,
   but weak validation failed. This means there are
   some bits that would be truncated if they were
   decoded without modification. returns number of
   bytes added (excluding null). */
static size_t
b64_nullpad(char *src, char *dest, size_t len)
{
  strncpy(dest, src, len + 1);
  switch (len % 4) {
    case 1:
      strcpy(dest+len, "A==");
      return 3;
    case 2:
      strcpy(dest+len, "A=");
      return 2;
    case 3:
      strcpy(dest+len, "A");
      return 1;
    default:
      return 0;
  }
}

size_t
b64_decode(char *src_s, char *dest, size_t len)
{
  size_t src_index, dest_index, dest_bitdex, b64_bitdex, shift, bits_wanted, bits_avail;
  unsigned char b64_val, u8_val, mask;

  /* probably easier to work with unsigned here */
  unsigned char src[MAX_B64_RNG_SEED_LEN+2];
  if (!is_valid_b64_strict(src_s, len)) {
    len += b64_nullpad(src_s, (char *)src, len);
  } else {
    strncpy((char *)src, src_s, len + 1);
  }

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

void
main() {
    char buf[1000];
    char *src = "UndyneAppreciationClub";
    char *b64src = "foobaQ";
    size_t len = b64_encode(src, buf, strlen(src));
    printf("%s encoded: %s, encoded len: %d\n", src, buf, len);
    len = b64_decode(b64src, buf, strlen(b64src));
    printf("%s decoded: %s, decoded len: %d\n", b64src, buf, len);
    if (!is_valid_b64(b64src, strlen(b64src))) {
      printf("%s is invalid base64\n", b64src);
    }
}