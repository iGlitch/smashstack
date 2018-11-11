#ifndef _AES_H
#define _AES_H

/*  This include is used only to find 8 and 32 bit unsigned integer types   */

#include "limits.h"

typedef struct ResultStruct {
	unsigned char* Buffer;
	unsigned int Length;
	unsigned int Error;
} Result;

typedef unsigned long  u32;
typedef unsigned short u16;
typedef unsigned char  u8;

#if UCHAR_MAX == 0xff       /* An unsigned 8 bit type for internal AES use  */
  typedef unsigned char      aes_08t;
#else
#error Please define an unsigned 8 bit type in aes.h
#endif

#if UINT_MAX == 0xffffffff  /* An unsigned 32 bit type for internal AES use */
  typedef   unsigned int     aes_32t;
#elif ULONG_MAX == 0xffffffff
  typedef   unsigned long    aes_32t;
#else
#error Please define an unsigned 32 bit type in aes.h
#endif

/* BLOCK_SIZE is in BYTES: 16, 24, 32 */

#define BLOCK_SIZE  16

/* Key schedule length (in 32-bit words) */

#if !defined(BLOCK_SIZE)
#define KS_LENGTH   128
#else
#define KS_LENGTH   4 * BLOCK_SIZE
#endif

#ifdef __cplusplus
extern "C"
{
#endif

typedef unsigned int aes_fret;   /* Type for function return value       */
#define aes_bad      0           /* Bad function return value            */
#define aes_good     1           /* Good function return value           */
#ifndef AES_DLL                  /* Implement normal or DLL functions    */
#define aes_rval     aes_fret
#else
#define aes_rval     aes_fret __declspec(dllexport) _stdcall
#endif


typedef struct                     /* The AES context for encryption   */
{   aes_32t    k_sch[KS_LENGTH];   /* The encryption key schedule      */
    aes_32t    n_rnd;              /* The number of cipher rounds      */
    aes_32t    n_blk;              /* The number of bytes in the state */
} aes_ctx;

#if !defined(BLOCK_SIZE)
aes_rval aes_blk_len(unsigned int blen, aes_ctx cx[1]);
#endif

aes_rval aes_enc_key(const unsigned char in_key[], unsigned int klen, aes_ctx cx[1]);
aes_rval aes_enc_blk(const unsigned char in_blk[], unsigned char out_blk[], const aes_ctx cx[1]);

aes_rval aes_dec_key(const unsigned char in_key[], unsigned int klen, aes_ctx cx[1]);
aes_rval aes_dec_blk(const unsigned char in_blk[], unsigned char out_blk[], const aes_ctx cx[1]);


Result EncFile(Result input);
Result DecFile(const char *filename);
Result Decompress(Result input);

#ifdef __cplusplus
}
#endif

#endif
