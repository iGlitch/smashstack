#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <memory.h>
#include <string.h>

#include "AES.h"

#define READ_ERROR  -7
#define WRITE_ERROR -8
#define _STDCALL_SUPPORTED

#ifdef LINUX
#define file_len(x) (unsigned long)x.__pos
#else
#define file_len(x) (unsigned long)x
#endif


static int IncreaseBuffer(unsigned char **buffer, unsigned int *buffersize);
static unsigned long ReadArray( unsigned char *Source, unsigned char *Buffer, unsigned int Offset, unsigned int Size, unsigned int maxSize);
static Result GetError(int errorCode);

const char *key = "\xAB\x01\xB9\xD8\xE1\x62\x2B\x08\xAF\xBA\xD8\x4D\xBF\xC2\xA5\x5D";  // Wii's SD-Key
const char *iv  = "\x4E\x03\x41\xDE\xE6\xBB\xAA\x41\x64\x19\xB3\xEA\xE8\xF5\x3B\xD9";  // Brawl's InitVector (First block [16bytes] of AES data)


Result EncFile(Result input) {
	unsigned char *Source = input.Buffer;
	unsigned char buf[BLOCK_SIZE], dbuf[2 * BLOCK_SIZE];
	unsigned long rlen = input.Length;
	unsigned long curPos = 0;
	unsigned long i = 0, len;
	aes_ctx ctx[1];
	ctx->n_rnd = 0;
	ctx->n_blk = 0;

	aes_enc_key( (const unsigned char*)key, 16, ctx);

	// Set the BRAWL-IV
	for (i = 0; i < 16; i++) { dbuf[i] = iv[i]; }

	unsigned char* output;
	output = malloc(rlen+1);

	// Read the file a block at a time 
	while (rlen > 0) {
		// Read a block and reduce the remaining byte count
		len = ReadArray(Source, buf, curPos, BLOCK_SIZE, input.Length);
		rlen -= len;

		// Verify length of block 
		if(len != BLOCK_SIZE) { return GetError(READ_ERROR); }

		// Do CBC chaining prior to encryption
		for(i = 0; i < BLOCK_SIZE; ++i) { buf[i] ^= dbuf[i]; }

		// Encrypt the block
		aes_enc_blk(buf, dbuf, ctx);

		unsigned int i;
		for (i = 0 ; i < len ; i++ ) {
			output[curPos + i] = dbuf[i];
		}
		curPos += len;
	}

	Result result;
	result.Buffer = output;
	result.Length = input.Length;
	result.Error = 0;
	return result;
}

Result DecFile(const char *filename) {
	char	buf1[BLOCK_SIZE], buf2[BLOCK_SIZE], dbuf[2 * BLOCK_SIZE];
	char	*b1, *b2, *bt;
	fpos_t	flen;
	unsigned long i, j, len, rlen;
//	int by;
	aes_ctx ctx[1];
	ctx->n_rnd = 0;
	ctx->n_blk = 0;
	i = 0; j = 0;

	aes_dec_key( (const unsigned char*)key, 16, ctx);

	FILE *fin = fopen(filename, "rb");
	fseek(fin, 0, SEEK_END);
	fgetpos(fin, &flen); 
	rlen = file_len(flen.__pos);
	fseek(fin, 0, SEEK_SET);

	unsigned char* output;
	output = malloc(rlen+1);
	
	b1 = buf1; b2 = buf2;
	for (i = 0; i < 16; i++) { b1[i] = iv[i]; }

	// Read the encrypted file a block at a time
	while(rlen > 0 && !feof(fin)) {
		// Input a block and reduce the remaining byte count
		len = (unsigned long)fread(b2, 1, BLOCK_SIZE, fin);
		rlen -= len;

		// Verify the length of the read operation
		if(len != BLOCK_SIZE) { fprintf( stderr, "Error 10\n"); return GetError(0); }

		// Decrypt input buffer
		aes_dec_blk((const unsigned char*)b2, (unsigned char*)dbuf, ctx);

		// If there's only one more block do ciphertext stealing
		if (rlen > 0 && rlen < BLOCK_SIZE) {
			// Read last ciphertext block
			if(fread(b2, 1, rlen, fin) != rlen) { fprintf( stderr, "Error 20\n"); return GetError(0); }

			// Append high part of last decrypted block
			for(i = rlen; i < BLOCK_SIZE; ++i) {
				b2[i] = dbuf[i];
			}

			// Decrypt last block of plaintext
			for (i = 0; i < rlen; ++i) {
				dbuf[i + BLOCK_SIZE] = dbuf[i] ^ b2[i];
			}

			// Decrypt last but one block of plaintext
			aes_dec_blk((const unsigned char*)b2, (unsigned char*)dbuf, ctx);

			// Adjust length of last output block
			len = rlen + BLOCK_SIZE; rlen = 0;
		}

		// Unchain CBC using the last ciphertext block
		for(i = 0; i < BLOCK_SIZE; ++i) { dbuf[i] ^= b1[i]; output[j] = dbuf[i]; j++; }

		// Swap the buffer pointers
		bt = b1; b1 = b2; b2 = bt;
	}

	fclose(fin);

	Result result;
	result.Buffer = output;
	result.Length = j;
	result.Error = 0;
	return result;
}

Result Decompress(Result input) {
	unsigned char *ibuffer = input.Buffer;
	unsigned int bufferlen = input.Length;
	unsigned int buffersize = 96000;
	unsigned int bufferindex = 0;
	unsigned char *outbuffer;
	unsigned char controlbyte;
	unsigned char tempbuffer[10];
	unsigned int num_bytes_to_copy;
	unsigned int backwards_offset;
	int copy_start_index;
	unsigned int copy_counter;
	unsigned int i = 0, j = 32, k = 0;

	outbuffer = malloc(buffersize);

	for (k = 0; k < j; k++) {
		outbuffer[bufferindex] = ibuffer[k];
		bufferindex++;
	} j = j + 4;

	while (j < bufferlen) {
		controlbyte = ibuffer[j]; j++;

		if (j > bufferlen) {
			fprintf( stderr, "Overflow!\n");
			continue;
		}
		// --------------------------------------------------------
			//fprintf( stderr, "Control byte:  0x%02x\n", controlbyte);
			//exit(-1);
		// --------------------------------------------------------
		for (i = 0; i < 8; i++) {
			if (controlbyte & (0x80 >> i)) {
				// Take encoded data
				tempbuffer[0] = ibuffer[j]; j++;
				tempbuffer[1] = ibuffer[j]; j++;
				
				// If the first nibble is 0, get a third byte
				if ((tempbuffer[0] & 0xF0) == 0) {
					tempbuffer[2] = ibuffer[j]; j++;
					num_bytes_to_copy = (((unsigned int) tempbuffer[0]) * 0x10) + (tempbuffer[1] >> 4) + 0x11;
					backwards_offset = (((unsigned int) (tempbuffer[1] & 0x0F)) * 0x100) + tempbuffer[2] + 1;
				}
				// If the first nibble is 1, grab TWO more bytes.  (next four nibbles will be length, then three offset)
				// HUGE thanks to Ondo for figuring this part out!  
				else if ((tempbuffer[0] & 0xF0) == 0x10) {
					tempbuffer[2] = ibuffer[j]; j++;
					tempbuffer[3] = ibuffer[j]; j++;
					//fprintf( stderr, "0x %02x %02x %02x %02x\n", tempbuffer[0], tempbuffer[1], tempbuffer[2], tempbuffer[3]);
					num_bytes_to_copy =
						(((unsigned int) tempbuffer[0] & 0x0F) * 0x1000) +
						(((unsigned int) tempbuffer[1]) * 0x10) +
						(tempbuffer[2] >> 4) + 0x111;
					backwards_offset = (((unsigned int) (tempbuffer[2] & 0x0F)) * 0x100) + tempbuffer[3] + 1;
				}
				// Otherwise, do a normal decompress using two bytes
				else {
					//fprintf( stderr, "0x %02x %02x\n", tempbuffer[0], tempbuffer[1]);
					num_bytes_to_copy = (tempbuffer[0] >> 4) + 0x01;
					backwards_offset = (((unsigned int) (tempbuffer[0] & 0x0F)) * 0x100) + tempbuffer[1] + 1;
				}
				// ----------------------------------------------------
					//fprintf( stderr, "I: %d\nBufferIndex: %d\nControlByte: %d\nTempBuffer 01: %d\nTempBuffer 02: %d\nTempBuffer 03: %d\n\nBytesToCopy: %d\nBackwardsOffset: %d", i, bufferindex, controlbyte, tempbuffer[0], tempbuffer[1], tempbuffer[2], num_bytes_to_copy, backwards_offset);
					//exit(-1);
				// ----------------------------------------------------
				if (backwards_offset <= 0) {
					fprintf( stderr, "Error:  Backwards offset is <= 0, this probably is wrong.\n");
				} else {
					copy_start_index = bufferindex - backwards_offset;
					if (copy_start_index < 0) {
						fprintf( stderr, "Error occured while decompressing: Start-Index negative.\nErrorcode: 10\n"); return(GetError(10));
					}
					for (copy_counter = 0; copy_counter < num_bytes_to_copy; copy_counter++) {
						if (bufferindex > (buffersize - 16)) {
							fprintf( stderr, "Error occured while decompressing: Running short on buffer space.\n");
							IncreaseBuffer(&outbuffer, &buffersize);
						}
						if (copy_start_index < 0) { // this shouldn't happen...it's a sort-of safety net
							fprintf( stderr, "Error occured while decompressing: Ended too early\nErrorcode: 30\n"); return(GetError(30));
						}
						else if ((copy_start_index + copy_counter) >= bufferindex) {
							fprintf( stderr, "Error occured while decompressing: The input seems to be telling us to copy uninitialized data.\nErrorcode: 40\n"); return(GetError(40));
						}
						else {
							outbuffer[bufferindex] = outbuffer[copy_start_index + copy_counter];
							bufferindex++;
						}
					} // <End copy loop>
				} // <End valid backwards offset>
			} // <End encoded data>
			else {
				outbuffer[bufferindex] = ibuffer[j]; j++;
				bufferindex++;
			} // <End literal data>
		} // <End looping through atoms for a given control word>
	} // <End looping through file>
	
	Result result;
	result.Buffer = outbuffer;
	result.Length = bufferindex;
	result.Error = 0;
	return result;
}

static int IncreaseBuffer(unsigned char **buffer, unsigned int *buffersize) {
	if(buffer == NULL || *buffer == NULL || buffersize == NULL) {
		fprintf( stderr, "Error: Invalid pointers passed when trying to increase buffer size!\n");
		return -1;
	}
	
	*buffersize = (*buffersize) + 32000;
	*buffer = realloc(*buffer, *buffersize);
	
	if (buffer == NULL) {
		fprintf( stderr, "Error: Unable to allocate memory.\n");
		return -1;
	} else {
		fprintf( stderr, "Successfully increased buffersize.\n");
		return 0;
	}
}

static unsigned long ReadArray( unsigned char *Source, unsigned char *Buffer, unsigned int Offset, unsigned int Size, unsigned int maxSize) {
	unsigned char i;
	for (i = 0 ; i < Size ; i++) {
		if ((Offset + i) > maxSize) return i;
		Buffer[i] = Source[Offset + i];
	}
	return (unsigned long)Size;
}

static Result GetError(int errorCode) {
	Result r;
	r.Error = errorCode;
	return r;
}
