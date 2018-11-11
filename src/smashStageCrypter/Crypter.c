#include <stdio.h>
#include <dirent.h>
#include <string.h> 
#include <stdlib.h>
#include "Crypter.h"


void wbe16(u8 *p, u16 x)
{
	p[0] = x >> 8;
	p[1] = x;
}

void wbe32(u8 *p, u32 x)
{
	wbe16(p, x >> 16);
	wbe16(p + 2, x);
}


//int main(int argc, char **argv) {
	/* CRC32 Test
	char* Test = "\xDE\xAD\xBE\xEF";
	printf("Checksum: 0x%08X", ComputeCRC32(Test, sizeof(Test))); // Must return 0x7C9CA35A
	exit(0);
	*/
	/*
	DecryptFile("st_080315_1829.bin", "st_Decrypted.bin");
	EncryptFile("st_Decrypted.bin", "st_Encrypted.bin");
	
	return 0;
}*/


/* ----------------------------------------------------------------------------------
	Decrypts a file and decompresses if necessary.
---------------------------------------------------------------------------------- */
void DecryptFile( const char* FileName, const char* OutputFilename) {
	FILE *Input;
	FILE *Output;
	
	Input = fopen( FileName, "rb");
	if (Input != NULL) {
		printf("Decrypting '%s' ...\n", FileName);
		
		// Decrypting file		
		Result r = DecFile( FileName );
		
		// Getting the decrypted and encrypted filesize
		u32 sizeDec = GetIntAt(r.Buffer, 24);
		u32 sizeEnc = GetIntAt(r.Buffer, 28);
		//printf("Decompressing file from %08x to %08x...\n", sizeDec, sizeEnc );
		sizeDec = SwapEndian(sizeDec);
		sizeEnc = SwapEndian(sizeEnc);
		
		// If the decrypted and encrypted filesize do not match,
		// it's compressed and needs to be uncompressed.
		if (sizeDec != sizeEnc) {
//			printf("Decompressing file from %08x to %08x...\n", sizeDec, sizeEnc );
			printf("compressed file starts with...\n" );
			r = Decompress(r);
		}
		
		// Padding
		u8 padding = (sizeDec % 16);
		if (padding > 0) {
			sizeDec += (16 - padding);
		}
		
		// Write filesize into buffer
		wbe32( r.Buffer + 24, sizeDec );
		wbe32( r.Buffer + 28, sizeDec );
		//WriteInt(r.Buffer, sizeDec, 24);
		//WriteInt(r.Buffer, sizeDec, 28);
		
		// Writes the output into a file.
		printf("decompressed file starts with...\n" );
		Output = fopen((const char*)OutputFilename, "wb");
		//fwrite(r.Buffer, 1, sizeDec, Output);				//originally this
		fwrite(r.Buffer, 1, r.Length, Output);				//switched to this to decrypt smash stack
		printf("rlen: %08x", r.Length );
		fclose(Output);
		printf("Done!\n\n");
	} else {
		printf("ERROR: Can't open %s!\n", FileName);
		exit(0);
	}
}


/* ----------------------------------------------------------------------------------
	Encrypts a file.
---------------------------------------------------------------------------------- */
void EncryptFile( const char*FileName, const char*OutputFilename) {
	FILE *Input;
	FILE *Output;
	u32 FileSize, BufferSize;
	u8* Buffer;
	
	Input = fopen( FileName, "rb");
	if (Input != NULL) {
		printf("Encrypting '%s' ...\n", FileName);
		
		// Obtain file size:
		fseek(Input , 0 , SEEK_END);
		FileSize = ftell(Input);
		rewind(Input);
		
		// Padding
		BufferSize = FileSize + 32;
		u8 padding = (FileSize % 16);
		if (padding > 0) {
			BufferSize += (16 - padding);
		}
		
		// Allocating buffer
		Buffer = (u8*)calloc(BufferSize, 1);
		fread(Buffer, 1, FileSize, Input);
		
		u32 DecSize = SwapEndian(GetIntAt(Buffer, 24));
		
		// Write filesize into buffer
		WriteInt(Buffer, DecSize, 24);
		WriteInt(Buffer, DecSize, 28);
		
		// Preparing & Calculating Checksum
		Buffer[16] = 0xDE; Buffer[17] = 0xAD; Buffer[18] = 0xBE; Buffer[19] = 0xEF;
		WriteInt(Buffer, ComputeCRC32(Buffer, DecSize + 32), 16);
		
		// Encrypting file
		Result input;
		input.Buffer = Buffer;
		input.Length = BufferSize;
		
		// Encrypt file (No compression required)
		Result r = EncFile(input);
		
		// Writes the output into a file.
		Output = fopen((const char*)OutputFilename, "wb");
		fwrite(r.Buffer, 1, DecSize + 32, Output);
		fclose(Output);
		printf("Done!\n");
	} else {
		printf("ERROR: Can't open %s!\n", FileName);
		exit(0);
	}
}

//calculate a checksum and encrypt a brawl stage
//len is including 0x20 for the header
void EncryptBuffer( char* in, char* out, u32 len )
{
	// Preparing & Calculating Checksum
	in[16] = 0xDE; in[17] = 0xAD; in[18] = 0xBE; in[19] = 0xEF;
	u32 checksum = ComputeCRC32( in, len );
	wbe32( in + 0x10, checksum );

	// Encrypting file
	Result input;
	input.Buffer = in;
	input.Length = len;

	// Encrypt file
	Result r = EncFile( input );

	//copy to outbuf
	memcpy( out, r.Buffer, len );
}

/* ----------------------------------------------------------------------------------
	Writes an integer with a custom length into a buffer at a specified position.
---------------------------------------------------------------------------------- */
void WriteInt(u8 *Buffer, u32 Value, u32 Offset ) {
	u8 i, x, size;
	size = sizeof(Value);
	
	for (i = 0; i < size; i++) {
		x = Value & 0xFF;
		Buffer[size-i-1+Offset] = x;
		Value = Value >> 8;
	}
	//printf("Output: 0x%02X%02X%02X%02X", Buffer[Offset], Buffer[Offset+1], Buffer[Offset+2], Buffer[Offset+3]);
}


/* ----------------------------------------------------------------------------------
	Calculates the CRC32 hash of a specified buffer using a premade lookup table.
---------------------------------------------------------------------------------- */
u32 ComputeCRC32(u8 *Buffer, u16 Size) {
	u32 CRC = 0xFFFFFFFF;
	u32 i = 0;
	for (i = 0; i < Size; i++) {
		CRC = (CRC >> 8) ^ CRC32Table[((Buffer[i] ^ CRC) & 0xFF)];
	}
	return ~CRC;
}

/* ----------------------------------------------------------------------------------
	Gets an unsigned integer from a buffer at a specified position.
---------------------------------------------------------------------------------- */
u32 GetIntAt(u8* buffer, u32 position) {
	return *((u32*)(((u8*)buffer)+position));
}


/* ----------------------------------------------------------------------------------
	Swaps the endian of an unsigned integer.
---------------------------------------------------------------------------------- */
u32 SwapEndian(u32 value) {
	//return (value >> 24) | ((value << 8) & 0x00FF0000) | ((value >> 8) & 0x0000FF00) | (value << 24);
	return ((value >> 24) & 0xff) | ((value >> 8) & 0xFF00) | ((value << 8) & 0xFF0000) | ((value << 24) & 0xff000000);
}
