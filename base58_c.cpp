/*
 * Copyright 2012-2014 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 
 2017-2024 by Alex Neudatchin
 
 */



#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include "libbase58.h"
#include <algorithm>
#include <memory>

bool (*b58_sha256_impl)(void *, const void *, size_t) = NULL;

static const int8_t b58digits_map[128] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};


bool b58tobin(void *bin /* out */ , size_t *binszp /* in - out */ , const char *b58 /* in */ , size_t b58sz /* in */ )
{
	size_t binsz = *binszp;
	const unsigned char *b58u = (const unsigned char *)b58;
	unsigned char *binu = (unsigned char *)bin;
	size_t outsz = (binsz + 3) / 4;
	 shared_ptr<uint32_t[]> out(new uint32_t[outsz]());
	uint64_t t;
	uint32_t c;
	size_t i, j;
	uint8_t bytesleft = binsz % 4;
	uint32_t zeromask = bytesleft == 0 ? 0 : (0xffffffff << (bytesleft * 8));
	unsigned int zerocount = 0;
	
	if (!b58sz)
		b58sz = strlen(b58);
	
	// Leading zeros, just count
	for (i = 0; i < b58sz && b58u[i] == '1'; i++)
		zerocount++;
	
	for ( ; i < b58sz; i++)
	{
		if (b58u[i] & 0x80)
		{
			// High-bit set on invalid digit
			return false;
		}
		if (b58digits_map[b58u[i]] == -1)
		{
			// Invalid base58 digit
			return false;
		}
		c = (unsigned short)b58digits_map[b58u[i]];
		for (j = outsz - 1; j + 1 > 0; j--)     
		{
			t = out[j] * 58ULL + c;
			c = (t  >> 32) & 0x3fULL;
			out[j] = t & 0xffffffffULL;
		}
		if (c)
		{
			// Output number too big (carry to the next int32)
			return false;
		}
		if (out[0] & zeromask)
		{
			// Output number too big (last int32 filled too far)
			return false;
		}
	}
	
	j = 0;
	switch (bytesleft) 
	{
		case 3:
			*(binu++) = *((uint8_t*)&out[0] + 2);
			/* Fall Through */ 
		case 2:
			*(binu++) = *((uint8_t*)&out[0] + 1);
			/* Fall Through */ 
		case 1:
			*(binu++) = *(uint8_t*)&out[0];
			j++;
			break;
		default:
			break;
	}
	
	for (; j < outsz; j++)
	{
		std::reverse((char *)(&out[0] + j), (char *)(&out[0] + j) + 4);
		*(uint32_t *)binu =  out[j];
		binu = binu + 4;
	}
	//size of the result binary,modified that way that the number of leading zeroes in it replaced by the count of leading '1' symbols in given string.
	binu = (unsigned char *)bin;
	for (i = 0; i < binsz; i++)
	{
		if (binu[i])
			break;
		(*binszp)--;
	}
	*binszp = *binszp + zerocount;
	
	return !false;
}
static const char b58digits_ordered[59] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool b58enc(char* b58 /* out */ ,  size_t *b58sz /* in - out */ , const void *data /* in */ , size_t binsz /* in */ )
{
	const uint8_t *bin = (const uint8_t *)data;
	int carry;
	long i, j, high, zcount = 0;	
	while (zcount < binsz && !bin[zcount])
		zcount++;
	const unsigned int size = (binsz - zcount) * 138 / 100 + 1; //latter is a smth like a logarithm of 256 to base 58 , but not exactly.
std::shared_ptr<unsigned char[]> buf(new unsigned char[size]());
	high = size - 1;
	for (i = zcount; i < binsz; i++)
	{
		carry = bin[i];	j = size - 1;
		while( carry || j > high )
		{
			carry = carry + 256 * buf[j];
			buf[j--] = carry % 58;  //as you all know 'int fifty_cent() { int j = 0; return j-- ; }' has a zero value      
			carry /= 58;
		}
		high = j;
	}
	
	for (j = 0; j < size && !buf[j]; j++);
	
	if (*b58sz < zcount + size - j + 1)
	{
		*b58sz = zcount + size - j + 1;
		return false;
	}

	if (zcount)
		memset(b58, '1', zcount);

	for (i = zcount; j < size; i++, j++)
		b58[i] = b58digits_ordered[buf[j]];

	b58[i] = '\0';
	*b58sz = i + 1;
	return !false;
}
