//
//  aes.h
//  AES
//
//  Created by Zach Brogan on 9/18/17.
//  Copyright © 2017 Zach Brogan. All rights reserved.
//

#ifndef aes_h
#define aes_h

#include <stdio.h>
#include <stdint.h>

#define NB 4 // 128-bit (4 word) blocks
#define NK (keySize/32) // key size in words
#define NR (NK + 6) // Number of rounds

extern uint16_t keySize; // key size in bits

/*** STRING HELPER FUNCTIONS ***/
char* ByteArrayToString(uint8_t block[], uint16_t size, char* string);
char* StateToString(uint8_t state[4][NB], char* string);
uint32_t word(uint8_t bytearray[4]);

/*** FINITE FIELD ARITHMETIC ***/
// Add two finite fields
uint8_t ffAdd(uint8_t a, uint8_t b);
// Multiplies a finite field by x
uint8_t xtime(uint8_t a);
// Uses xtime to multiply any finite field by any other finite field
uint8_t ffMultiply(uint8_t a, uint8_t b);

/*** KEY EXPANSION ***/
void expandKey(uint8_t key[], uint32_t expandedKey[]);
// takes a four-byte input word and substitutes each byte in that word with its appropriate value from the S-Box
void subWord(uint32_t *in);
// performs a cyclic permutation on its input word
void rotWord(uint32_t *in);

/*** CIPHER and INVERSE CIPHER ***/
// Encrypt a single block (16 bytes) using AES and a 128, 194, or 256 bit key
void aesEncrypt(uint8_t in[16], uint8_t out[16], uint16_t key_size, uint8_t key[key_size/8]);
// Decrypt a single block (16 bytes) using AES and a 128, 194, or 256 bit key
void aesDecrypt(uint8_t in[16], uint8_t out[16], uint16_t key_size, uint8_t key[key_size/8]);
void cipher(uint8_t in[4 * NB], uint8_t out[4 * NB], uint32_t key[NB * (1)]);
void invCipher(uint8_t in[4 * NB], uint8_t out[4 * NB], uint32_t key[NB * (NR + 1)]);
// Substitutes each byte in the State with its corresponding value from the S-Box
void subBytes(uint8_t state[4][NB]);
// Performs a circular shift on each row in the State
void shiftRows(uint8_t state[4][NB]);
// Treats each column in state as a four-term polynomial, multiplied (modulo another polynomial) by a fixed polynomial with coefficients
void mixColumns(uint8_t state[4][NB]);
// This transformation adds a round key to the State using XOR.
void addRoundKey(uint8_t state[4][NB], uint32_t roundKey[NB]);
// Substitutes each byte in the State with its corresponding value from the inverse S-Box, thus reversing the effect of a subBytes() operation.
void invSubBytes(uint8_t state[4][NB]);
// This transformation performs the inverse of shiftRows() on each row in the State
void invShiftRows(uint8_t state[4][NB]);
// This transformation is the inverse of mixColumns
void invMixColumns(uint8_t state[4][NB]);

#endif /* aes_h */
