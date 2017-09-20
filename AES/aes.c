//
//  aes.c
//  AES
//
//  Created by Zach Brogan on 9/18/17.
//  Copyright © 2017 Zach Brogan. All rights reserved.
//

#include "aes.h"

#define MSB_MASK 0x80
#define IRRED_POLY_MASK 0x1b

const uint32_t Rcon[] = { 0x00000000, // Rcon[] is 1-based, so the first entry is just a place holder
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000, 0x6C000000, 0xD8000000,
    0xAB000000, 0x4D000000, 0x9A000000, 0x2F000000,
    0x5E000000, 0xBC000000, 0x63000000, 0xC6000000,
    0x97000000, 0x35000000, 0x6A000000, 0xD4000000,
    0xB3000000, 0x7D000000, 0xFA000000, 0xEF000000,
    0xC5000000, 0x91000000, 0x39000000, 0x72000000,
    0xE4000000, 0xD3000000, 0xBD000000, 0x61000000,
    0xC2000000, 0x9F000000, 0x25000000, 0x4A000000,
    0x94000000, 0x33000000, 0x66000000, 0xCC000000,
    0x83000000, 0x1D000000, 0x3A000000, 0x74000000,
    0xE8000000, 0xCB000000, 0x8D000000};

const uint8_t Sbox[16][16] = {
    { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 } ,
    { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 } ,
    { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 } ,
    { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 } ,
    { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 } ,
    { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf } ,
    { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 } ,
    { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 } ,
    { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 } ,
    { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb } ,
    { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 } ,
    { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 } ,
    { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a } ,
    { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e } ,
    { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf } ,
    { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
};

const uint8_t InvSbox[16][16] = {
    { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb } ,
    { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb } ,
    { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e } ,
    { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 } ,
    { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 } ,
    { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 } ,
    { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 } ,
    { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b } ,
    { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 } ,
    { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e } ,
    { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b } ,
    { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 } ,
    { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f } ,
    { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef } ,
    { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 } ,
    { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
};

uint16_t keySize = 128; // key size in bits

 /*** HELPER FUNCTIONS ***/
//Convert a byte array into a word
uint32_t word(uint8_t bytearray[4]) {
    uint32_t word = 0;
    for(uint8_t i = 0; i < 4; i++) {
        word = word | (bytearray[i] << (8 * (3-i)));
    }
    return word;
}

char* ByteArrayToString(uint8_t block[], uint16_t size, char* string) {
    uint8_t i;
    for(i = 0; i < size; i++) {
        sprintf(string+(2*i), "%02x", block[i]);
    }
    return string;
}

char* StateToString(uint8_t state[4][NB], char* string) {
    uint8_t i = 0;
    uint8_t j = 0;
    for(i = 0; i < NB; i++) {
        for(j = 0; j < 4; j++) {
            sprintf(string+(8*i+2*j), "%02x", state[j][i]);
        }
    }
    sprintf(string + (8*i+2*j),"\n");
    return string;
}

void printState(uint8_t round, char* routine, uint8_t state[4][NB]) {
    char string[100];
    printf("round[%02d].%s    %s\n", round, routine, StateToString(state, string));
}

void printKeySchedule(uint8_t round, uint32_t keySchedule[NB]) {
    printf("round[%02d].k_sch     ", round);
    for(uint8_t i = 0; i < NB; i++) {
        printf("%08x", keySchedule[i]);
    }
    printf("\n");
}

/*** FINITE FIELD ARITHMETIC ***/
// Add two finite fields
uint8_t ffAdd(uint8_t a, uint8_t b) {
    return a ^ b;
}

// Multiplies a finite field by x
uint8_t xtime(uint8_t a) {
    if(!(a & MSB_MASK)) {
        return a << 1;
    }
    else {
        return (a << 1) ^ IRRED_POLY_MASK;
    }
}

// Uses xtime to multiply any finite field by any other finite field
uint8_t ffMultiply(uint8_t a, uint8_t b) {
    uint8_t c = 0;
    uint8_t b_x[8];
    b_x[0] = b;
    for(uint8_t i = 1; i < 8; i++) {
        b_x[i] = xtime(b_x[i-1]);
    }
    
    for(uint8_t i = 0; i < 8; i++) {
        if(a & (0x01 << i)) {
            c = c ^ b_x[i];
        }
    }
    
    return c;
}

/*** KEY EXPANSION ***/
void expandKey(uint8_t key[4*NK], uint32_t expandedKey[NB*(NR+1)]) {
    uint32_t temp;
    uint8_t i;
    
    for(i = 0; i < NK; i++) {
        expandedKey[i] = word(key + (4 * i));
    }
    
    for(i = NK; i < NB * (NR+1); i++) {
        temp = expandedKey[i-1];
        if (i % NK == 0) {
            rotWord(&temp);
            subWord(&temp);
            temp = temp ^ Rcon[i/NK];
        }
        else if (NK > 6 && i % NK == 4) {
            subWord(&temp);
        }
        expandedKey[i] = expandedKey[i-NK] ^ temp;
    }
}

// takes a four-byte input word and substitutes each byte in that word with its appropriate value from the S-Box
void subWord(uint32_t *in) {
    uint8_t temp[4];
    for(uint8_t i = 0; i < 4; i++) {
        temp[i] = (*in >> (3-i) * 8) & 0xFF;
        temp[i] = Sbox[temp[i] >> 4][temp[i] & 0x0F];
    }
    *in = word(temp);
}

// performs a cyclic permutation on its input word
void rotWord(uint32_t *in) {
    *in = ((*in & 0xFF000000) >> 24) | (*in << 8);
}

/*** CIPHER and INVERSE CIPHER ***/
// Encrypt a single block (16 bytes) using AES and a 128, 194, or 256 bit key
void aesEncrypt(uint8_t in[16], uint8_t out[16], uint16_t key_size, uint8_t key[key_size/8]) {
    // Check valid inputs
    if(key_size != 128 && key_size != 194 && key_size != 256) {
        return;
    }
    keySize = key_size;
    uint32_t expandedKey[NB*(NR+1)];
    expandKey(key, expandedKey);
    cipher(in, out, expandedKey);
}

// Decrypt a single block (16 bytes) using AES and a 128, 194, or 256 bit key
void aesDecrypt(uint8_t in[16], uint8_t out[16], uint16_t key_size, uint8_t key[key_size/8]) {
    // Check valid inputs
    if(key_size != 128 && key_size != 194 && key_size != 256) {
        return;
    }
    keySize = key_size;
    uint32_t expandedKey[NB*(NR+1)];
    expandKey(key, expandedKey);
    invCipher(in, out, expandedKey);
}

void cipher(uint8_t in[4 * NB], uint8_t out[4 * NB], uint32_t key[NB * (NR + 1)]) {
    uint8_t state[4][NB];
    for(uint8_t i = 0; i < NB; i++) {
        for(uint8_t j = 0; j < 4; j++) {
            state[j][i] = in[4*i + j];
        }
    }
    uint8_t round = 0;
    printState(round, "input ", state);
    addRoundKey(state, key);
    printKeySchedule(round, key);
    for(round = 1; round < NR; round++) {
        printState(round, "start ", state);
        subBytes(state);
        printState(round, "s_box ", state);
        shiftRows(state);
        printState(round, "s_row ", state);
        mixColumns(state);
        printState(round, "m_col ", state);
        addRoundKey(state, key + round*NB);
        printKeySchedule(round, key + round*NB);
    }
    printState(round, "start ", state);
    subBytes(state);
    printState(round, "s_box ", state);
    shiftRows(state);
    printState(round, "s_row ", state);
    addRoundKey(state, key + NB * NR);
    printKeySchedule(round, key + NB * NR);
    printState(round, "out   ", state);
    
    for(uint8_t i = 0; i < NB; i++) {
        for(uint8_t j = 0; j < 4; j++) {
            out[4*i + j] = state[j][i];
        }
    }
}

void invCipher(uint8_t in[4 * NB], uint8_t out[4 * NB], uint32_t key[NB * (NR + 1)]) {
    uint8_t state[4][NB];
    for(uint8_t i = 0; i < NB; i++) {
        for(uint8_t j = 0; j < 4; j++) {
            state[j][i] = in[4*i + j];
        }
    }
    uint8_t round = NR;
    printState(round, "iinput", state);
    addRoundKey(state, key + NB * NR);
    printKeySchedule(round, key);
    for(round = NR - 1; round > 0; round--) {
        printState(round, "istart", state);
        invShiftRows(state);
        printState(round, "is_row", state);
        invSubBytes(state);
        printState(round, "is_box", state);
        addRoundKey(state, key + round*NB);
        printKeySchedule(round, key + round*NB);
        invMixColumns(state); // See Sec. 5.3.3
        printState(round, "im_col", state);
        
    }
    printState(round, "istart", state);
    invShiftRows(state);
    printState(round, "is_row", state);
    invSubBytes(state);
    printState(round, "is_box", state);
    addRoundKey(state, key);
    printKeySchedule(round, key + NB * NR);
    printState(round, "iout  ", state);
    
    for(uint8_t i = 0; i < NB; i++) {
        for(uint8_t j = 0; j < 4; j++) {
            out[4*i + j] = state[j][i];
        }
    }
}

// Substitutes each byte in the State with its corresponding value from the S-Box
void subBytes(uint8_t state[4][NB]) {
    for(uint8_t i = 0; i < NB; i++) {
        for(uint8_t j = 0; j < 4; j++) {
            state[j][i] = Sbox[state[j][i] >> 4][state[j][i] & 0x0F];
        }
    }
}
// Performs a circular shift on each row in the State
void shiftRows(uint8_t state[4][NB]) {
    //Row 1 does not shift (state[0]
    for(uint8_t j = 1; j < 4; j++) {
        uint8_t temp;
        if(j == 1) {
            temp = state[j][0];
            state[j][0] = state[j][1];
            state[j][1] = state[j][2];
            state[j][2] = state[j][3];
            state[j][3] = temp;
        }
        else if(j == 2) {
            temp = state[j][0];
            uint8_t temp2 = state[j][1];
            state[j][0] = state[j][2];
            state[j][1] = state[j][3];
            state[j][2] = temp;
            state[j][3] = temp2;
        }
        else if(j == 3) {
            temp = state[j][0];
            state[j][0] = state[j][3];
            state[j][3] = state[j][2];
            state[j][2] = state[j][1];
            state[j][1] = temp;
        }
    }
}
// Treats each column in state as a four-term polynomial, multiplied (modulo another polynomial) by a fixed polynomial with coefficients
void mixColumns(uint8_t state[4][NB]) {
    uint8_t newState[4][NB];
    for(uint8_t i = 0; i < NB; i++) {
        newState[0][i] = ffMultiply(0x02, state[0][i])
        ^ ffMultiply(0x03, state[1][i])
        ^ state[2][i]
        ^ state[3][i];
        
        newState[1][i] = state[0][i]
        ^ ffMultiply(0x02, state[1][i])
        ^ ffMultiply(0x03, state[2][i])
        ^ state[3][i];
        
        newState[2][i] = state[0][i]
        ^ state[1][i]
        ^ ffMultiply(0x02, state[2][i])
        ^ ffMultiply(0x03, state[3][i]);
        
        newState[3][i] = ffMultiply(0x03, state[0][i])
        ^ state[1][i]
        ^ state[2][i]
        ^ ffMultiply(0x02, state[3][i]);
    }
    
    for(uint8_t i = 0; i < NB; i++) {
        for(uint8_t j = 0; j < 4; j++) {
            state[j][i] = newState[j][i];
        }
    }
}

// This transformation adds a round key to the State using XOR.
void addRoundKey(uint8_t state[4][NB], uint32_t roundKey[NB]) {
    for(uint8_t i = 0; i < NB; i++) {
        for(uint8_t j = 0; j < 4; j++) {
            state[j][i] ^= (roundKey[i] >> (8*(3-j))) & 0xFF;
        }
    }
}

// Substitutes each byte in the State with its corresponding value from the inverse S-Box, thus reversing the effect of a subBytes() operation.
void invSubBytes(uint8_t state[4][NB]) {
    for(uint8_t i = 0; i < NB; i++) {
        for(uint8_t j = 0; j < 4; j++) {
            state[j][i] = InvSbox[state[j][i] >> 4][state[j][i] & 0x0F];
        }
    }
}

// This transformation performs the inverse of shiftRows() on each row in the State
void invShiftRows(uint8_t state[4][NB]) {
    //Row 1 does not shift (state[0]
    for(uint8_t j = 1; j < 4; j++) {
        uint8_t temp;
        if(j == 1) {
            temp = state[j][0];
            state[j][0] = state[j][3];
            state[j][3] = state[j][2];
            state[j][2] = state[j][1];
            state[j][1] = temp;
        }
        else if(j == 2) {
            temp = state[j][0];
            uint8_t temp2 = state[j][1];
            state[j][0] = state[j][2];
            state[j][1] = state[j][3];
            state[j][2] = temp;
            state[j][3] = temp2;
        }
        else if(j == 3) {
            temp = state[j][0];
            state[j][0] = state[j][1];
            state[j][1] = state[j][2];
            state[j][2] = state[j][3];
            state[j][3] = temp;
        }
    }
    
}

// This transformation is the inverse of mixColumns
void invMixColumns(uint8_t state[4][NB]) {
    uint8_t newState[4][NB];
    for(uint8_t i = 0; i < NB; i++) {
        newState[0][i] = ffMultiply(0x0e, state[0][i])
        ^ ffMultiply(0x0b, state[1][i])
        ^ ffMultiply(0x0d, state[2][i])
        ^ ffMultiply(0x09, state[3][i]);
        
        newState[1][i] = ffMultiply(0x09, state[0][i])
        ^ ffMultiply(0x0e, state[1][i])
        ^ ffMultiply(0x0b, state[2][i])
        ^ ffMultiply(0x0d, state[3][i]);
        
        newState[2][i] = ffMultiply(0x0d, state[0][i])
        ^ ffMultiply(0x09, state[1][i])
        ^ ffMultiply(0x0e, state[2][i])
        ^ ffMultiply(0x0b, state[3][i]);
        
        newState[3][i] = ffMultiply(0x0b, state[0][i])
        ^ ffMultiply(0x0d, state[1][i])
        ^ ffMultiply(0x09, state[2][i])
        ^ ffMultiply(0x0e, state[3][i]);
    }
    
    for(uint8_t i = 0; i < NB; i++) {
        for(uint8_t j = 0; j < 4; j++) {
            state[j][i] = newState[j][i];
        }
    }
}
