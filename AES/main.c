//
//  main.c
//  AES
//
//  Created by Zach Brogan on 9/18/17.
//  Copyright © 2017 Zach Brogan. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include "aes.h"

// Tests AES encryption for 128, 194, and 256 bit keys
int main(int argc, const char * argv[]) {
    uint8_t in[] ={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t out[16];
    uint8_t key128[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t key192[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17};
    uint8_t key256[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    
    char string[100];
    
    /**** TEST 128 bit encryption ****/
    printf("\nTesting AES-128\n");
    printf("---Encryption---\n");
    printf("PLAINTEXT: %s\n",ByteArrayToString(in, 16, string));
    printf("KEY: %s\n",ByteArrayToString(key128, 16, string));
    aesEncrypt(in, out, 128, key128);
    printf("---Decryption---\n");
    aesDecrypt(out, in, 128, key128);
    
    /**** TEST 192 bit encryption ****/
    printf("\nTesting AES-192\n");
    printf("---Encryption---\n");
    printf("PLAINTEXT: %s\n",ByteArrayToString(in, 16, string));
    printf("KEY: %s\n",ByteArrayToString(key192, 24, string));
    aesEncrypt(in, out, 192, key192);
    printf("---Decryption---\n");
    aesDecrypt(out, in, 192, key192);
    
    /**** TEST 256 bit encryption ****/
    printf("\nTesting AES-256\n");
    printf("---Encryption---\n");
    printf("PLAINTEXT: %s\n",ByteArrayToString(in, 16, string));
    printf("KEY: %s\n",ByteArrayToString(key256, 32, string));
    aesEncrypt(in, out, 256, key256);
    printf("---Decryption---\n");
    aesDecrypt(out, in, 256, key256);
    
    return 0;
}
