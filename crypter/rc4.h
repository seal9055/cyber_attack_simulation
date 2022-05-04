#ifndef RC4_H
#define RC4_H

#include <stdio.h>
#include <stdlib.h>

// Size of key schedule for RC4, in bytes
#define SCHEDULE_LEN 256

// Size of key for RC4, in bytes
#define KEY_LEN 8

/*
 * RC4 Implementation based off of https://gist.github.com/rverton/a44fc8ca67ab9ec32089
 */


/**
 * @brief Gets the byte at a certain index from the key
 * 
 * @param key 64-bit key to get byte from
 * @param i Index of byte. 0 is MSB, 7 is LSB
 * @return unsigned char 
 */
unsigned char get_key_byte(long key, int i);

/**
 * @brief Swaps the position of two values in an array
 * 
 * @param arr array to swap values
 * @param i1 first value to swap
 * @param i2 second value to swap
 */
void swap(unsigned char* arr, int i1, int i2);

/**
 * @brief RC4 Key scheduling algortihm
 * 
 * @param S 256-byte buffer to write key schedule to
 * @param key 64-bit key to create key schedule with
 */
void KSA(unsigned char* S, long key);

/**
 * @brief RC4 Psuedo-random generation algorithm, crypts buffer with given key schedule
 * 
 * @param buffer buffer to crypt
 * @param buffer_len size of buffer to crypt
 * @param S 256-byte key schedule to use for crypting
 */
void PRGA(unsigned char* buffer, long buffer_len, unsigned char* S);

/**
 * @brief Encrypts/decrypts a given buffer with RC4 using the given key
 * 
 * @param buffer buffer to crypt
 * @param buffer_len size of buffer to crypt
 * @param key 64-bit key to crypt with
 */
void crypt_rc4(void* buffer, long buffer_len, long key);

#endif // RC4_H