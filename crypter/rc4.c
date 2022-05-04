#include "rc4.h"

unsigned char get_key_byte(long key, int i) {
    i = i % KEY_LEN;
    unsigned char offset = 64 - ((i + 1) * 8);
    return (key >> offset) & 0xFF;
}

void swap(unsigned char* arr, int i1, int i2) {
    unsigned char tmp = arr[i1];
    arr[i1] = arr[i2];
    arr[i2] = tmp;
}

void KSA(unsigned char* S, long key) {
    for (int i = 0; i < SCHEDULE_LEN; i++) {
        S[i] = i;
    }

    int j = 0;
    for (int i = 0; i < SCHEDULE_LEN; i++) {
        j = (j + S[i] + get_key_byte(key, i)) % SCHEDULE_LEN;
        swap(S, i, j);
    }
}

void PRGA(unsigned char* buffer, long buffer_len, unsigned char* S) {
    int i = 0, j = 0;

    for (long n = 0; n < buffer_len; n++) {
        i = (i + 1) % SCHEDULE_LEN;
        j = (j + S[i]) % SCHEDULE_LEN;

        swap(S, i, j);
        unsigned char rnd = S[(S[i] + S[j]) % SCHEDULE_LEN];
        buffer[n] = rnd ^ buffer[n];
    }
}

void crypt_rc4(void* buffer, long buffer_len, long key) {
    unsigned char S[SCHEDULE_LEN];

    KSA(S, key);
    PRGA(buffer, buffer_len, S);
}