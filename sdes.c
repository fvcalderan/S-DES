/*
 * BSD 3-Clause License
 * Copyright (c) 2021, fvcalderan
 * All rights reserved.
 * See the full license text inside the LICENSE file.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* Data Types ============================================================== */

typedef uint32_t int2b;
typedef uint32_t int4b;
typedef uint32_t int5b;
typedef uint32_t int8b;
typedef uint32_t int10b;
typedef struct {int2b left; int2b right;} pair2b;
typedef struct {int4b left; int4b right;} pair4b;
typedef struct {int5b left; int5b right;} pair5b;

/* Aux Functions =========================================================== */

pair5b ten2five(int10b n)
{
    return (pair5b){.left = (n & 0b1111100000) >> 5, .right = n & 0b0000011111};
}

pair4b eight2four(int8b n)
{
    return (pair4b){.left = (n & 0b11110000) >> 4, .right = n & 0b00001111};
}

int10b five2ten(pair5b n)   { return n.right + (n.left << 5); }
int8b  four2eight(pair4b n) { return n.right + (n.left << 4); }
int4b  two2four(pair2b n)   { return n.right + (n.left << 2); }

uint32_t *int2arr(uint32_t n, uint32_t size)
{
    uint32_t *out = malloc(size * sizeof(int));
    uint32_t mask = 1U << (size-1);

    for (uint32_t i = 0; i < size; i++) {
        out[i] = (n & mask) > 0;
        n <<= 1;
    }

    return out;
}

uint32_t arr2int(uint32_t *arr, uint32_t size)
{
    uint32_t out = 0;
    uint32_t exponent = size - 1;

    for (uint32_t i = size; i > 0; i--) {
        uint32_t power = 1;
        for (uint32_t j = 1; j < i; j++) power *= 2;
        out += arr[size-i] * power;
    }
    return out;
}

void usage_message(char **argv) {
    printf("\n\tEncrypt: %s -e path/to/input path/to/output\n", argv[0]);
    printf("\tDecrypt: %s -d path/to/input path/to/output\n\n", argv[0]);
    exit(0);
}

/* Encryption Functions ==================================================== */

int4b P4(pair2b keys)
{
    /* Permutate: 1 2 3 4 -> 2 4 3 1 */
    uint32_t *a = int2arr(two2four(keys), 4), b[4];
    b[3] = a[0]; b[0] = a[1]; b[2] = a[2]; b[1] = a[3];
    free(a);
    return arr2int(b, 4);
}

int8b P8(pair5b keys)
{
    /* Select and Permutate: 1 2 3 4 5 6 7 8 9 10 -> 6 3 7 4 8 5 10 9 */
    uint32_t *a = int2arr(five2ten(keys), 10), b[10];
    b[1] = a[2]; b[3] = a[3]; b[5] = a[4]; b[0] = a[5];
    b[2] = a[6]; b[4] = a[7]; b[7] = a[8]; b[6] = a[9];
    free(a);
    return arr2int(b, 8);
}

pair5b P10(int10b key)
{
    /* Permutate: 1 2 3 4 5 6 7 8 9 10 -> 3 5 2 7 4 10 1 9 8 6 */
    uint32_t *a = int2arr(key, 10), b[10];
    b[6] = a[0]; b[2] = a[1]; b[0] = a[2]; b[4] = a[3]; b[1] = a[4];
    b[9] = a[5]; b[3] = a[6]; b[8] = a[7]; b[7] = a[8]; b[5] = a[9];
    free(a);
    return ten2five(arr2int(b, 10));
}

pair4b IP(int8b value)
{
    /* Permutate: 1 2 3 4 5 6 7 8 -> 2 6 3 1 4 8 5 7 */
    uint32_t *a = int2arr(value, 8), b[8];
    b[3] = a[0]; b[0] = a[1]; b[2] = a[2]; b[4] = a[3];
    b[6] = a[4]; b[1] = a[5]; b[7] = a[6]; b[5] = a[7];
    free(a);
    return eight2four(arr2int(b, 8));
}

int8b EP(int4b value)
{
    /* Expand and Permutate: 1 2 3 4 -> 4 1 2 3 2 3 4 1 */
    uint32_t *a = int2arr(value, 4), b[8];
    b[0] = a[3]; b[1] = a[0]; b[2] = a[1]; b[3] = a[2];
    b[4] = a[1]; b[5] = a[2]; b[6] = a[3]; b[7] = a[0];
    free(a);
    return arr2int(b, 8);
}

/* Round Left Shifts */
int5b LS1(int5b key) { return ((key << 1) | (key >> (5 - 1))) & 0b11111; }
int5b LS2(int5b key) { return ((key << 2) | (key >> (5 - 2))) & 0b11111; }

int8b *generate_keys(int10b input_key)
{
    /* Generate keys K1 and K2 */
    pair5b p10out = P10(input_key);
    p10out.left  = LS1(p10out.left);
    p10out.right = LS1(p10out.right);
    int8b K1 = P8(p10out);
    pair5b p10out_LS2 = {.left = LS2(p10out.left), .right = LS2(p10out.right)};
    int8b K2 = P8(p10out_LS2);
    int8b *keys = malloc(2 * sizeof(int8b));
    keys[0] = K1;
    keys[1] = K2;
    return keys;
}

int2b S(int4b value, uint32_t box)
{
    /* S-boxes */
    uint32_t m[2][4][4] = {
        {
            {0b01, 0b00, 0b11, 0b10},
            {0b11, 0b10, 0b01, 0b00},
            {0b00, 0b10, 0b01, 0b11},
            {0b11, 0b01, 0b11, 0b10}
        },
        {
            {0b00, 0b01, 0b10, 0b11},
            {0b10, 0b00, 0b01, 0b11},
            {0b11, 0b00, 0b01, 0b00},
            {0b10, 0b01, 0b00, 0b11}
        }
    };

    uint32_t *value_arr = int2arr(value, 4);
    uint32_t row_arr[2] = {value_arr[0], value_arr[3]};
    uint32_t col_arr[2] = {value_arr[1], value_arr[2]};

    free(value_arr);
    return m[box][arr2int(row_arr, 2)][arr2int(col_arr, 2)];
}

pair4b fk(pair4b IP_out, int8b key)
{
    /* Process text for encryption/decryption */
    int8b EPr_out = EP(IP_out.right);
    int8b EPxK1 = EPr_out ^ key;
    pair4b EPxK1_out = eight2four(EPxK1);
    int2b S0_out = S(EPxK1_out.left, 0);
    int2b S1_out = S(EPxK1_out.right, 1);
    int4b P4_out = P4((pair2b){.left=S0_out, .right=S1_out});
    int4b P4xIP = P4_out ^ IP_out.left;
    return (pair4b){.left=P4xIP, .right=IP_out.right};
}

/* switch left and right items from a pair */
pair4b switch_(pair4b keys) { return (pair4b){keys.right, keys.left}; }

int8b IP_inv(pair4b keys)
{
    /* Permutate: 1 2 3 4 5 6 7 8 -> 4 1 3 5 7 2 8 6 */
    uint32_t *a = int2arr(four2eight(keys), 8), b[8];
    b[0] = a[3]; b[1] = a[0]; b[2] = a[2]; b[3] = a[4];
    b[4] = a[6]; b[5] = a[1]; b[6] = a[7]; b[7] = a[5];
    free(a);
    return arr2int(b, 8);
}

/* Main Functions ========================================================== */

int8b S_DES(int10b input_key, int8b plain, bool decipher)
{
    /* Simplified Data Encryption Standard (S-DES) */
    int8b *keys = generate_keys(input_key);
    pair4b IP_out = IP(plain);
    pair4b first_round = fk(IP_out, keys[decipher]);
    pair4b first_round_swap = switch_(first_round);
    pair4b second_round = fk(first_round_swap, keys[!decipher]);
    int8b cipher = IP_inv(second_round);
    free(keys);
    return cipher;
}

int32_t main(int argc, char **argv)
{
    /* check number of args */
    if (argc != 4) usage_message(argv);

    /* get mode (encrypt or decrypt) */
    int mode;
    if      (!strcmp(argv[1], "-e")) mode = 0;
    else if (!strcmp(argv[1], "-d")) mode = 1;
    else    usage_message(argv);

    /* get encryption key (and treat wrong input) */
    char in_key_raw[1024], *in_key_p;
    uint32_t in_key = 1024;
    printf("Type the key (integer from 0 to 1023): ");
    while (fgets(in_key_raw, sizeof(in_key_raw), stdin)) {
        in_key = strtol(in_key_raw, &in_key_p, 10);
        if (in_key_p == in_key_raw || *in_key_p != '\n' || in_key > 1023) {
            printf("Type the key (integer from 0 to 1023): ");
        } else {
            break;
        }
    }

    /* open (if possible) input and output files */
    FILE *input_file, *output_file;
    input_file = fopen(argv[2], "rb");
    output_file = fopen(argv[3], "wb");

    if (input_file == NULL) {
        printf("Cannot open file %s\n", argv[2]);
        exit(0);
    }
    if (output_file == NULL) {
        printf("Cannot open file %s\n", argv[3]);
        exit(0);
    }

    /* read-encrypt/decrypt-write loop */
    char c;
    while ((c = getc(input_file)) != EOF)
        fputc(S_DES(in_key, c, mode), output_file);

    /* close everything and return */
    fclose(input_file);
    fclose(output_file);
    return 0;
}
