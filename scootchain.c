// scootchain.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

//#define KEY_TYPE "ML-DSA-44"
#define KEY_TYPE "ML-DSA-87"
#define PRIVKEY_FILE "scootchain_sk.bin"

void hexprint(const uint8_t *data, size_t len) 
{
    for (size_t i = 0; i < len; i++) printf("%02X", data[i]);
    printf("\n");
}

int main(int argc, char **argv) 
{
    if (argc < 2) {
        printf("Usage: %s genkey\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "genkey") == 0) {
        OQS_SIG *sig = OQS_SIG_new(KEY_TYPE);
        if (!sig) {
            fprintf(stderr, "Failed to initialize signature scheme\n");
            return 1;
        }

        uint8_t *pub_key = malloc(sig->length_public_key);
        uint8_t *priv_key = malloc(sig->length_secret_key);

        if (OQS_SIG_keypair(sig, pub_key, priv_key) != OQS_SUCCESS) {
            fprintf(stderr, "Key generation failed\n");
            return 1;
        }

        printf("Public Key:\n");
        hexprint(pub_key, sig->length_public_key);

        FILE *fp = fopen(PRIVKEY_FILE, "wb");
        if (fp) {
            fwrite(priv_key, 1, sig->length_secret_key, fp);
            fclose(fp);
            printf("Private key saved to %s\n", PRIVKEY_FILE);
        } else {
            fprintf(stderr, "Failed to write private key\n");
        }

        OQS_SIG_free(sig);
        free(pub_key);
        free(priv_key);
    } else {
        printf("Unknown command: %s\n", argv[1]);
    }

    return 0;
}

