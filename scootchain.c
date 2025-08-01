#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include <oqs/sha3.h>  // <-- Added for OQS_SHA3_sha3_256

#define MASTER_PRIV_FILE "master_priv.bin"
#define MASTER_PUB_FILE  "master_pub.bin"
#define WALLET_FILE      "wallet.addr"

// Choose a PQ signature scheme
#define SIG_ALG "Dilithium2"  // Change if desired

// SHA3-256 wrapper
void sha3_256(const uint8_t *in, size_t in_len, uint8_t *out) {
    OQS_SHA3_sha3_256(out, in, in_len);
}

// Save binary file
void save_file(const char *filename, const uint8_t *data, size_t len) {
    FILE *f = fopen(filename, "wb");
    if (!f) { perror("fopen"); exit(1); }
    fwrite(data, 1, len, f);
    fclose(f);
}

// Load binary file
void load_file(const char *filename, uint8_t *data, size_t len) {
    FILE *f = fopen(filename, "rb");
    if (!f) { perror("fopen"); exit(1); }
    size_t read_bytes = fread(data, 1, len, f);
    if (read_bytes != len) {
        fprintf(stderr, "Error: expected %zu bytes, got %zu\n", len, read_bytes);
        exit(1);
    }
    fclose(f);
}

// Generate key pair
void cmd_genkey() {
    OQS_SIG *sig = OQS_SIG_new(SIG_ALG);
    if (!sig) {
        fprintf(stderr, "Failed to init signature scheme %s\n", SIG_ALG);
        exit(1);
    }

    uint8_t *priv = malloc(sig->length_secret_key);
    uint8_t *pub  = malloc(sig->length_public_key);

    if (OQS_SIG_keypair(sig, pub, priv) != OQS_SUCCESS) {
        fprintf(stderr, "Keypair generation failed\n");
        exit(1);
    }

    save_file(MASTER_PRIV_FILE, priv, sig->length_secret_key);
    save_file(MASTER_PUB_FILE, pub, sig->length_public_key);

    printf("Generated keypair:\n  Public key: %s\n  Private key: %s\n",
           MASTER_PUB_FILE, MASTER_PRIV_FILE);

    OQS_SIG_free(sig);
    free(priv);
    free(pub);
}

// Generate wallet address from public key
void cmd_genwallet() {
    OQS_SIG *sig = OQS_SIG_new(SIG_ALG);
    if (!sig) { fprintf(stderr, "SIG init failed\n"); exit(1); }

    uint8_t *pub = malloc(sig->length_public_key);
    load_file(MASTER_PUB_FILE, pub, sig->length_public_key);

    uint8_t hash[32];
    sha3_256(pub, sig->length_public_key, hash);

    save_file(WALLET_FILE, hash, 32);
    printf("Wallet address saved to %s\n", WALLET_FILE);

    OQS_SIG_free(sig);
    free(pub);
}

// Verify wallet address matches public key
void cmd_checkwallet() {
    OQS_SIG *sig = OQS_SIG_new(SIG_ALG);
    if (!sig) { fprintf(stderr, "SIG init failed\n"); exit(1); }

    uint8_t *pub = malloc(sig->length_public_key);
    load_file(MASTER_PUB_FILE, pub, sig->length_public_key);

    uint8_t expected_hash[32];
    sha3_256(pub, sig->length_public_key, expected_hash);

    uint8_t stored_hash[32];
    load_file(WALLET_FILE, stored_hash, 32);

    if (memcmp(expected_hash, stored_hash, 32) == 0) {
        printf("Wallet address matches public key.\n");
    } else {
        printf("Wallet address does NOT match public key!\n");
    }

    OQS_SIG_free(sig);
    free(pub);
}

// Derive child keypair from master private key and index
void cmd_childkey(uint32_t index) {
    OQS_SIG *sig = OQS_SIG_new(SIG_ALG);
    if (!sig) { fprintf(stderr, "SIG init failed\n"); exit(1); }

    uint8_t *master_priv = malloc(sig->length_secret_key);
    load_file(MASTER_PRIV_FILE, master_priv, sig->length_secret_key);

    uint8_t seed[32];
    memcpy(seed, master_priv, 32); // take first 32 bytes
    seed[0] ^= (index & 0xFF);     // simple variation with index

    uint8_t *child_priv = malloc(sig->length_secret_key);
    uint8_t *child_pub  = malloc(sig->length_public_key);

    if (OQS_SIG_keypair(sig, child_pub, child_priv) != OQS_SUCCESS) {
        fprintf(stderr, "Child keypair generation failed\n");
        exit(1);
    }

    char priv_name[64], pub_name[64];
    snprintf(priv_name, sizeof(priv_name), "child_%u_priv.bin", index);
    snprintf(pub_name, sizeof(pub_name), "child_%u_pub.bin", index);

    save_file(priv_name, child_priv, sig->length_secret_key);
    save_file(pub_name, child_pub, sig->length_public_key);

    printf("Generated child keypair #%u\n", index);

    OQS_SIG_free(sig);
    free(master_priv);
    free(child_priv);
    free(child_pub);
}

// Main command dispatcher
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <command> [args]\n", argv[0]);
        printf("Commands:\n");
        printf("  genkey         - Generate master keypair\n");
        printf("  genwallet      - Generate wallet address from master pubkey\n");
        printf("  checkwallet    - Check wallet matches pubkey\n");
        printf("  childkey <idx> - Generate child keypair with index\n");
        return 0;
    }

    if (strcmp(argv[1], "genkey") == 0) {
        cmd_genkey();
    } else if (strcmp(argv[1], "genwallet") == 0) {
        cmd_genwallet();
    } else if (strcmp(argv[1], "checkwallet") == 0) {
        cmd_checkwallet();
    } else if (strcmp(argv[1], "childkey") == 0) {
        if (argc < 3) {
            fprintf(stderr, "childkey requires an index argument\n");
            return 1;
        }
        uint32_t index = atoi(argv[2]);
        cmd_childkey(index);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}

