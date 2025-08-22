#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include <oqs/sha3.h>
#include "db_wrapper.h"
#include "scootchain.h"

#define ADDR_LEN 34  // Updated: 1 flag + 1 checksum + 32 address hash
#define SEED_LEN 32

// ===== Utility: SHA3-256 via SHAKE256 (liboqs one-shot) =====
void sha3_256(const uint8_t *in, size_t in_len, uint8_t *out) {
    OQS_SHA3_shake256(out, 32, in, in_len);
}

// ===== CRC-8 implementation with polynomial 0x07 =====
uint8_t crc8_table[256];
static int crc8_table_initialized = 0;

void crc8_init_table(void) {
    if (crc8_table_initialized) return;
    
    const uint8_t poly = 0x07;
    for (int i = 0; i < 256; i++) {
        uint8_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 0x80) {
                crc = (crc << 1) ^ poly;
            } else {
                crc = crc << 1;
            }
        }
        crc8_table[i] = crc;
    }
    crc8_table_initialized = 1;
}

uint8_t crc8(const uint8_t *data, size_t len) {
    crc8_init_table();
    
    uint8_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc = crc8_table[crc ^ data[i]];
    }
    return crc;
}

// ===== Local DRBG for deterministic keys =====
typedef struct {
    uint8_t state[32];
    uint64_t counter;
} local_drbg_t;

void local_drbg_init(local_drbg_t *drbg, const uint8_t *seed) {
    memcpy(drbg->state, seed, 32);
    drbg->counter = 0;
}

void local_drbg_randombytes(local_drbg_t *drbg, uint8_t *out, size_t outlen) {
    uint8_t buf[40];
    while (outlen > 0) {
        memcpy(buf, drbg->state, 32);
        memcpy(buf + 32, &drbg->counter, 8);
        uint8_t hash[32];
        sha3_256(buf, sizeof(buf), hash);

        size_t take = outlen < 32 ? outlen : 32;
        memcpy(out, hash, take);
        out += take;
        outlen -= take;
        drbg->counter++;
    }
}

// ===== Save & Load helpers =====
void save_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror("fopen"); exit(1); }
    fwrite(data, 1, len, f);
    fclose(f);
}

void load_file(const char *path, uint8_t *data, size_t len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); exit(1); }
    if (fread(data, 1, len, f) != len) {
        fprintf(stderr, "File read error or unexpected length\n");
        exit(1);
    }
    fclose(f);
}

// ===== Generate Address from Public Key =====
// New 34-byte address format: [flag][checksum][32-byte hash]
// flag: 1 byte (set to 0 for now)
// checksum: 1 byte (CRC-8 over flag + 32-byte hash)
// hash: 32 bytes (SHA3-256 of public key)
void pubkey_to_address(const uint8_t *pubkey, size_t pubkey_len, uint8_t *address) {
    // Generate 32-byte hash from public key
    uint8_t hash[32];
    sha3_256(pubkey, pubkey_len, hash);
    
    // Set flag byte to 0
    address[0] = 0;
    
    // Copy hash to positions 2-33
    memcpy(address + 2, hash, 32);
    
    // Calculate checksum over flag (position 0) and hash (positions 2-33)
    uint8_t checksum_data[33];
    checksum_data[0] = address[0];  // flag
    memcpy(checksum_data + 1, hash, 32);  // hash
    
    // Set checksum at position 1
    address[1] = crc8(checksum_data, 33);
}

// ===== Validate Address Format =====
// Returns 1 if address is valid, 0 if invalid
int validate_address(const uint8_t *address) {
    // Check flag byte (must be 0 for now)
    if (address[0] != 0) {
        return 0;
    }
    
    // Prepare data for checksum verification: flag + hash
    uint8_t checksum_data[33];
    checksum_data[0] = address[0];  // flag
    memcpy(checksum_data + 1, address + 2, 32);  // hash from positions 2-33
    
    // Calculate expected checksum
    uint8_t expected_checksum = crc8(checksum_data, 33);
    
    // Compare with stored checksum at position 1
    return (address[1] == expected_checksum) ? 1 : 0;
}

// ===== Deterministic keypair from seed =====
void genkey_from_seed(const uint8_t *seed) {
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) { fprintf(stderr, "OQS_SIG_new failed\n"); exit(1); }

    uint8_t *pub = malloc(sig->length_public_key);
    uint8_t *priv = malloc(sig->length_secret_key);

    local_drbg_t drbg;
    local_drbg_init(&drbg, seed);
    local_drbg_randombytes(&drbg, priv, sig->length_secret_key);
    local_drbg_randombytes(&drbg, pub, sig->length_public_key);

    save_file("public.key", pub, sig->length_public_key);
    save_file("private.key", priv, sig->length_secret_key);

    printf("Generated deterministic key pair from seed\n");

    free(pub);
    free(priv);
    OQS_SIG_free(sig);
}

// ===== Command: genkey (random) =====
void cmd_genkey(void) {
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) { fprintf(stderr, "OQS_SIG_new failed\n"); exit(1); }

    uint8_t *pub = malloc(sig->length_public_key);
    uint8_t *priv = malloc(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, pub, priv) != OQS_SUCCESS) {
        fprintf(stderr, "Key generation failed\n");
        exit(1);
    }

    save_file("public.key", pub, sig->length_public_key);
    save_file("private.key", priv, sig->length_secret_key);

    printf("Generated random key pair: public.key, private.key\n");

    free(pub);
    free(priv);
    OQS_SIG_free(sig);
}

// ===== Command: genwallet =====
void cmd_genwallet(void) {
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);

    uint8_t *pub = malloc(sig->length_public_key);
    load_file("public.key", pub, sig->length_public_key);

    uint8_t address[ADDR_LEN];
    pubkey_to_address(pub, sig->length_public_key, address);
    save_file("wallet.addr", address, ADDR_LEN);

    printf("Wallet address generated: wallet.addr\n");

    free(pub);
    OQS_SIG_free(sig);
}

// ===== Command: checkwallet =====
void cmd_checkwallet(void) {
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);

    uint8_t *pub = malloc(sig->length_public_key);
    load_file("public.key", pub, sig->length_public_key);

    uint8_t expected_addr[ADDR_LEN];
    load_file("wallet.addr", expected_addr, ADDR_LEN);

    // Validate address format first
    if (!validate_address(expected_addr)) {
        printf("Wallet address format is invalid (bad checksum or flag) ❌\n");
        free(pub);
        OQS_SIG_free(sig);
        return;
    }

    uint8_t actual_addr[ADDR_LEN];
    pubkey_to_address(pub, sig->length_public_key, actual_addr);

    if (memcmp(expected_addr, actual_addr, ADDR_LEN) == 0) {
        printf("Wallet address matches public key ✅\n");
    } else {
        printf("Wallet address does NOT match public key ❌\n");
    }

    free(pub);
    OQS_SIG_free(sig);
}

// ===== Command: seedgen =====
void cmd_seedgen(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s seedgen <word1> <word2> ...\n", argv[0]);
        exit(1);
    }

    char combined[1024] = {0};
    for (int i = 2; i < argc; i++) {
        strcat(combined, argv[i]);
        if (i != argc - 1) strcat(combined, " ");
    }

    uint8_t seed[SEED_LEN];
    sha3_256((uint8_t *)combined, strlen(combined), seed);

    genkey_from_seed(seed);
}

// ===== Command: child key derivation =====
void cmd_child(int index) {
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);

    uint8_t *master_priv = malloc(sig->length_secret_key);
    load_file("private.key", master_priv, sig->length_secret_key);

    uint8_t buf[4096];
    memcpy(buf, master_priv, sig->length_secret_key);
    memcpy(buf + sig->length_secret_key, &index, sizeof(index));

    uint8_t child_seed[SEED_LEN];
    sha3_256(buf, sig->length_secret_key + sizeof(index), child_seed);

    genkey_from_seed(child_seed);

    free(master_priv);
    OQS_SIG_free(sig);
}

// ===== Main =====
int main(int argc, char **argv) 
{
	

	if (argc < 2) {
        fprintf(stderr, "Usage: %s [genkey|genwallet|checkwallet|seedgen|child <index>]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "genkey") == 0) {
        cmd_genkey();
    } else if (strcmp(argv[1], "genwallet") == 0) {
        cmd_genwallet();
    } else if (strcmp(argv[1], "checkwallet") == 0) {
        cmd_checkwallet();
    } else if (strcmp(argv[1], "seedgen") == 0) {
        cmd_seedgen(argc, argv);
    } else if (strcmp(argv[1], "child") == 0) {
        if (argc < 3) { fprintf(stderr, "Need child index\n"); return 1; }
        cmd_child(atoi(argv[2]));
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }
    return 0;
}

