/*
 * Scootchain - Quantum-safe blockchain implementation
 *
 * Address Format (34 bytes total):
 * [0]     - Flag byte (0 = standard address)
 * [1]     - Checksum (CRC-8 with polynomial 0x07)
 * [2-33]  - Address hash (SHA3-256 of public key)
 *
 * The checksum is calculated over the flag byte + 32-byte address hash.
 * This format provides integrity checking and allows for future extensions
 * via the flag byte.
 */


#include "scootchain.h"

#define ADDR_LEN 34  // Updated: 1 flag + 1 checksum + 32 address hash
#define SEED_LEN 32

// ===== Utility: SHA3-256 via SHAKE256 (liboqs one-shot) =====
void sha3_256(const UINT8 *in, size_t in_len, UINT8 *out)
{
    OQS_SHA3_shake256(out, 32, in, in_len);
}

// ===== CRC-8 implementation with polynomial 0x07 =====
// CRC-8 with polynomial 0x07 (x^8 + x^2 + x + 1)
// Used for address checksum validation
UINT8 crc8_table[256];
static int crc8_table_initialized = 0;

void crc8_init_table(void)
{
    if (crc8_table_initialized)
    {
        return;
    }

    const UINT8 poly = 0x07;  // Standard CRC-8 polynomial
    for (int i = 0; i < 256; i++)
    {
        UINT8 crc = i;
        for (int j = 0; j < 8; j++)
        {
            if (crc & 0x80)
            {
                crc = (crc << 1) ^ poly;
            }
            else
            {
                crc = crc << 1;
            }
        }
        crc8_table[i] = crc;
    }
    crc8_table_initialized = 1;
}

UINT8 crc8(const UINT8 *data, size_t len)
{
    crc8_init_table();

    UINT8 crc = 0;
    for (size_t i = 0; i < len; i++)
    {
        crc = crc8_table[crc ^ data[i]];
    }
    return crc;
}

// ===== Local DRBG for deterministic keys =====
typedef struct
{
    UINT8 state[32];
    UINT64 counter;
} local_drbg_t;

void local_drbg_init(local_drbg_t *drbg, const UINT8 *seed)
{
    memcpy(drbg->state, seed, 32);
    drbg->counter = 0;
}

void local_drbg_randombytes(local_drbg_t *drbg, UINT8 *out, size_t outlen)
{
    UINT8 buf[40];
    while (outlen > 0)
    {
        memcpy(buf, drbg->state, 32);
        memcpy(buf + 32, &drbg->counter, 8);
        UINT8 hash[32];
        sha3_256(buf, sizeof(buf), hash);

        size_t take = outlen < 32 ? outlen : 32;
        memcpy(out, hash, take);
        out += take;
        outlen -= take;
        drbg->counter++;
    }
}

// ===== Save & Load helpers =====
void save_file(const char *path, const UINT8 *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
    {
        perror("fopen");
        exit(1);
    }
    fwrite(data, 1, len, f);
    fclose(f);
}

void load_file(const char *path, UINT8 *data, size_t len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
    {
        perror("fopen");
        exit(1);
    }
    if (fread(data, 1, len, f) != len)
    {
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
void pubkey_to_address(const UINT8 *pubkey, size_t pubkey_len, scoot_address *pAddress)
{
    // Generate 32-byte hash from public key
    UINT8 hash[32];
    sha3_256(pubkey, pubkey_len, hash);

    // Set flag byte to 0
    pAddress->u.flags = 0;

    // Copy hash to positions 2-33
    memcpy(pAddress->hash, hash, 32);

    // Calculate checksum over flag (position 0) and hash (positions 2-33)
    UINT8 checksum_data[33];
    checksum_data[0] = pAddress->u.flags;  // flag
    memcpy(checksum_data + 1, hash, 32);  // hash

    // Set checksum at position 1
    pAddress->checksum = crc8(checksum_data, 33);
}

// ===== Validate Address Format =====
// Returns 1 if address is valid, 0 if invalid
int validate_address(const scoot_address address)
{

    // Prepare data for checksum verification: flag + hash
    UINT8 checksum_data[33];
    checksum_data[0] = address.u.flags;  // flag
    memcpy(checksum_data + 1, address.hash, 32);  // hash from positions 2-33

    // Calculate expected checksum
    UINT8 expected_checksum = crc8(checksum_data, 33);

    // Compare with stored checksum at position 1
    return (address.checksum == expected_checksum) ? 1 : 0;
}

// ===== Simple helpers =====
static void hex_encode(const UINT8 *in, size_t in_len, char *out)
{
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < in_len; i++)
    {
        out[2 * i] = hex[(in[i] >> 4) & 0xF];
        out[2 * i + 1] = hex[in[i] & 0xF];
    }
    out[2 * in_len] = '\0';
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F')
    {
        return 10 + (c - 'A');
    }
    return -1;
}

static int hex_decode(const char *hex, UINT8 **out, size_t *outlen)
{
    size_t len = strlen(hex);
    if (len == 0 )//|| ((len - 1) % 2) != 0)
    {

        printf("!LEN len = %ld outlen = %ld\n", len, *outlen);

        return 0;
    }
    size_t blen = len / 2;
    UINT8 *buf = (UINT8 *)malloc(blen);
    if (!buf)
    {
        printf("!BUF blen = %ld\n", blen);
        return 0;
    }
    for (size_t i = 0; i < blen; i++)
    {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
        {
            printf("hex_code hi = %d lo = %d i= %ld\n", hi, lo, i);
            free(buf);
            return 0;
        }
        buf[i] = (UINT8)((hi << 4) | lo);
    }
    *out = buf;
    *outlen = blen;
    return 1;
}

static void save_text_file(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
    {
        perror("fopen");
        exit(1);
    }
    fwrite(data, 1, len, f);
    fclose(f);
}

static void read_text_file(const char *path, char **out_data, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
    {
        perror("fopen");
        exit(1);
    }
    if (fseek(f, 0, SEEK_END) != 0)
    {
        perror("fseek");
        fclose(f);
        exit(1);
    }
    long sz = ftell(f);

    if (sz < 0)
    {
        perror("ftell");
        fclose(f);
        exit(1);
    }
    rewind(f);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf)
    {
        fprintf(stderr, "Out of memory\n");
        fclose(f);
        exit(1);
    }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    printf("sz = %ld n = %ld\n", sz, n);

    *out_data = buf;
    if (out_len)
    {
        *out_len = n + 1;
    }
}

static void rstrip_whitespace(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t'))
    {
        s[--n] = '\0';
    }
}

static char *strip_non_hex(const char *s)
{
    size_t len = strlen(s);
    char *out = (char *)malloc(len + 1);
    if (!out)
    {
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }
    size_t j = 0;
    for (size_t i = 0; i < len; i++)
    {
        char c = s[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
        {
            out[j++] = c;
        }
        else
        {
            printf("SKIP %ld\n", i);
        }
    }
    printf("OUT J = %ld len = %ld\n", j, len);
    out[j] = '\0';
    return out;
}

static void prompt_read_line(const char *prompt, char **out)
{
    printf("%s", prompt);
    fflush(stdout);

    size_t cap = 8192;
    char *buf = (char *)malloc(cap);
    if (!buf)
    {
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    size_t n = 0;
    int c;
    while ((c = fgetc(stdin)) != EOF && c != '\n')
    {
        if (n + 1 >= cap)
        {
            cap *= 2;
            char *nbuf = (char *)realloc(buf, cap);
            if (!nbuf)
            {
                free(buf);
                fprintf(stderr, "Out of memory\n");
                exit(1);
            }
            buf = nbuf;
        }
#if 0
        printf("[%d](%c)", n, c);
        if(n % 16 == 0 )
        {
            printf("\n");
        }
        buf[n++] = (char)c;
#endif


    }
    buf[n] = '\0';
    *out = buf;
}

static void prompt_and_read_message(UINT8 **msg, size_t *len)
{
    printf("Enter message: ");
    fflush(stdout);

    size_t cap = 256;
    UINT8 *buf = (UINT8 *)malloc(cap);
    if (!buf)
    {
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    size_t n = 0;
    int c;
    while ((c = fgetc(stdin)) != EOF && c != '\n')
    {
        if (n + 1 > cap)
        {
            cap *= 2;
            UINT8 *nbuf = (UINT8 *)realloc(buf, cap);
            if (!nbuf)
            {
                free(buf);
                fprintf(stderr, "Out of memory\n");
                exit(1);
            }
            buf = nbuf;
        }
        buf[n++] = (UINT8)c;
    }

    *msg = buf;
    *len = n;
}

// ===== Deterministic keypair from seed =====
void genkey_from_seed(const UINT8 *seed)
{
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig)
    {
        fprintf(stderr, "OQS_SIG_new failed\n");
        exit(1);
    }

    UINT8 *pub = malloc(sig->length_public_key);
    UINT8 *priv = malloc(sig->length_secret_key);

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
void cmd_genkey(void)
{
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig)
    {
        fprintf(stderr, "OQS_SIG_new failed\n");
        exit(1);
    }

    UINT8 *pub = malloc(sig->length_public_key);
    UINT8 *priv = malloc(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, pub, priv) != OQS_SUCCESS)
    {
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
void cmd_genwallet(UINT8 flags, int has_flags)
{
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);

    UINT8 *pub = malloc(sig->length_public_key);
    load_file("public.key", pub, sig->length_public_key);

    scoot_address address;
    pubkey_to_address(pub, sig->length_public_key, &address);
    if (has_flags)
    {
        // Override flags and recompute checksum
        address.u.flags = flags;
        UINT8 checksum_data[33];
        checksum_data[0] = address.u.flags;
        memcpy(checksum_data + 1, address.hash, 32);
        address.checksum = crc8(checksum_data, 33);
    }
    save_file("wallet.addr", (UINT8 *)&address, ADDR_LEN);

    printf("Wallet address generated: wallet.addr\n");

    free(pub);
    OQS_SIG_free(sig);
}

// ===== Command: checkwallet =====
void cmd_checkwallet(void)
{
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);

    UINT8 *pub = malloc(sig->length_public_key);
    load_file("public.key", pub, sig->length_public_key);

    scoot_address expected_addr;
    load_file("wallet.addr", (UINT8 *)&expected_addr, ADDR_LEN);

    // Validate address format first
    if (!validate_address(expected_addr))
    {
        printf("Wallet address format is invalid (bad checksum or flag) ❌\n");
        free(pub);
        OQS_SIG_free(sig);
        return;
    }

    scoot_address actual_addr = { 0 };
    pubkey_to_address(pub, sig->length_public_key, &actual_addr);

    if (memcmp((void *)&expected_addr, (void *)&actual_addr, ADDR_LEN) == 0)
    {
        printf("Wallet address matches public key ✅\n");
    }
    else
    {
        printf("Wallet address does NOT match public key ❌\n");
    }

    free(pub);
    OQS_SIG_free(sig);
}

// ===== Command: seedgen =====
void cmd_seedgen(int argc, char **argv)
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s seedgen <word1> <word2> ...\n", argv[0]);
        exit(1);
    }

    char combined[1024] = {0};
    for (int i = 2; i < argc; i++)
    {
        strcat(combined, argv[i]);
        if (i != argc - 1)
        {
            strcat(combined, " ");
        }
    }

    UINT8 seed[SEED_LEN];
    sha3_256((UINT8 *)combined, strlen(combined), seed);

    genkey_from_seed(seed);
}

// ===== Command: child key derivation =====
void cmd_child(int index)
{
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);

    UINT8 *master_priv = malloc(sig->length_secret_key);
    load_file("private.key", master_priv, sig->length_secret_key);

    UINT8 buf[4096];
    memcpy(buf, master_priv, sig->length_secret_key);
    memcpy(buf + sig->length_secret_key, &index, sizeof(index));

    UINT8 child_seed[SEED_LEN];
    sha3_256(buf, sig->length_secret_key + sizeof(index), child_seed);

    genkey_from_seed(child_seed);

    free(master_priv);
    OQS_SIG_free(sig);
}

// ===== Command: sign =====
void cmd_sign(const char *out_path)
{
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig)
    {
        fprintf(stderr, "OQS_SIG_new failed\n");
        exit(1);
    }

    UINT8 *sk = (UINT8 *)malloc(sig->length_secret_key);
    if (!sk)
    {
        fprintf(stderr, "Out of memory\n");
        OQS_SIG_free(sig);
        exit(1);
    }
    load_file("private.key", sk, sig->length_secret_key);

    UINT8 *msg = NULL;
    size_t msg_len = 0;
    prompt_and_read_message(&msg, &msg_len);

    size_t sig_len = sig->length_signature;
    UINT8 *signature = (UINT8 *)malloc(sig_len);
    if (!signature)
    {
        fprintf(stderr, "Out of memory\n");
        free(sk);
        free(msg);
        OQS_SIG_free(sig);
        exit(1);
    }

    if (OQS_SIG_sign(sig, signature, &sig_len, msg, msg_len, sk) != OQS_SUCCESS)
    {
        fprintf(stderr, "Signing failed\n");
        free(signature);
        free(sk);
        free(msg);
        OQS_SIG_free(sig);
        exit(1);
    }

    char *hex = (char *)malloc(sig_len * 2 + 1);
    if (!hex)
    {
        fprintf(stderr, "Out of memory\n");
        free(signature);
        free(sk);
        free(msg);
        OQS_SIG_free(sig);
        exit(1);
    }
    hex_encode(signature, sig_len, hex);
    printf("Signature (hex): %s\n", hex);
    if (out_path)
    {
        save_text_file(out_path, hex, strlen(hex));
        printf("Saved signature hex to %s\n", out_path);
    }

    free(hex);
    free(signature);
    free(sk);
    free(msg);
    OQS_SIG_free(sig);
}

// ===== Command: encrypt =====
// Symmetric stream-encrypt using key derived from private.key
// keystream = SHAKE256( SHA3-256(private.key) || nonce, outlen=len(msg) )
// ciphertext = msg XOR keystream
void cmd_encrypt(const char *out_path)
{
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig)
    {
        fprintf(stderr, "OQS_SIG_new failed\n");
        exit(1);
    }

    // Load private key bytes (only used as entropy for key derivation)
    UINT8 *sk = (UINT8 *)malloc(sig->length_secret_key);
    if (!sk)
    {
        fprintf(stderr, "Out of memory\n");
        OQS_SIG_free(sig);
        exit(1);
    }
    load_file("private.key", sk, sig->length_secret_key);

    // Derive a 32-byte key from private.key
    UINT8 kdf_key[32];
    sha3_256(sk, sig->length_secret_key, kdf_key);

    // Read message
    UINT8 *msg = NULL;
    size_t msg_len = 0;
    prompt_and_read_message(&msg, &msg_len);

    // Random nonce
    UINT8 nonce[16];
    OQS_randombytes(nonce, sizeof(nonce));

    // Build input to SHAKE: key || nonce
    UINT8 *shake_in = (UINT8 *)malloc(sizeof(kdf_key) + sizeof(nonce));
    if (!shake_in)
    {
        fprintf(stderr, "Out of memory\n");
        free(sk);
        free(msg);
        OQS_SIG_free(sig);
        exit(1);
    }
    memcpy(shake_in, kdf_key, sizeof(kdf_key));
    memcpy(shake_in + sizeof(kdf_key), nonce, sizeof(nonce));

    // Derive keystream and encrypt
    UINT8 *keystream = (UINT8 *)malloc(msg_len);
    UINT8 *ct = (UINT8 *)malloc(msg_len);
    if (!keystream || !ct)
    {
        fprintf(stderr, "Out of memory\n");
        free(keystream);
        free(ct);
        free(shake_in);
        free(sk);
        free(msg);
        OQS_SIG_free(sig);
        exit(1);
    }
    OQS_SHA3_shake256(keystream, msg_len, shake_in, sizeof(kdf_key) + sizeof(nonce));
    for (size_t i = 0; i < msg_len; i++)
    {
        ct[i] = msg[i] ^ keystream[i];
    }

    // Output nonce and ciphertext as hex
    char *nonce_hex = (char *)malloc(sizeof(nonce) * 2 + 1);
    char *ct_hex = (char *)malloc(msg_len * 2 + 1);
    if (!nonce_hex || !ct_hex)
    {
        fprintf(stderr, "Out of memory\n");
        free(nonce_hex);
        free(ct_hex);
        free(keystream);
        free(ct);
        free(shake_in);
        free(sk);
        free(msg);
        OQS_SIG_free(sig);
        exit(1);
    }
    hex_encode(nonce, sizeof(nonce), nonce_hex);
    hex_encode(ct, msg_len, ct_hex);
    printf("Nonce (hex): %s\n", nonce_hex);
    printf("Ciphertext (hex): %s\n", ct_hex);
    if (out_path)
    {
        // Write as two lines: nonce_hex then ciphertext_hex
        size_t total = strlen(nonce_hex) + 1 + strlen(ct_hex);
        char *buf = (char *)malloc(total + 1);
        if (!buf)
        {
            fprintf(stderr, "Out of memory\n");
            free(nonce_hex);
            free(ct_hex);
            free(keystream);
            free(ct);
            free(shake_in);
            free(sk);
            free(msg);
            OQS_SIG_free(sig);
            exit(1);
        }
        sprintf(buf, "%s\n%s", nonce_hex, ct_hex);
        save_text_file(out_path, buf, strlen(buf));
        printf("Saved nonce+ciphertext hex to %s\n", out_path);
        free(buf);
    }

    free(nonce_hex);
    free(ct_hex);
    free(keystream);
    free(ct);
    free(shake_in);
    free(sk);
    free(msg);
    OQS_SIG_free(sig);
}

// ===== Command: decrypt =====
void cmd_decrypt(const char *in_path)
{
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig)
    {
        fprintf(stderr, "OQS_SIG_new failed\n");
        exit(1);
    }

    // Load private key and derive key
    UINT8 *sk = (UINT8 *)malloc(sig->length_secret_key);
    if (!sk)
    {
        fprintf(stderr, "Out of memory\n");
        OQS_SIG_free(sig);
        exit(1);
    }
    load_file("private.key", sk, sig->length_secret_key);
    UINT8 kdf_key[32];
    sha3_256(sk, sig->length_secret_key, kdf_key);

    char *nonce_hex = NULL;
    char *ct_hex = NULL;
    if (in_path)
    {
        char *file_data = NULL;
        size_t file_len = 0;
        read_text_file(in_path, &file_data, &file_len);
        // Split on first newline
        char *nl = strchr(file_data, '\n');
        if (!nl)
        {
            fprintf(stderr, "Invalid input file format; expected two lines (nonce hex, ciphertext hex)\n");
            free(file_data);
            free(sk);
            OQS_SIG_free(sig);
            exit(1);
        }
        size_t l1 = (size_t)(nl - file_data);
        nonce_hex = (char *)malloc(l1 + 1);
        memcpy(nonce_hex, file_data, l1);
        nonce_hex[l1] = '\0';
        char *line2 = nl + 1;
        // Copy remaining as ciphertext line
        size_t l2 = strlen(line2);
        ct_hex = (char *)malloc(l2 + 1);
        memcpy(ct_hex, line2, l2 + 1);
        rstrip_whitespace(nonce_hex);
        rstrip_whitespace(ct_hex);
        free(file_data);
    }
    else
    {
        prompt_read_line("Enter nonce (hex): ", &nonce_hex);
        prompt_read_line("Enter ciphertext (hex): ", &ct_hex);
    }

    UINT8 *nonce = NULL;
    size_t nonce_len = 0;
    if (!hex_decode(nonce_hex, &nonce, &nonce_len) || nonce_len == 0)
    {
        fprintf(stderr, "Invalid nonce hex\n");
        free(nonce_hex);
        free(ct_hex);
        free(sk);
        OQS_SIG_free(sig);
        exit(1);
    }

    UINT8 *ct = NULL;
    size_t ct_len = 0;
    if (!hex_decode(ct_hex, &ct, &ct_len))
    {
        fprintf(stderr, "Invalid ciphertext hex\n");
        free(nonce);
        free(nonce_hex);
        free(ct_hex);
        free(sk);
        OQS_SIG_free(sig);
        exit(1);
    }

    // Derive keystream and decrypt
    UINT8 *shake_in = (UINT8 *)malloc(sizeof(kdf_key) + nonce_len);
    if (!shake_in)
    {
        fprintf(stderr, "Out of memory\n");
        free(ct);
        free(nonce);
        free(nonce_hex);
        free(ct_hex);
        free(sk);
        OQS_SIG_free(sig);
        exit(1);
    }
    memcpy(shake_in, kdf_key, sizeof(kdf_key));
    memcpy(shake_in + sizeof(kdf_key), nonce, nonce_len);

    UINT8 *keystream = (UINT8 *)malloc(ct_len);
    UINT8 *pt = (UINT8 *)malloc(ct_len);
    if (!keystream || !pt)
    {
        fprintf(stderr, "Out of memory\n");
        free(keystream);
        free(pt);
        free(shake_in);
        free(ct);
        free(nonce);
        free(nonce_hex);
        free(ct_hex);
        free(sk);
        OQS_SIG_free(sig);
        exit(1);
    }
    OQS_SHA3_shake256(keystream, ct_len, shake_in, sizeof(kdf_key) + nonce_len);
    for (size_t i = 0; i < ct_len; i++)
    {
        pt[i] = ct[i] ^ keystream[i];
    }

    printf("Decrypted message: ");
    fwrite(pt, 1, ct_len, stdout);
    printf("\n");

    free(keystream);
    free(pt);
    free(shake_in);
    free(ct);
    free(nonce);
    free(nonce_hex);
    free(ct_hex);
    free(sk);
    OQS_SIG_free(sig);
}

// ===== Command: verify =====
void cmd_verify(const char *in_path)
{
    const char *alg = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig)
    {
        fprintf(stderr, "OQS_SIG_new failed\n");
        exit(1);
    }

    // Load public key
    UINT8 *pk = (UINT8 *)malloc(sig->length_public_key);
    if (!pk)
    {
        fprintf(stderr, "Out of memory\n");
        OQS_SIG_free(sig);
        exit(1);
    }
    load_file("public.key", pk, sig->length_public_key);

    // Read message
    UINT8 *msg = NULL;
    size_t msg_len = 0;
    prompt_and_read_message(&msg, &msg_len);

    // Read signature hex (from file or prompt)
    char *sig_hex = NULL;
    if (in_path)
    {
        char *file_data = NULL;
        size_t file_len = 0;
        read_text_file(in_path, &file_data, &file_len);
        printf("file_len = %ld\n", file_len);
        char *only_hex = strip_non_hex(file_data);
        free(file_data);
        sig_hex = only_hex;
    }
    else
    {
        prompt_read_line("Enter signature (hex): ", &sig_hex);
    }

    UINT8 *sig_bytes = NULL;
    size_t sig_len = 0;
    if (!hex_decode(sig_hex, &sig_bytes, &sig_len))
    {
        fprintf(stderr, "*Invalid signature hex\n");
        free(sig_hex);
        free(msg);
        free(pk);
        OQS_SIG_free(sig);
        exit(1);
    }

    OQS_STATUS ok = OQS_SIG_verify(sig, msg, msg_len, sig_bytes, sig_len, pk);
    if (ok == OQS_SUCCESS)
    {
        printf("Signature verified ✅\n");
    }
    else
    {
        printf("Signature INVALID ❌\n");
    }

    free(sig_bytes);
    free(sig_hex);
    free(msg);
    free(pk);
    OQS_SIG_free(sig);
}

// ===== Main =====
int main(int argc, char **argv)
{


    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s [genkey|genwallet|checkwallet|seedgen|child <index>|sign [-o file]|encrypt [-o file]|decrypt [-i file]|verify [-i file]]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "genkey") == 0)
    {
        cmd_genkey();
    }
    else if (strcmp(argv[1], "genwallet") == 0)
    {
        if (argc == 2)
        {
            cmd_genwallet(0, 0);
        }
        else if (argc == 3)
        {
            char *end = NULL;
            long v;
            if ((argv[2][0] == '0') && (argv[2][1] == 'x' || argv[2][1] == 'X'))
            {
                v = strtol(argv[2], &end, 16);
            }
            else
            {
                v = strtol(argv[2], &end, 10);
            }
            if (end == NULL || *end != '\0' || v < 0 || v > 255)
            {
                fprintf(stderr, "Usage: %s genwallet [flags (0..255 or 0x..)]\n", argv[0]);
                return 1;
            }
            cmd_genwallet((UINT8)v, 1);
        }
        else
        {
            fprintf(stderr, "Usage: %s genwallet [flags]\n", argv[0]);
            return 1;
        }
    }
    else if (strcmp(argv[1], "checkwallet") == 0)
    {
        cmd_checkwallet();
    }
    else if (strcmp(argv[1], "seedgen") == 0)
    {
        cmd_seedgen(argc, argv);
    }
    else if (strcmp(argv[1], "child") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Need child index\n");
            return 1;
        }
        cmd_child(atoi(argv[2]));
    }
    else if (strcmp(argv[1], "sign") == 0)
    {
        const char *out_path = NULL;
        if (argc == 4 && strcmp(argv[2], "-o") == 0)
        {
            out_path = argv[3];
        }
        else if (argc != 2)
        {
            fprintf(stderr, "Usage: %s sign [-o file]\n", argv[0]);
            return 1;
        }
        cmd_sign(out_path);
    }
    else if (strcmp(argv[1], "encrypt") == 0)
    {
        const char *out_path = NULL;
        if (argc == 4 && strcmp(argv[2], "-o") == 0)
        {
            out_path = argv[3];
        }
        else if (argc != 2)
        {
            fprintf(stderr, "Usage: %s encrypt [-o file]\n", argv[0]);
            return 1;
        }
        cmd_encrypt(out_path);
    }
    else if (strcmp(argv[1], "decrypt") == 0)
    {
        const char *in_path = NULL;
        if (argc == 4 && strcmp(argv[2], "-i") == 0)
        {
            in_path = argv[3];
        }
        else if (argc != 2)
        {
            fprintf(stderr, "Usage: %s decrypt [-i file]\n", argv[0]);
            return 1;
        }
        cmd_decrypt(in_path);
    }
    else if (strcmp(argv[1], "verify") == 0)
    {
        const char *in_path = NULL;
        if (argc == 4 && strcmp(argv[2], "-i") == 0)
        {
            in_path = argv[3];
        }
        else if (argc != 2)
        {
            fprintf(stderr, "Usage: %s verify [-i file]\n", argv[0]);
            return 1;
        }
        cmd_verify(in_path);
    }
    else
    {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }
    return 0;
}

