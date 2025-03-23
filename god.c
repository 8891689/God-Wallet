/*Author: 8891689
 * Assist in creation ：ChatGPT 
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "secp256k1.h"
#include "sha256.h"
#include "ripemd160.h"
#include "base58.h"
#include "bech32.h"
#include "sha3256.h"
#include "keccak256.h"
#include "random.h"
#include "cashaddr.h"

/* secp256k1 椭圆曲线参数 */
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

// 全局变量，存储大整数形式的椭圆曲线参数，以便在 scalar_multiply 中使用
BigInt EC_constant_P_BI;
ECPoint G; // 在 main 中初始化

/* 辅助函数声明 */
int hex2bin(const char *hex, uint8_t *bin, size_t bin_len);
int wif_to_private_key(const char *wif, char *priv_hex, size_t hex_len, bool *compressed);
int private_key_to_wif(const char *priv_hex, bool compressed, char *wif, size_t wif_len);
void hash160(const uint8_t *data, size_t data_len, uint8_t *out);
int base58check_encode(uint8_t version, const uint8_t *hash20, char *address, size_t addr_len);

/* 新增函数声明 */
char *public_key_to_address(const char *public_key_hex, const char *address_type);
char *generate_eth_address(const char *public_key_hex);
char *generate_tron_address(const char *public_key_hex);
char *generate_dogecoin_address(const char *public_key_hex);
char *generate_litecoin_address(const char *public_key_hex);
char *generate_dash_address(const char *public_key_hex);
char *generate_zcash_address(const char *public_key_hex);
char *generate_bitcoincash_address(const char *public_key_hex);
char *generate_bitcoingold_address(const char *public_key_hex);

/* 将 hex 字符串转换为二进制数据 */
int hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != bin_len * 2)
        return -1;
    for (size_t i = 0; i < bin_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1)
            return -1;
        bin[i] = (uint8_t)byte;
    }
    return 0;
}

/* 将 WIF 解码为私钥的 16 进制字符串，并判断是否为压缩格式 */
int wif_to_private_key(const char *wif, char *priv_hex, size_t hex_len, bool *compressed) {
    size_t decoded_len = 100;
    uint8_t decoded[100] = {0};

    if (!b58tobin(decoded, &decoded_len, wif, strlen(wif)))
        return -1;

    /* 解码后长度应为 37 字节（非压缩）或 38 字节（压缩） */
    if (decoded_len == 37)
        *compressed = false;
    else if (decoded_len == 38)
        *compressed = true;
    else
        return -1;

    /* 检查版本字节：应为 0x80 */
    if (decoded[0] != 0x80)
        return -1;

    /* 校验 checksum：对前 decoded_len-4 字节进行双 SHA256 */
    uint8_t hash1[32], hash2[32];
    sha256(decoded, decoded_len - 4, hash1);
    sha256(hash1, 32, hash2);
    if (memcmp(hash2, decoded + decoded_len - 4, 4) != 0)
        return -1;

    /* 私钥位于 decoded[1..32] */
    if (hex_len < 65)
        return -1;
    for (int i = 0; i < 32; i++) {
        sprintf(priv_hex + i * 2, "%02x", decoded[1 + i]);
    }
    priv_hex[64] = '\0';
    return 0;
}


/* 将 32 字节私钥（Hex）转换为 WIF 格式 */
int private_key_to_wif(const char *priv_hex, bool compressed, char *wif, size_t wif_len) {
    uint8_t priv_bin[32];
    if (hex2bin(priv_hex, priv_bin, 32) != 0)
        return -1;
    uint8_t payload[34];
    payload[0] = 0x80;
    memcpy(payload + 1, priv_bin, 32);
    size_t payload_len = 33;
    if (compressed) {
        payload[33] = 0x01;
        payload_len = 34;
    }
    uint8_t hash1[32], hash2[32];
    sha256(payload, payload_len, hash1);
    sha256(hash1, 32, hash2);
    uint8_t full[38];
    memcpy(full, payload, payload_len);
    memcpy(full + payload_len, hash2, 4);
    size_t full_len = payload_len + 4;
    size_t encoded_len = wif_len;
    if (!b58enc(wif, &encoded_len, full, full_len))
        return -1;
    return 0;
}

/* 计算 hash160 (RIPEMD160(SHA256(data))) */
void hash160(const uint8_t *data, size_t data_len, uint8_t *out) {
    uint8_t sha[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, sha);

    RIPEMD160_CTX rip_ctx;
    ripemd160_init(&rip_ctx);
    ripemd160_update(&rip_ctx, sha, 32);
    ripemd160_final(&rip_ctx, out);
}

/* 根据版本字节和 20 字节数据生成 Base58Check 地址 */
int base58check_encode(uint8_t version, const uint8_t *hash20, char *address, size_t addr_len) {
    uint8_t payload[21];
    payload[0] = version;
    memcpy(payload + 1, hash20, 20);
    uint8_t hash1[32], hash2[32];
    sha256(payload, 21, hash1);
    sha256(hash1, 32, hash2);
    uint8_t full[25];
    memcpy(full, payload, 21);
    memcpy(full + 21, hash2, 4);
    size_t encoded_len = addr_len;
    if (!b58enc(address, &encoded_len, full, 25))
         return -1;
    return 0;
}

/* 假定你的 secp256k1.h 中有以下函数 */
void point_to_compressed_hex(const ECPoint *P, char *hex_string);
void point_to_uncompressed_hex(const ECPoint *P, char *hex_string);

/* 新增函数：根据公钥和地址类型生成地址 */
char *public_key_to_address(const char *public_key_hex, const char *address_type) {
    uint8_t pub_bin[65] = {0}; //  65 bytes is enough for compressed *and* uncompressed
    size_t pub_bin_len = strlen(public_key_hex) / 2;

    // Input Validation: Check for valid public key length (66 for compressed, 130 for uncompressed)
    if (pub_bin_len != 33 && pub_bin_len != 65) {
         fprintf(stderr, "Error: Invalid public key length. Must be 66 (compressed) or 130 (uncompressed) hex characters.\n");
         return NULL;
    }

    if (hex2bin(public_key_hex, pub_bin, pub_bin_len) != 0) {
        fprintf(stderr, "Error: Invalid public key hex.\n");
        return NULL;
    }

    uint8_t hash_160[20] = {0};
    hash160(pub_bin, pub_bin_len, hash_160);

    char *address = (char *)malloc(100 * sizeof(char)); // Allocate enough space
    if (address == NULL) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        return NULL;
    }

    if (strcmp(address_type, "P2PKH") == 0) {
        if (base58check_encode(0x00, hash_160, address, 100) != 0) {
            free(address);
            return NULL;
        }
    } else if (strcmp(address_type, "P2SH") == 0) {
        if (base58check_encode(0x05, hash_160, address, 100) != 0) {
            free(address);
            return NULL;
        }
    } else if (strcmp(address_type, "BECH32") == 0) {
        if (segwit_addr_encode(address, "bc", 0, hash_160, 20) != 1) {
            free(address);
            return NULL;
        }
    } else if (strcmp(address_type, "BECH32M") == 0) {
        if (segwit_addr_encode(address, "bc", 1, hash_160, 20) != 1) {
            free(address);
            return NULL;
        }
    } else if (strcmp(address_type, "P2SH-P2WPKH") == 0) {
        // P2SH wrapped P2WPKH: script is hash160(0014<20 byte key hash>), address is base58(script, 0x05 version)
        uint8_t redeem_script[22] = {0x00, 0x14};
        memcpy(redeem_script + 2, hash_160, 20);
        uint8_t redeem_hash160[20] = {0};
        hash160(redeem_script, 22, redeem_hash160);
        if (base58check_encode(0x05, redeem_hash160, address, 100) != 0) {
            free(address);
            return NULL;
        }
    } else if (strcmp(address_type, "P2WSH") == 0) {
        // P2WSH: script hash is hash256(script), address is bech32(witness_version = 0, script_hash)
        uint8_t sha[32];
        sha256(pub_bin, pub_bin_len, sha);  // Use the sha256 function
        if (segwit_addr_encode(address, "bc", 0, sha, 32) != 1) {
            free(address);
            return NULL;
        }
    } else if (strcmp(address_type, "P2WSH-P2WPKH") == 0) { // Corrected typo: P2SH-P2WPKH -> P2WSH-P2WPKH
        // P2WSH wrapped P2WPKH:  redeem_script is 0014<20byte public key hash>, script_hash = sha256(script)
        uint8_t redeem_script[22] = {0x00, 0x14};
        memcpy(redeem_script + 2, hash_160, 20);
        uint8_t sha[32];
        sha256(redeem_script, 22, sha); // Use the sha256 function
        if (segwit_addr_encode(address, "bc", 0, sha, 32) != 1) {
            free(address);
            return NULL;
        }
    } else {
        free(address);
        fprintf(stderr, "Error: Invalid address type.\n");
        return NULL;
    }
    return address;
}

/* 新增函数：生成 Ethereum 地址 */
char *generate_eth_address(const char *public_key_hex) {
    uint8_t pub_bin[130] = {0};
    size_t pub_bin_len = strlen(public_key_hex) / 2;
    if (hex2bin(public_key_hex, pub_bin, pub_bin_len) != 0) {
        fprintf(stderr, "Error: Invalid public key hex for ETH.\n");
        return NULL;
    }

    // 如果存在 '04' 前缀则去掉（非压缩公钥）
    uint8_t *eth_pub_key_bytes = pub_bin;
    size_t eth_pub_key_len = pub_bin_len;
    if (pub_bin_len == 65 && pub_bin[0] == 0x04) {
        eth_pub_key_bytes = pub_bin + 1;
        eth_pub_key_len = 64;
    }

    uint8_t keccak_hash[32];
    keccak_256(eth_pub_key_bytes, eth_pub_key_len, keccak_hash);

    char *address = (char *)malloc(43 * sizeof(char)); // "0x" + 40 字符 + '\0'
    if (address == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for ETH address.\n");
        return NULL;
    }
    address[0] = '0';
    address[1] = 'x';
    for (int i = 0; i < 20; i++) {
        sprintf(address + 2 + i * 2, "%02x", keccak_hash[12 + i]);
    }
    address[42] = '\0';
    return address;
}

/* 新增函数：生成 Tron 地址 */
char *generate_tron_address(const char *public_key_hex) {
    uint8_t pub_bin[130] = {0};
    size_t pub_bin_len = strlen(public_key_hex) / 2;
    if (hex2bin(public_key_hex, pub_bin, pub_bin_len) != 0) {
        fprintf(stderr, "Error: Invalid public key hex for Tron.\n");
        return NULL;
    }

    uint8_t hash_160[20] = {0};
    hash160(pub_bin, pub_bin_len, hash_160);

    char *address = (char *)malloc(100 * sizeof(char));
    if (address == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for Tron address.\n");
        return NULL;
    }

    if (base58check_encode(0x41, hash_160, address, 100) != 0) { // Tron version 0x41
        free(address);
        return NULL;
    }
    return address;
}

/* 新增函数：生成 Dogecoin 地址 */
char *generate_dogecoin_address(const char *public_key_hex) {
    uint8_t pub_bin[130] = {0};
    size_t pub_bin_len = strlen(public_key_hex) / 2;
    if (hex2bin(public_key_hex, pub_bin, pub_bin_len) != 0) {
        fprintf(stderr, "Error: Invalid public key hex for Dogecoin.\n");
        return NULL;
    }

    uint8_t hash_160[20] = {0};
    hash160(pub_bin, pub_bin_len, hash_160);

    char *address = (char *)malloc(100 * sizeof(char));
    if (address == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for Dogecoin address.\n");
        return NULL;
    }

    if (base58check_encode(0x1E, hash_160, address, 100) != 0) { // Dogecoin P2PKH version 0x1E
        free(address);
        return NULL;
    }
    return address;
}

/* 新增函数：生成 Litecoin 地址 */
char *generate_litecoin_address(const char *public_key_hex) {
    uint8_t pub_bin[130] = {0};
    size_t pub_bin_len = strlen(public_key_hex) / 2;
    if (hex2bin(public_key_hex, pub_bin, pub_bin_len) != 0) {
        fprintf(stderr, "Error: Invalid public key hex for Litecoin.\n");
        return NULL;
    }

    uint8_t hash_160[20] = {0};
    hash160(pub_bin, pub_bin_len, hash_160);

    char *address = (char *)malloc(100 * sizeof(char));
    if (address == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for Litecoin address.\n");
        return NULL;
    }

    if (base58check_encode(0x30, hash_160, address, 100) != 0) { // Litecoin P2PKH version 0x30
        free(address);
        return NULL;
    }
    return address;
}

/* 新增函数：生成 Dash 地址 */
char *generate_dash_address(const char *public_key_hex) {
    uint8_t pub_bin[130] = {0};
    size_t pub_bin_len = strlen(public_key_hex) / 2;
    if (hex2bin(public_key_hex, pub_bin, pub_bin_len) != 0) {
        fprintf(stderr, "Error: Invalid public key hex for Dash.\n");
        return NULL;
    }

    uint8_t hash_160[20] = {0};
    hash160(pub_bin, pub_bin_len, hash_160);

    char *address = (char *)malloc(100 * sizeof(char));
    if (address == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for Dash address.\n");
        return NULL;
    }

    if (base58check_encode(0x4C, hash_160, address, 100) != 0) { // Dash P2PKH version 0x4C
        free(address);
        return NULL;
    }
    return address;
}

/* 新增函数：生成 Zcash 地址 (Transparent P2PKH) */
char *generate_zcash_address(const char *public_key_hex) {
    uint8_t pub_bin[130] = {0};
    size_t pub_bin_len = strlen(public_key_hex) / 2;
    if (hex2bin(public_key_hex, pub_bin, pub_bin_len) != 0) {
        fprintf(stderr, "Error: Invalid public key hex for Zcash.\n");
        return NULL;
    }

    uint8_t hash_160[20] = {0};
    hash160(pub_bin, pub_bin_len, hash_160);

    char *address = (char *)malloc(100 * sizeof(char));
    if (address == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for Zcash address.\n");
        return NULL;
    }

    uint8_t zcash_version[2] = {0x1C, 0xB8};
    uint8_t payload[22];
    memcpy(payload, zcash_version, 2);
    memcpy(payload + 2, hash_160, 20);

    uint8_t hash1[32], hash2[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, payload, 22);
    sha256_final(&ctx, hash1);

    sha256_init(&ctx);
    sha256_update(&ctx, hash1, 32);
    sha256_final(&ctx, hash2);

    uint8_t full[26];
    memcpy(full, payload, 22);
    memcpy(full + 22, hash2, 4);
    size_t encoded_len = 100;
    if (!b58enc(address, &encoded_len, full, 26))
         return NULL;
    return address;
}

/* 新增函数：生成 Bitcoin Cash 地址 (Legacy P2PKH - 同 Bitcoin) */
char *generate_bitcoincash_address(const char *public_key_hex) {
    return public_key_to_address(public_key_hex, "P2PKH");
}

/* 新增：生成 Bitcoin Cash CashAddr 地址 */
char *generate_bitcoincash_cashaddr(const char *public_key_hex) {
    uint8_t pub_bin[130] = {0};  // 保存公钥二进制数据
    size_t pub_bin_len = strlen(public_key_hex) / 2;
    if (hex2bin(public_key_hex, pub_bin, pub_bin_len) != 0) {
        fprintf(stderr, "Error: Invalid public key hex for Bitcoin Cash CashAddr.\n");
        return NULL;
    }
    uint8_t hash_160[20] = {0};
    hash160(pub_bin, pub_bin_len, hash_160);
    char hash_hex[41] = {0};
    for (int i = 0; i < 20; i++) {
        sprintf(hash_hex + i * 2, "%02x", hash_160[i]);
    }
    char *address = (char *)malloc(512);
    if (address == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for Bitcoin Cash CashAddr.\n");
        return NULL;
    }
    /* 使用 cashaddr.h 中的 encode_cashaddr 函数，版本号设 0，类型为 "P2PKH"，前缀为 "bitcoincash" */
    if (encode_cashaddr("bitcoincash", 0, "P2PKH", hash_hex, address, 512) != 0) {
        fprintf(stderr, "Error: Encoding Bitcoin Cash CashAddr failed.\n");
        free(address);
        return NULL;
    }
    return address;
}

/* 新增函数：生成 Bitcoin Gold 地址 */
char *generate_bitcoingold_address(const char *public_key_hex) {
    uint8_t pub_bin[130] = {0};
    size_t pub_bin_len = strlen(public_key_hex) / 2;
    if (hex2bin(public_key_hex, pub_bin, pub_bin_len) != 0) {
        fprintf(stderr, "Error: Invalid public key hex for Bitcoin Gold.\n");
        return NULL;
    }

    uint8_t hash_160[20] = {0};
    hash160(pub_bin, pub_bin_len, hash_160);

    char *address = (char *)malloc(100 * sizeof(char));
    if (address == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for Bitcoin Gold address.\n");
        return NULL;
    }

    if (base58check_encode(0x26, hash_160, address, 100) != 0) { // Bitcoin Gold P2PKH version 0x26
        free(address);
        return NULL;
    }
    return address;
}

int main(int argc, char **argv) {
    /* 初始化随机数生成器 */
    srand(time(NULL));

    if (argc != 2) {
        //fprintf(stderr, "Usage: %s <Private Key (Hex or WIF)>\n", argv[0]);
        //fprintf(stderr, "       Or run without arguments to generate a random key.\n");
    }

    /* 初始化 secp256k1 参数 */
    hex_to_bigint(EC_constant_P, &EC_constant_P_BI);
    point_set_infinity(&G);
    hex_to_bigint(EC_constant_Gx, &G.x);
    hex_to_bigint(EC_constant_Gy, &G.y);
    G.infinity = 0;

    // 创建一个新的 ECPointJac 类型的 G_jac
    ECPointJac G_jac;
    point_set_infinity_jac(&G_jac);
    G_jac.X = G.x;
    G_jac.Y = G.y;
    G_jac.Z = (BigInt){1};  // Z 坐标初始化为 1
    G_jac.infinity = false;  // 设置为非无穷点

    char input_key[65] = {0};
    bool is_wif = false, compressed_flag = false;
    char priv_hex[65] = {0};
    char wif[100] = {0};

    if (argc == 2) {
        strcpy(input_key, argv[1]);
        /* 判断输入格式：如果首字符为 '5'、'K' 或 'L' 则认为是 WIF 格式 */
        if (input_key[0] == '5' || input_key[0] == 'K' || input_key[0] == 'L') {
            is_wif = true;
            if (wif_to_private_key(input_key, priv_hex, sizeof(priv_hex), &compressed_flag) != 0) {
                fprintf(stderr, "WIF 解码失败\n");
                return 1;
            }
            printf("WIF Private Key: %s\n", input_key);
            printf("Raw Private Key (Hex): %s\n", priv_hex);
        } else {
            if (strlen(input_key) < 64) {
                char padded[65] = {0};
                int pad = 64 - strlen(input_key);
                memset(padded, '0', pad);
                strcpy(padded + pad, input_key);
                strcpy(priv_hex, padded);
            } else if (strlen(input_key) == 64) {
                strcpy(priv_hex, input_key);
            } else {
                fprintf(stderr, "无效的私钥 hex 长度，应为 64 字符\n");
                return 1;
            }

            char wif_compressed[100] = {0};
            char wif_uncompressed[100] = {0};

            if (private_key_to_wif(priv_hex, true, wif_compressed, sizeof(wif_compressed)) != 0) {
                fprintf(stderr, "私钥转换为压缩 WIF 失败\n");
                return 1;
            }
            if (private_key_to_wif(priv_hex, false, wif_uncompressed, sizeof(wif_uncompressed)) != 0) {
                fprintf(stderr, "私钥转换为非压缩 WIF 失败\n");
                return 1;
            }

            printf("WIF Private Key (Compressed): %s\n", wif_compressed);
            printf("WIF Private Key (Uncompressed): %s\n", wif_uncompressed);
        }
    } else {
        char random_bin[257] = {0};
        if (generateRandomBinary(random_bin, 256) != 0) {
            fprintf(stderr, "随机私钥生成失败\n");
            return 1;
        }
        convertBinaryToHex(random_bin, priv_hex, 256);
        printf("Randomly Generated Raw Private Key (Hex): %s\n", priv_hex);

        char wif_compressed[100] = {0};
        char wif_uncompressed[100] = {0};

        if (private_key_to_wif(priv_hex, true, wif_compressed, sizeof(wif_compressed)) != 0) {
            fprintf(stderr, "私钥转换为压缩 WIF 失败\n");
            return 1;
        }
        if (private_key_to_wif(priv_hex, false, wif_uncompressed, sizeof(wif_uncompressed)) != 0) {
            fprintf(stderr, "私钥转换为非压缩 WIF 失败\n");
            return 1;
        }
        printf("WIF Private Key (Compressed): %s\n", wif_compressed);
        printf("WIF Private Key (Uncompressed): %s\n", wif_uncompressed);
    }

    /* 由私钥计算公钥 */
    BigInt priv;
    hex_to_bigint(priv_hex, &priv);

    ECPointJac pub_jac;  // 使用雅可比坐标
    point_set_infinity_jac(&pub_jac);  // 初始化公钥为无穷点
    ECPoint pub;  // 仿射坐标下的公钥
    point_set_infinity(&pub);  // 初始化为无穷点

    // 使用 G_jac 代替 G 计算公钥
    scalar_multiply_jac(&pub_jac, &G_jac, &priv, &EC_constant_P_BI);

    // 转换到仿射坐标
    jacobian_to_affine(&pub, &pub_jac, &EC_constant_P_BI);

    char pub_hex_comp[67] = {0};
    char pub_hex_uncomp[131] = {0};

    point_to_compressed_hex(&pub, pub_hex_comp);
    point_to_uncompressed_hex(&pub, pub_hex_uncomp);

    printf("\nCompressed Public Key: %s\n", pub_hex_comp);
    printf("Uncompressed Public Key: %s\n", pub_hex_uncomp);

    printf("\n=== Bitcoin Addresses ===\n");
    char *p2pkh_address_compressed = public_key_to_address(pub_hex_comp, "P2PKH");
    if (p2pkh_address_compressed != NULL)
      printf("P2PKH (Starts with 1) Address (Compressed): %s\n", p2pkh_address_compressed);
      free(p2pkh_address_compressed);

    char *p2sh_address_compressed = public_key_to_address(pub_hex_comp, "P2SH");
    if (p2sh_address_compressed != NULL)
      //printf("P2SH (Starts with 3) Address (Compressed): %s (P2SH => P2PKH)\n", p2sh_address_compressed);
    free(p2sh_address_compressed);
    
    char *p2sh_p2wpkh_address_compressed = public_key_to_address(pub_hex_comp, "P2SH-P2WPKH");
        if (p2sh_p2wpkh_address_compressed != NULL)
         printf("P2SH (Starts with 3) Address (Compressed): %s\n", p2sh_p2wpkh_address_compressed);
    free(p2sh_p2wpkh_address_compressed);

    char *bech32_address_compressed = public_key_to_address(pub_hex_comp, "BECH32");
        if (bech32_address_compressed != NULL)
      printf("Bech32 (Starts with bc1) Address (Compressed): %s\n", bech32_address_compressed);
    free(bech32_address_compressed);

    char *bech32m_address_compressed = public_key_to_address(pub_hex_comp, "BECH32M");
        if (bech32m_address_compressed != NULL)
     // printf("Bech32m (Starts with bc1p) Address (Compressed): %s\n", bech32m_address_compressed);
    free(bech32m_address_compressed);

    char *p2wsh_address_compressed = public_key_to_address(pub_hex_comp, "P2WSH");
    if (p2wsh_address_compressed != NULL)
        //printf("P2WSH (Starts with bc1) Address (Compressed): %s (P2WSH => P2PKH)\n", p2wsh_address_compressed);
     free(p2wsh_address_compressed);
     
    char *p2wsh_p2wpkh_address_compressed = public_key_to_address(pub_hex_comp, "P2WSH-P2WPKH");
    if (p2wsh_p2wpkh_address_compressed != NULL)
        //printf("P2WSH (Starts with bc1) Address (Compressed): %s (P2WSH => P2WPKH)\n", p2wsh_p2wpkh_address_compressed);
    free(p2wsh_p2wpkh_address_compressed);
    
    char *p2pkh_address_uncompressed = public_key_to_address(pub_hex_uncomp, "P2PKH");
    if (p2pkh_address_uncompressed != NULL)
      printf("P2PKH (Starts with 1) Address (Uncompressed): %s\n", p2pkh_address_uncompressed);
    free(p2pkh_address_uncompressed);

    char *p2sh_address_uncompressed = public_key_to_address(pub_hex_uncomp, "P2SH");
    if (p2sh_address_uncompressed != NULL)
       //printf("P2SH (Starts with 3) Address (Uncompressed): %s (P2SH => P2PKH)\n", p2sh_address_uncompressed);
    free(p2sh_address_uncompressed);

   char *p2sh_p2wpkh_address_uncompressed = public_key_to_address(pub_hex_uncomp, "P2SH-P2WPKH");
       if (p2sh_p2wpkh_address_uncompressed != NULL)
        printf("P2SH (Starts with 3) Address (Uncompressed): %s\n", p2sh_p2wpkh_address_uncompressed);
    free(p2sh_p2wpkh_address_uncompressed);
    
    char *bech32_address_uncompressed = public_key_to_address(pub_hex_uncomp, "BECH32");
    if (bech32_address_uncompressed != NULL)
      printf("Bech32 (Starts with bc1) Address (Uncompressed): %s\n", bech32_address_uncompressed);
    free(bech32_address_uncompressed);

    char *bech32m_address_uncompressed = public_key_to_address(pub_hex_uncomp, "BECH32M");
      if (bech32m_address_uncompressed != NULL)
      //printf("Bech32m (Starts with bc1p) Address (Uncompressed): %s\n", bech32m_address_uncompressed);
    free(bech32m_address_uncompressed);
    
    char *p2wsh_address_uncompressed = public_key_to_address(pub_hex_uncomp, "P2WSH");
        if (p2wsh_address_uncompressed != NULL)
      //printf("P2WSH (Starts with bc1) Address (Uncompressed): %s (P2WSH => P2PKH)\n", p2wsh_address_uncompressed);
    free(p2wsh_address_uncompressed);
    
    char *p2wsh_p2wpkh_address_uncompressed = public_key_to_address(pub_hex_uncomp, "P2WSH-P2WPKH");
        if (p2wsh_p2wpkh_address_uncompressed != NULL)
      //printf("P2WSH (Starts with bc1) Address (Uncompressed): %s (P2WSH => P2WPKH)\n", p2wsh_p2wpkh_address_uncompressed);
   free(p2wsh_p2wpkh_address_uncompressed);
    

        printf("\n=== Ethereum Address ===\n");
    char *eth_address = generate_eth_address(pub_hex_uncomp);
    if (eth_address != NULL)
        printf("Ethereum Address: %s\n", eth_address);
    free(eth_address);

    printf("\n=== TRON (TRX) Address ===\n");
    char *trx_address = generate_tron_address(pub_hex_uncomp);
    if (trx_address != NULL)
        printf("TRON (TRX) Address: %s\n", trx_address);
    free(trx_address);

    printf("\n=== Dogecoin Addresses ===\n");
    char *doge_address_compressed = generate_dogecoin_address(pub_hex_comp);
    if (doge_address_compressed != NULL)
        printf("P2PKH Address (Compressed): %s\n", doge_address_compressed);
    free(doge_address_compressed);
    char *doge_address_uncompressed = generate_dogecoin_address(pub_hex_uncomp);
    if (doge_address_uncompressed != NULL)
        printf("P2PKH Address (Uncompressed): %s\n", doge_address_uncompressed);
    free(doge_address_uncompressed);

    printf("\n=== Litecoin Addresses ===\n");
    char *ltc_address_compressed = generate_litecoin_address(pub_hex_comp);
    if (ltc_address_compressed != NULL)
        printf("P2PKH Address (Compressed): %s\n", ltc_address_compressed);
    free(ltc_address_compressed);
    char *ltc_address_uncompressed = generate_litecoin_address(pub_hex_uncomp);
    if (ltc_address_uncompressed != NULL)
        printf("P2PKH Address (Uncompressed): %s\n", ltc_address_uncompressed);
    free(ltc_address_uncompressed);

    printf("\n=== Dash Addresses ===\n");
    char *dash_address_compressed = generate_dash_address(pub_hex_comp);
    if (dash_address_compressed != NULL)
        printf("P2PKH Address (Compressed): %s\n", dash_address_compressed);
    free(dash_address_compressed);
    char *dash_address_uncompressed = generate_dash_address(pub_hex_uncomp);
    if (dash_address_uncompressed != NULL)
        printf("P2PKH Address (Uncompressed): %s\n", dash_address_uncompressed);
    free(dash_address_uncompressed);

    printf("\n=== Zcash (Transparent) Addresses ===\n");
    char *zec_address_compressed = generate_zcash_address(pub_hex_comp);
    if (zec_address_compressed != NULL)
        printf("P2PKH Address (Compressed): %s\n", zec_address_compressed);
    free(zec_address_compressed);
    char *zec_address_uncompressed = generate_zcash_address(pub_hex_uncomp);
    if (zec_address_uncompressed != NULL)
        printf("P2PKH Address (Uncompressed): %s\n", zec_address_uncompressed);
    free(zec_address_uncompressed);

    printf("\n=== Bitcoin Cash Addresses (Legacy) ===\n");
    char *bch_address_compressed = generate_bitcoincash_address(pub_hex_comp);
    if (bch_address_compressed != NULL)
        printf("P2PKH Address (Compressed): %s\n", bch_address_compressed);
    free(bch_address_compressed);
    char *bch_address_uncompressed = generate_bitcoincash_address(pub_hex_uncomp);
    if (bch_address_uncompressed != NULL)
        printf("P2PKH Address (Uncompressed): %s\n", bch_address_uncompressed);
    free(bch_address_uncompressed);

    printf("\n=== Bitcoin Cash Addresses (CashAddr) ===\n");
    char *bch_cashaddr_compressed = generate_bitcoincash_cashaddr(pub_hex_comp);
    if (bch_cashaddr_compressed != NULL)
        printf("CashAddr (Compressed): %s\n", bch_cashaddr_compressed);
    free(bch_cashaddr_compressed);
    char *bch_cashaddr_uncompressed = generate_bitcoincash_cashaddr(pub_hex_uncomp);
    if (bch_cashaddr_uncompressed != NULL)
        printf("CashAddr (Uncompressed): %s\n", bch_cashaddr_uncompressed);
    free(bch_cashaddr_uncompressed);

    printf("\n=== Bitcoin Gold Addresses ===\n");
    char *btg_address_compressed = generate_bitcoingold_address(pub_hex_comp);
    if (btg_address_compressed != NULL)
        printf("P2PKH Address (Compressed): %s\n", btg_address_compressed);
    free(btg_address_compressed);
    char *btg_address_uncompressed = generate_bitcoingold_address(pub_hex_uncomp);
    if (btg_address_uncompressed != NULL)
        printf("P2PKH Address (Uncompressed): %s\n", btg_address_uncompressed);
    free(btg_address_uncompressed);

    return 0;
}

