/*Author: 8891689
 * Assist in creation ：ChatGPT 
 */
#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE 32  // 输出哈希长度为32字节

// SHA256上下文结构体
typedef struct {
    uint8_t data[64];         // 数据缓冲区
    uint32_t datalen;         // 当前缓冲区中的数据长度
    unsigned long long bitlen;// 累计处理的位数
    uint32_t state[8];        // 当前哈希状态
} SHA256_CTX;

// 初始化SHA256上下文
void sha256_init(SHA256_CTX *ctx);
// 更新数据
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
// 完成哈希计算，输出最终的哈希值
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);
// 辅助函数，一次性计算输入数据的sha256哈希值
void sha256(const uint8_t *data, size_t len, uint8_t *hash);

#endif // SHA256_H

