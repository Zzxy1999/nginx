#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_http_v2.h>
#include <ngx_md5.h>
#include <openssl/sha.h>

#include <nginx_ssl_fingerprint.h>

#define IS_GREASE_CODE(code) (((code)&0x0f0f) == 0x0a0a && ((code)&0xff) == ((code)>>8))

// JA4 辅助函数：比较函数用于排序
static int ja4_uint16_compare(const void *a, const void *b) {
    uint16_t val_a = *(const uint16_t*)a;
    uint16_t val_b = *(const uint16_t*)b;
    return (val_a > val_b) - (val_a < val_b);
}

// JA4 辅助函数：将uint16转换为4位十六进制字符串（小写）
static void ja4_uint16_to_hex4(uint16_t val, unsigned char *buf) {
    static const char hex_chars[] = "0123456789abcdef";
    buf[0] = hex_chars[(val >> 12) & 0xf];
    buf[1] = hex_chars[(val >> 8) & 0xf];
    buf[2] = hex_chars[(val >> 4) & 0xf];
    buf[3] = hex_chars[val & 0xf];
}

static inline
unsigned char *append_uint8(unsigned char* dst, uint8_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;
    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;
    } else {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;
    }

    return dst;
}

static inline
unsigned char *append_uint16(unsigned char* dst, uint16_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;
    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;
    } else if (n < 1000) {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;
    }  else if (n < 10000) {
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 4;
    } else {
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 5;
    }

    return dst;
}

static inline
unsigned char *append_uint32(unsigned char* dst, uint32_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;
    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;
    } else if (n < 1000) {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;
    } else if (n < 10000) {
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 4;
    } else if (n < 100000) {
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 5;
    } else if (n < 1000000) {
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 6;
    } else if (n < 10000000) {
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 7;
    } else if (n < 100000000) {
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 8;
    } else if (n < 1000000000) {
        dst[8] = n % 10 + '0';
        n /= 10;
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 9;
    } else {
        dst[9] = n % 10 + '0';
        n /= 10;
        dst[8] = n % 10 + '0';
        n /= 10;
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 10;
    }

    return dst;
}


/**
 * Params:
 *      c and c->ssl should be valid pointers
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja3_str is already set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_ja_data(ngx_connection_t *c)
{
    u_char *ptr = NULL, *data = NULL, *ja4_header_ptr = NULL, *ja4_cipher_ptr = NULL, *ja4_ext_ptr = NULL;
    size_t num = 0, i;
    uint16_t n;

    data = c->ssl->fp_ja_data.data;
    if (data == NULL) {
        return NGX_ERROR;
    }

    if (c->ssl->fp_ja3_str.data != NULL) {
        return NGX_OK;
    }

    // client hello的长度限制为16KB，乘以3是安全的
    c->ssl->fp_ja3_str.len = c->ssl->fp_ja_data.len * 3;
    c->ssl->fp_ja3_str.data = ngx_pnalloc(c->pool, c->ssl->fp_ja3_str.len);
    if (c->ssl->fp_ja3_str.data == NULL) {
        c->ssl->fp_ja3_str.len = 0;
        return NGX_ERROR;
    }
    // 20足够
    c->ssl->fp_ja4_header.len = 20;
    c->ssl->fp_ja4_header.data = ngx_pnalloc(c->pool, c->ssl->fp_ja4_header.len);
    if (c->ssl->fp_ja4_header.data == NULL) {
        c->ssl->fp_ja4_header.len = 0;
        return NGX_ERROR;
    }
    c->ssl->fp_ja4_cipher.len = c->ssl->fp_ja_data.len * 3;
    c->ssl->fp_ja4_cipher.data = ngx_pnalloc(c->pool, c->ssl->fp_ja4_cipher.len);
    if (c->ssl->fp_ja4_cipher.data == NULL) {
        c->ssl->fp_ja4_cipher.len = 0;
        return NGX_ERROR;
    }
    c->ssl->fp_ja4_ext.len = c->ssl->fp_ja_data.len * 3;
    c->ssl->fp_ja4_ext.data = ngx_pnalloc(c->pool, c->ssl->fp_ja4_ext.len);
    if (c->ssl->fp_ja4_ext.data == NULL) {
        c->ssl->fp_ja4_ext.len = 0;
        return NGX_ERROR;
    }

    ptr = c->ssl->fp_ja3_str.data;
    ja4_header_ptr = c->ssl->fp_ja4_header.data;
    ja4_cipher_ptr = c->ssl->fp_ja4_cipher.data;
    ja4_ext_ptr = c->ssl->fp_ja4_ext.data;
    
    /* tcp */
    *ja4_header_ptr++ = 't';

    /* version */
    ptr = append_uint16(ptr, *(uint16_t*)data);
    *ptr++ = ',';
    if (*(uint16_t*)data == TLS1_VERSION) {
        *ja4_header_ptr++ = '1';
        *ja4_header_ptr++ = '0';
    } else if (*(uint16_t*)data == TLS1_1_VERSION) {
        *ja4_header_ptr++ = '1';
        *ja4_header_ptr++ = '1';
    } else if (*(uint16_t*)data == TLS1_2_VERSION) {
        *ja4_header_ptr++ = '1';
        *ja4_header_ptr++ = '2';
    } else if (*(uint16_t*)data == TLS1_3_VERSION) {
        *ja4_header_ptr++ = '1';
        *ja4_header_ptr++ = '3';
    }
    data += 2;

    /* sni */
    *ja4_header_ptr++ = *data++;

    /* ciphers */
    num = *(uint16_t*)data;
    
    // JA4: 动态分配密码套件数组（每个密码套件2字节，所以最多num/2个）
    uint16_t *cipher_array = ngx_pnalloc(c->pool, (num/2) * sizeof(uint16_t));
    if (cipher_array == NULL) {
        return NGX_ERROR;
    }
    size_t cipher_count = 0;
    
    for (i = 2; i <= num; i += 2) {
        n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i+1]);
        if (!IS_GREASE_CODE(n)) {
            // JA3 处理
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
            
            // JA4 处理：收集密码套件
            cipher_array[cipher_count++] = n;
        }
    }
    *(ptr-1) = ',';
    
    // JA4 header: cipher count (固定2位十进制，超过99截断)
    uint16_t cipher_count_truncated = cipher_count > 99 ? 99 : cipher_count;
    *ja4_header_ptr++ = (cipher_count_truncated / 10) + '0';
    *ja4_header_ptr++ = (cipher_count_truncated % 10) + '0';
    
    // JA4: 排序密码套件
    qsort(cipher_array, cipher_count, sizeof(uint16_t), ja4_uint16_compare);
    
    // JA4: 生成排序后的十六进制字符串
    for (i = 0; i < cipher_count; i++) {
        ja4_uint16_to_hex4(cipher_array[i], (unsigned char*)ja4_cipher_ptr);
        ja4_cipher_ptr += 4;
        if (i < cipher_count - 1) {
            *ja4_cipher_ptr++ = ',';
        }
    }
    
    data += 2 + num;

    /* extensions */
    num = *(uint16_t*)data;
    
    // JA4: 动态分配扩展数组（每个扩展2字节，所以最多num/2个）
    uint16_t *ext_array = ngx_pnalloc(c->pool, (num/2) * sizeof(uint16_t));
    if (ext_array == NULL) {
        return NGX_ERROR;
    }
    size_t ext_count = 0;
    
    for (i = 2; i <= num; i += 2) {
        n = *(uint16_t*)(data + i);
        if (!IS_GREASE_CODE(n)) {
            // JA3 处理
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
            if (n != 0x0000 && n != 0x0010) {
                // JA4 处理：收集扩展
                ext_array[ext_count++] = n;
            }
        }
    }
    
    if (num != 0) {
        *(ptr-1) = ',';
        data += 2 + num;
    } else {
        *(ptr++) = ',';
    }
    
    // JA4 header: extension count (固定2位十进制，超过99截断)
    uint16_t ext_count_truncated = ext_count > 99 ? 99 : ext_count;
    *ja4_header_ptr++ = (ext_count_truncated / 10) + '0';
    *ja4_header_ptr++ = (ext_count_truncated % 10) + '0';
    
    // JA4: 排序扩展
    qsort(ext_array, ext_count, sizeof(uint16_t), ja4_uint16_compare);
    
    // JA4: 生成排序后的十六进制字符串
    for (i = 0; i < ext_count; i++) {
        ja4_uint16_to_hex4(ext_array[i], (unsigned char*)ja4_ext_ptr);
        ja4_ext_ptr += 4;
        if (i < ext_count - 1) {
            *ja4_ext_ptr++ = ',';
        }
    }


    /* groups */
    num = *(uint16_t*)data;
    for (i = 2; i < num; i += 2) {
        n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i+1]);
        if (!IS_GREASE_CODE(n)) {
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        }
    }
    if (num != 0) {
        *(ptr-1) = ',';
        data += num;
    } else {
        *(ptr++) = ',';
    }

    /* formats */
    num = *(uint8_t*)data;
    for (i = 1; i < num; i++) {
        ptr = append_uint16(ptr, (uint16_t)data[i]);
        *ptr++ = '-';
    }
    if (num != 0) {
        data += num;
        *(ptr-1) = ',';
        *ptr-- = 0;
    }

    /* ja3 end */
    c->ssl->fp_ja3_str.len = ptr - c->ssl->fp_ja3_str.data;

    /* alpn - JA4处理 */
    num = *(uint16_t*)data;
    if (num > 0) {
        data += 2; // 跳过总长度字段(2字节)
        // ALPN格式：总长度(2字节) + [协议长度(1字节) + 协议名] + [协议长度(1字节) + 协议名] ...
        size_t alpn_data_len = num - 2; // 实际ALPN数据长度，减去长度字段
        if (alpn_data_len >= 2) { // 至少需要2字节：第一个协议长度(1) + 协议名至少1字符
            uint8_t first_proto_len = data[0]; // 第一个协议的长度
            if (first_proto_len >= 1 && (size_t)(first_proto_len + 1) <= alpn_data_len) {
                // 取第一个协议名
                unsigned char *proto_name = &data[1];
                
                // 构建ALPN字符串：按照Python逻辑处理
                unsigned char alpn_str[3] = {0}; // 最多2个字符+结束符  
                if (first_proto_len > 2) {
                    // 长度>2时取首尾字符: alpn = f"{alpn[0]}{alpn[-1]}"
                    alpn_str[0] = proto_name[0];
                    alpn_str[1] = proto_name[first_proto_len - 1];
                } else {
                    // 长度<=2时保持原样，但需要补齐到2位
                    if (first_proto_len >= 1) {
                        alpn_str[0] = proto_name[0];
                    } else {
                        alpn_str[0] = '0';
                    }
                    if (first_proto_len >= 2) {
                        alpn_str[1] = proto_name[1];
                    } else {
                        alpn_str[1] = '0'; // 长度=1时第二位补0
                    }
                }
                
                // 检查首字符ASCII值是否>127
                if (alpn_str[0] > 127) {
                    *ja4_header_ptr++ = '9';
                    *ja4_header_ptr++ = '9';
                } else {
                    // 直接输出首尾字符（2个字符）
                    *ja4_header_ptr++ = alpn_str[0];
                    *ja4_header_ptr++ = alpn_str[1];
                }
            } else {
                // 第一个协议格式异常，使用00
                *ja4_header_ptr++ = '0';
                *ja4_header_ptr++ = '0';
            }
        } else {
            // ALPN数据太短，使用00
            *ja4_header_ptr++ = '0';
            *ja4_header_ptr++ = '0';
        }
        data += (num - 2); // 跳过ALPN数据（不包括已跳过的长度字段）
    } else {
        // 没有ALPN，使用00
        *ja4_header_ptr++ = '0';
        *ja4_header_ptr++ = '0';
        data += 2; // 跳过长度字段(值为0)
    }

    /* algorithm - JA4处理 */
    num = *(uint16_t*)data;
    num -= 2; // 减去长度字段
    if (num > 0) {
        data += 2; // 跳过长度字段
        
        // JA4: 动态分配算法数组（每个算法2字节，所以最多num/2个）
        uint16_t *algo_array = ngx_pnalloc(c->pool, (num/2) * sizeof(uint16_t));
        if (algo_array == NULL) {
            return NGX_ERROR;
        }
        size_t algo_count = 0;
        
        // 收集算法（类似密码套件处理）
        for (i = 0; i < num; i += 2) {
            n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i+1]);
            if (!IS_GREASE_CODE(n)) {
                algo_array[algo_count++] = n;
            }
        }
        
        // 将算法拼接到扩展字段中
        if (algo_count > 0) {
            // 检查扩展字段是否已有数据
            if (ja4_ext_ptr > c->ssl->fp_ja4_ext.data) {
                // 扩展字段有数据，用下划线连接
                *ja4_ext_ptr++ = '_';
            }
            
            // 生成排序后的算法十六进制字符串
            for (i = 0; i < algo_count; i++) {
                ja4_uint16_to_hex4(algo_array[i], (unsigned char*)ja4_ext_ptr);
                ja4_ext_ptr += 4;
                if (i < algo_count - 1) {
                    *ja4_ext_ptr++ = ',';
                }
            }
        }
        
        data += num; // 跳过算法数据
    } else {
        data += 2; // 跳过长度字段(值为0)
    }

    /* 设置JA4字段长度 */
    *ja4_header_ptr = '\0';
    c->ssl->fp_ja4_header.len = ja4_header_ptr - c->ssl->fp_ja4_header.data;
    
    *ja4_cipher_ptr = '\0';
    c->ssl->fp_ja4_cipher.len = ja4_cipher_ptr - c->ssl->fp_ja4_cipher.data;
    
    *ja4_ext_ptr = '\0';
    c->ssl->fp_ja4_ext.len = ja4_ext_ptr - c->ssl->fp_ja4_ext.data;

    return NGX_OK;
}

/**
 * Params:
 *      c and c->ssl should be valid pointers and tested before.
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja3_hash is alread set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_ja3_hash(ngx_connection_t *c)
{
    ngx_md5_t ctx;
    u_char hash_buf[16];

    if (c->ssl->fp_ja3_hash.len > 0) {
        return NGX_OK;
    }

    if (ngx_ssl_ja_data(c) != NGX_OK) {
        return NGX_ERROR;
    }

    c->ssl->fp_ja3_hash.len = 32;
    c->ssl->fp_ja3_hash.data = ngx_pnalloc(c->pool, c->ssl->fp_ja3_hash.len);
    if (c->ssl->fp_ja3_hash.data == NULL) {
        /** Else we can break a stream */
        c->ssl->fp_ja3_hash.len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_ssl_ja3_hash: alloc bytes: [%d]\n", c->ssl->fp_ja3_hash.len);

    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, c->ssl->fp_ja3_str.data, c->ssl->fp_ja3_str.len);
    ngx_md5_final(hash_buf, &ctx);
    ngx_hex_dump(c->ssl->fp_ja3_hash.data, hash_buf, 16);

    return NGX_OK;
}

/**
 * Params:
 *      c and h2c should be a valid pointers
 *
 * Returns:
 *      NGX_OK -- h2c->fp_str is set
 *      NGX_ERROR -- something went wrong
 */
int ngx_http2_fingerprint(ngx_connection_t *c, ngx_http_v2_connection_t *h2c)
{
    unsigned char *pstr = NULL;
    unsigned short n = 0;
    size_t i;

    if (h2c->fp_str.len > 0) {
        return NGX_OK;
    }

    n = 4 + h2c->fp_settings.len * 3
        + 10 + h2c->fp_priorities.len * 2
        + h2c->fp_pseudoheaders.len * 2;

    h2c->fp_str.data = ngx_pnalloc(c->pool, n);
    if (h2c->fp_str.data == NULL) {
        /** Else we break a stream */
        return NGX_ERROR;
    }
    pstr = h2c->fp_str.data;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_http2_fingerprint: alloc bytes: [%d]\n", n);

    /* setting */
    for (i = 0; i < h2c->fp_settings.len; i+=5) {
        pstr = append_uint8(pstr, h2c->fp_settings.data[i]);
        *pstr++ = ':';
        pstr = append_uint32(pstr, *(uint32_t*)(h2c->fp_settings.data+i+1));
        *pstr++ = ';';
    }
    *(pstr-1) = '|';

    /* windows update */
    pstr = append_uint32(pstr, h2c->fp_windowupdate);
    *pstr++ = '|';

    /* priorities */
    for (i = 0; i < h2c->fp_priorities.len; i+=4) {
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i]);
        *pstr++ = ':';
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i+1]);
        *pstr++ = ':';
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i+2]);
        *pstr++ = ':';
        pstr = append_uint16(pstr, (uint16_t)h2c->fp_priorities.data[i+3]+1);
        *pstr++ = ',';
    }
    *(pstr-1) = '|';

    /* fp_pseudoheaders */
    for (i = 0; i < h2c->fp_pseudoheaders.len; i++) {
        *pstr++ = h2c->fp_pseudoheaders.data[i];
        *pstr++ = ',';
    }

    /* null terminator */
    *--pstr = 0;

    h2c->fp_str.len = pstr - h2c->fp_str.data;

    h2c->fp_fingerprinted = 1;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_http2_fingerprint: http2 fingerprint: [%V], len=[%d]\n", &h2c->fp_str, h2c->fp_str.len);

    return NGX_OK;
}

/**
 * JA4 header wrapper function
 */
int ngx_ssl_ja4_header(ngx_connection_t *c)
{
    if (c->ssl->fp_ja4_header.len > 0) {
        return NGX_OK;
    }

    // JA4 header通过ngx_ssl_ja_data计算
    if (ngx_ssl_ja_data(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * JA4 cipher wrapper function
 */
int ngx_ssl_ja4_cipher(ngx_connection_t *c)
{
    if (c->ssl->fp_ja4_cipher.len > 0) {
        return NGX_OK;
    }

    // JA4 cipher通过ngx_ssl_ja_data计算
    if (ngx_ssl_ja_data(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * JA4 ext wrapper function  
 */
int ngx_ssl_ja4_ext(ngx_connection_t *c)
{
    if (c->ssl->fp_ja4_ext.len > 0) {
        return NGX_OK;
    }

    // JA4 ext通过ngx_ssl_ja_data计算
    if (ngx_ssl_ja_data(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * JA4 hash function - 完整的JA4指纹
 */
int ngx_ssl_ja4_hash(ngx_connection_t *c)
{
    SHA256_CTX sha256_ctx;
    
    if (c->ssl->fp_ja4_hash.len > 0) {
        return NGX_OK;
    }

    // 确保所有JA4组件都已计算
    if (ngx_ssl_ja4_header(c) != NGX_OK ||
        ngx_ssl_ja4_cipher(c) != NGX_OK ||
        ngx_ssl_ja4_ext(c) != NGX_OK) {
        return NGX_ERROR;
    }

    // 计算cipher部分的SHA256哈希
    unsigned char cipher_hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, c->ssl->fp_ja4_cipher.data, c->ssl->fp_ja4_cipher.len);
    SHA256_Final(cipher_hash, &sha256_ctx);
    
    // 将cipher哈希转换为十六进制字符串（前12个字符）
    char cipher_hex[25] = {0}; // 12*2 + 1
    for (int i = 0; i < 12; i++) {
        sprintf(cipher_hex + i*2, "%02x", cipher_hash[i]);
    }
    cipher_hex[24] = '\0';

    // 计算extension部分的SHA256哈希
    unsigned char ext_hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, c->ssl->fp_ja4_ext.data, c->ssl->fp_ja4_ext.len);
    SHA256_Final(ext_hash, &sha256_ctx);
    
    // 将extension哈希转换为十六进制字符串（前12个字符）
    char ext_hex[25] = {0}; // 12*2 + 1
    for (int i = 0; i < 12; i++) {
        sprintf(ext_hex + i*2, "%02x", ext_hash[i]);
    }
    ext_hex[24] = '\0';

    // 分配JA4哈希存储空间
    // 格式: header_cipher_hash_ext_hash
    size_t total_len = c->ssl->fp_ja4_header.len + 1 + 24 + 1 + 24;
    
    c->ssl->fp_ja4_hash.data = ngx_pnalloc(c->pool, total_len + 1);
    if (c->ssl->fp_ja4_hash.data == NULL) {
        return NGX_ERROR;
    }

    // 拼接: header_cipher_hash_ext_hash
    u_char *ptr = c->ssl->fp_ja4_hash.data;
    
    ngx_memcpy(ptr, c->ssl->fp_ja4_header.data, c->ssl->fp_ja4_header.len);
    ptr += c->ssl->fp_ja4_header.len;
    *ptr++ = '_';
    
    ngx_memcpy(ptr, cipher_hex, 24);
    ptr += 24;
    *ptr++ = '_';
    
    ngx_memcpy(ptr, ext_hex, 24);
    ptr += 24;
    *ptr = '\0';
    
    c->ssl->fp_ja4_hash.len = ptr - c->ssl->fp_ja4_hash.data;

    return NGX_OK;
}
