#include "md5.h"
#include <cstring>
#include <cmath>

// Константы MD5
static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint32_t s[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

// Вспомогательные функции
inline uint32_t F(uint32_t x, uint32_t y, uint32_t z){ return (x & y) | (~x & z);}
inline uint32_t G(uint32_t x, uint32_t y, uint32_t z){ return (x & z) | (y & ~z);}
inline uint32_t H(uint32_t x, uint32_t y, uint32_t z){ return x ^ y ^ z;}
inline uint32_t I(uint32_t x, uint32_t y, uint32_t z){ return y ^ (x | ~z);}
inline uint32_t rotate_left(uint32_t x, uint32_t n){ return (x << n) | (x >> (32-n));}

MD5::MD5() : finalized(false), bitlen(0) {
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
    memset(buffer, 0, 64);
}

void MD5::update(const std::vector<uint8_t>& data) {
    if(finalized) return;
    size_t i = 0;
    size_t index = bitlen/8 % 64;
    bitlen += data.size() * 8;
    while(i < data.size()){
        buffer[index++] = data[i++];
        if(index == 64){
            processBlock(buffer);
            index = 0;
        }
    }
}

void MD5::processBlock(const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t M[16];
    for(int i=0;i<16;i++){
        M[i] = block[i*4] | (block[i*4+1]<<8) | (block[i*4+2]<<16) | (block[i*4+3]<<24);
    }
    for(int i=0;i<64;i++){
        uint32_t f, g;
        if(i<16){ f=F(b,c,d); g=i;}
        else if(i<32){ f=G(b,c,d); g=(5*i+1)%16;}
        else if(i<48){ f=H(b,c,d); g=(3*i+5)%16;}
        else{ f=I(b,c,d); g=(7*i)%16;}
        uint32_t temp = d;
        d = c;
        c = b;
        b = b + rotate_left(a+f+K[i]+M[g], s[i]);
        a = temp;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void MD5::finalize(){
    if(finalized) return;
    uint8_t padding[64] = {0x80};
    uint64_t bitlen_le = bitlen;
    size_t index = bitlen/8 % 64;
    size_t pad_len = (index < 56) ? (56 - index) : (120 - index);
    update(std::vector<uint8_t>(padding, padding + pad_len));
    uint8_t len_bytes[8];
    for(int i=0;i<8;i++) len_bytes[i] = (bitlen_le >> (8*i)) & 0xFF;
    update(std::vector<uint8_t>(len_bytes, len_bytes+8));
    finalized = true;
}

std::vector<uint8_t> MD5::digest(){
    finalize();
    std::vector<uint8_t> out(16);
    for(int i=0;i<4;i++){
        out[i*4] = state[i] & 0xFF;
        out[i*4+1] = (state[i]>>8) & 0xFF;
        out[i*4+2] = (state[i]>>16) & 0xFF;
        out[i*4+3] = (state[i]>>24) & 0xFF;
    }
    return out;
}

std::vector<uint8_t> MD5::hash(const std::vector<uint8_t>& data){
    MD5 md5;
    md5.update(data);
    return md5.digest();
}
