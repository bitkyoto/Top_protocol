#pragma once
#include <vector>
#include <cstdint>
#include <string>

class MD5 {
public:
    MD5();
    void update(const std::vector<uint8_t>& data);
    std::vector<uint8_t> digest();
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data);

private:
    void processBlock(const uint8_t block[64]);
    void finalize();

    bool finalized;
    uint64_t bitlen;
    uint8_t buffer[64];
    uint32_t state[4]; // A, B, C, D
};
