#pragma once
#include <vector>
#include <cstdint>

class RC4 {
public:
    RC4(const std::vector<uint8_t>& key);

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);
    void reset();
    void initialize(const std::vector<uint8_t>& key);
    void example();

private:
    std::vector<uint8_t> process(const std::vector<uint8_t>& data);

    std::vector<uint8_t> S;
    std::vector<uint8_t> key;
};

