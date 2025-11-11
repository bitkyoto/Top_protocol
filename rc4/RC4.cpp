#include "RC4.h"
#include <algorithm>
#include <stdexcept>
#include <fstream>
#include <iostream>
#include <iomanip>

RC4::RC4(const std::vector<uint8_t>& key) {
    this->key = key;
    initialize(key);
}

std::vector<uint8_t> RC4::encrypt(const std::vector<uint8_t>& plaintext) {
    return process(plaintext);
}

std::vector<uint8_t> RC4::decrypt(const std::vector<uint8_t>& ciphertext) {
    return process(ciphertext);
}

void RC4::reset() {
    S.resize(256);
    for (int k = 0; k < 256; ++k) {
        S[k] = static_cast<uint8_t>(k);
    }

    uint8_t k = 0;
    for (int d = 0; d < 256; ++d) {
        k = k + S[d] + this->key[d % this->key.size()];
        std::swap(S[d], S[k]);
    }
}

void RC4::initialize(const std::vector<uint8_t>& key) {
    if (key.empty()) {
        throw std::invalid_argument("Key cannot be empty");
    }

    S.resize(256);
    for (int k = 0; k < 256; ++k) {
        S[k] = static_cast<uint8_t>(k);
    }

    uint8_t k = 0;
    for (int d = 0; d < 256; ++d) {
        k = k + S[d] + key[d % key.size()];
        std::swap(S[d], S[k]);
    }
}

void RC4::example() {
    std::vector<uint8_t> ifile_content;
    std::ifstream file("test.txt", std::ios::binary);
    if (file.is_open()) {
        char ch;
        while (file.get(ch)) {
            ifile_content.push_back(static_cast<uint8_t>(ch));
        }
        file.close();
    }

    std::cout << "File content: ";
    for (auto ch : ifile_content) {
        std::cout << static_cast<char>(ch);
    }
    std::cout << std::endl;

    auto encrypted_text = this->encrypt(ifile_content);
    std::cout << "Encrypted file: ";
    for (auto byte : encrypted_text) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;

    this->reset();

    auto decrypted_text = this->decrypt(encrypted_text);
    std::cout << "Decrypted file: ";
    for (auto byte : decrypted_text) {
        std::cout << static_cast<char>(byte);
    }
    std::cout << std::endl;
}

std::vector<uint8_t> RC4::process(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result;
    result.reserve(data.size());

    uint8_t current_i = 0;
    uint8_t current_j = 0;

    for (uint8_t byte : data) {
        current_i = current_i + 1;
        current_j = current_j + S[current_i];
        std::swap(S[current_i], S[current_j]);
        uint8_t k = S[static_cast<uint8_t>(S[current_i] + S[current_j])];
        result.push_back(byte ^ k);
    }

    return result;
}