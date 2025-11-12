#ifndef RMD5_H
#define RMD5_H

#include <string>
#include <vector>
#include <cstdint>

class RMD5 {
private:
    typedef uint32_t uint32;
    typedef uint8_t uint8;

    // Константы для MD5
    static const uint32 T[64];
    static const uint32 S[64];

    // Начальные значения буфера
    static const uint32 A0;
    static const uint32 B0;
    static const uint32 C0;
    static const uint32 D0;

    // Вспомогательные функции
    static uint32 F(uint32 x, uint32 y, uint32 z);
    static uint32 G(uint32 x, uint32 y, uint32 z);
    static uint32 H(uint32 x, uint32 y, uint32 z);
    static uint32 I(uint32 x, uint32 y, uint32 z);
    static uint32 rotateLeft(uint32 x, uint32 n);
    static uint32 toLittleEndian(uint32 x);

    // Внутренние методы
    static std::vector<uint8> padMessage(const std::vector<uint8>& data);
    static std::string toHexString(const std::vector<uint8_t>& hash);

public:
    // Основные методы хэширования
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data);

    // Вспомогательные методы для преобразования в строку
    static std::string hashToHexString(const std::vector<uint8_t>& data);
};

#endif // RMD5_H
