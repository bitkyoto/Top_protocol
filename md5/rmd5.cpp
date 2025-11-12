#include "RMD5.h"
#include <iostream>
#include <cstring>
#include <sstream>
#include <iomanip>

using namespace std;

// Инициализация статических констант
const RMD5::uint32 RMD5::A0 = 0x67452301;
const RMD5::uint32 RMD5::B0 = 0xEFCDAB89;
const RMD5::uint32 RMD5::C0 = 0x98BADCFE;
const RMD5::uint32 RMD5::D0 = 0x10325476;

const RMD5::uint32 RMD5::T[64] = {
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

const RMD5::uint32 RMD5::S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

// Реализации вспомогательных функций
RMD5::uint32 RMD5::F(uint32 x, uint32 y, uint32 z) {
    return (x & y) | (~x & z);
}

RMD5::uint32 RMD5::G(uint32 x, uint32 y, uint32 z) {
    return (x & z) | (y & ~z);
}

RMD5::uint32 RMD5::H(uint32 x, uint32 y, uint32 z) {
    return x ^ y ^ z;
}

RMD5::uint32 RMD5::I(uint32 x, uint32 y, uint32 z) {
    return y ^ (x | ~z);
}

RMD5::uint32 RMD5::rotateLeft(uint32 x, uint32 n) {
    return (x << n) | (x >> (32 - n));
}

RMD5::uint32 RMD5::toLittleEndian(uint32 x) {
    return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) |
           ((x & 0xFF0000) >> 8) | ((x >> 24) & 0xFF);
}

// Основной метод хэширования для vector<uint8_t> (возвращает vector<uint8_t>)
vector<uint8_t> RMD5::hash(const vector<uint8_t>& data) {
    // Инициализация буфера
    uint32 A = A0;
    uint32 B = B0;
    uint32 C = C0;
    uint32 D = D0;

    // Подготовка сообщения
    vector<uint8> padded = padMessage(data);

    // Обработка по 512-битным блокам
    for (size_t i = 0; i < padded.size(); i += 64) {
        uint32 X[16];

        // Разбиваем блок на 16 слов
        for (int j = 0; j < 16; j++) {
            X[j] = *reinterpret_cast<uint32*>(&padded[i + j * 4]);
        }

        uint32 AA = A;
        uint32 BB = B;
        uint32 CC = C;
        uint32 DD = D;

        // Основной цикл RMD5
        for (int j = 0; j < 64; j++) {
            uint32 F_result, g;

            if (j < 16) {
                F_result = F(B, C, D);
                g = j;
            } else if (j < 32) {
                F_result = G(B, C, D);
                g = (5 * j + 1) % 16;
            } else if (j < 48) {
                F_result = H(B, C, D);
                g = (3 * j + 5) % 16;
            } else {
                F_result = I(B, C, D);
                g = (7 * j) % 16;
            }

            F_result = F_result + A + X[g] + T[j];
            A = D;
            D = C;
            C = B;
            B = B + rotateLeft(F_result, S[j]);
        }

        A += AA;
        B += BB;
        C += CC;
        D += DD;
    }

    // Формирование результата как vector<uint8_t> (16 байт)
    vector<uint8_t> result(16);

    // Преобразуем 4 uint32 в 16 uint8_t (little-endian)
    result[0] = (A >> 0) & 0xFF;
    result[1] = (A >> 8) & 0xFF;
    result[2] = (A >> 16) & 0xFF;
    result[3] = (A >> 24) & 0xFF;

    result[4] = (B >> 0) & 0xFF;
    result[5] = (B >> 8) & 0xFF;
    result[6] = (B >> 16) & 0xFF;
    result[7] = (B >> 24) & 0xFF;

    result[8] = (C >> 0) & 0xFF;
    result[9] = (C >> 8) & 0xFF;
    result[10] = (C >> 16) & 0xFF;
    result[11] = (C >> 24) & 0xFF;

    result[12] = (D >> 0) & 0xFF;
    result[13] = (D >> 8) & 0xFF;
    result[14] = (D >> 16) & 0xFF;
    result[15] = (D >> 24) & 0xFF;

    return result;
}


// Вспомогательные методы для получения hex-строки
string RMD5::hashToHexString(const vector<uint8_t>& data) {
    vector<uint8_t> hashResult = hash(data);
    return toHexString(hashResult);
}



// Внутренние приватные методы
vector<RMD5::uint8> RMD5::padMessage(const vector<uint8_t>& data) {
    vector<uint8> result = data;

    // Добавляем бит '1'
    result.push_back(0x80);

    // Добавляем нули до длины 448 бит (56 байт) по модулю 512
    while ((result.size() % 64) != 56) {
        result.push_back(0x00);
    }

    // Добавляем длину исходного сообщения (64 бита)
    uint64_t length = data.size() * 8;
    for (int i = 0; i < 8; i++) {
        result.push_back(static_cast<uint8>((length >> (i * 8)) & 0xFF));
    }

    return result;
}


string RMD5::toHexString(const vector<uint8_t>& hash) {
    stringstream ss;
    ss << hex << setfill('0');

    for (uint8_t byte : hash) {
        ss << setw(2) << static_cast<int>(byte);
    }

    return ss.str();
}
