#pragma once

#include "config.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <random>

namespace crypto {

class SHA256 {
private:
    uint32_t state[8];
    uint64_t bitCount;
    uint8_t buffer[64];

    static constexpr uint32_t rotr(uint32_t x, uint32_t n) noexcept {
        return (x >> n) | (x << (32 - n));
    }

    static constexpr uint32_t choose(uint32_t e, uint32_t f, uint32_t g) noexcept {
        return (e & f) ^ (~e & g);
    }

    static constexpr uint32_t majority(uint32_t a, uint32_t b, uint32_t c) noexcept {
        return (a & b) ^ (a & c) ^ (b & c);
    }

    static constexpr uint32_t sig0(uint32_t x) noexcept {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    static constexpr uint32_t sig1(uint32_t x) noexcept {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    static constexpr uint32_t theta0(uint32_t x) noexcept {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static constexpr uint32_t theta1(uint32_t x) noexcept {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    void transform(const uint8_t chunk[64]) noexcept {
        static constexpr uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = ((uint32_t)chunk[i * 4] << 24) |
                   ((uint32_t)chunk[i * 4 + 1] << 16) |
                   ((uint32_t)chunk[i * 4 + 2] << 8) |
                   ((uint32_t)chunk[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = theta1(w[i - 2]) + w[i - 7] + theta0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + sig1(e) + choose(e, f, g) + K[i] + w[i];
            uint32_t t2 = sig0(a) + majority(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

public:
    SHA256() noexcept { reset(); }

    void reset() noexcept {
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
        bitCount = 0;
    }

    void update(const uint8_t* data, size_t length) noexcept {
        for (size_t i = 0; i < length; ++i) {
            buffer[(bitCount / 8) % 64] = data[i];
            bitCount += 8;
            if ((bitCount / 8) % 64 == 0) {
                transform(buffer);
            }
        }
    }

    void update(std::string_view str) noexcept {
        update(reinterpret_cast<const uint8_t*>(str.data()), str.size());
    }

    [[nodiscard]] std::vector<uint8_t> digestBytes() {
        uint64_t totalBits = bitCount;
        uint8_t pad = 0x80;
        update(&pad, 1);

        while ((bitCount / 8) % 64 != 56) {
            uint8_t zero = 0x00;
            update(&zero, 1);
        }

        for (int i = 7; i >= 0; --i) {
            uint8_t b = static_cast<uint8_t>((totalBits >> (i * 8)) & 0xff);
            update(&b, 1);
        }

        std::vector<uint8_t> out(32);
        for (int i = 0; i < 8; ++i) {
            out[i * 4]     = static_cast<uint8_t>((state[i] >> 24) & 0xff);
            out[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 16) & 0xff);
            out[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 8)  & 0xff);
            out[i * 4 + 3] = static_cast<uint8_t>(state[i] & 0xff);
        }
        return out;
    }

    [[nodiscard]] std::string digestHex() {
        auto bytes = digestBytes();
        std::ostringstream oss;
        for (uint8_t b : bytes) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return oss.str();
    }

    [[nodiscard]] static std::string hash(std::string_view input) {
        SHA256 sha;
        sha.update(input);
        return sha.digestHex();
    }
};

class CryptoService {
private:
    config::SecurityConfig security;

public:
    explicit CryptoService(config::SecurityConfig sec = {}) : security(sec) {}

    [[nodiscard]] std::string generateSalt() const {
        static constexpr std::string_view charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::random_device rd;
        std::mt19937 rng(rd());
        std::uniform_int_distribution<size_t> dist(0, charset.size() - 1);

        std::string salt;
        salt.reserve(security.saltLength);
        for (size_t i = 0; i < security.saltLength; ++i) {
            salt += charset[dist(rng)];
        }
        return salt;
    }

    [[nodiscard]] std::string hashPassword(std::string_view password, std::string_view salt) const {
        std::string current = std::string(salt) + std::string(password);
        for (int i = 0; i < security.hashIterations; ++i) {
            current = SHA256::hash(current + std::string(salt));
        }
        return current;
    }

    [[nodiscard]] std::string deriveKey(std::string_view password, std::string_view salt) const {
        std::string current = std::string(salt) + std::string(password);
        for (int i = 0; i < security.encryptionKeyIterations; ++i) {
            current = SHA256::hash(current + std::string(salt));
        }
        return current;
    }

    [[nodiscard]] std::string encrypt(std::string_view plaintext, std::string_view masterPassword, std::string_view salt) const {
        std::string derivedKey = deriveKey(masterPassword, salt);
        std::string ciphertext;
        ciphertext.reserve(plaintext.size());

        size_t blockSize = security.cipherBlockSize;
        size_t numBlocks = (plaintext.size() + blockSize - 1) / blockSize;

        for (size_t block = 0; block < numBlocks; ++block) {
            std::string blockCounter = derivedKey + ":" + std::to_string(block);
            SHA256 sha;
            sha.update(blockCounter);
            auto keyStream = sha.digestBytes();

            for (size_t i = 0; i < blockSize && (block * blockSize + i) < plaintext.size(); ++i) {
                size_t idx = block * blockSize + i;
                ciphertext += static_cast<char>(static_cast<uint8_t>(plaintext[idx]) ^ keyStream[i]);
            }
        }

        std::ostringstream oss;
        for (char c : ciphertext) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<uint8_t>(c));
        }
        return oss.str();
    }

    [[nodiscard]] std::string decrypt(std::string_view hexCiphertext, std::string_view masterPassword, std::string_view salt) const {
        if (hexCiphertext.length() % 2 != 0) {
            return "";
        }

        std::string rawCipher;
        rawCipher.reserve(hexCiphertext.length() / 2);
        for (size_t i = 0; i < hexCiphertext.length(); i += 2) {
            std::string byteStr = std::string(hexCiphertext.substr(i, 2));
            uint8_t byteVal = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
            rawCipher += static_cast<char>(byteVal);
        }

        std::string derivedKey = deriveKey(masterPassword, salt);
        std::string plaintext;
        plaintext.reserve(rawCipher.size());

        size_t blockSize = security.cipherBlockSize;
        size_t numBlocks = (rawCipher.size() + blockSize - 1) / blockSize;

        for (size_t block = 0; block < numBlocks; ++block) {
            std::string blockCounter = derivedKey + ":" + std::to_string(block);
            SHA256 sha;
            sha.update(blockCounter);
            auto keyStream = sha.digestBytes();

            for (size_t i = 0; i < blockSize && (block * blockSize + i) < rawCipher.size(); ++i) {
                size_t idx = block * blockSize + i;
                plaintext += static_cast<char>(static_cast<uint8_t>(rawCipher[idx]) ^ keyStream[i]);
            }
        }

        return plaintext;
    }
};

}
