#pragma once

#include <string>
#include <filesystem>
#include <cstddef>

namespace config {

struct SecurityConfig {
    size_t saltLength = 16;
    int hashIterations = 10000;
    int encryptionKeyIterations = 2000;
    size_t cipherBlockSize = 32;
};

struct GeneratorConfig {
    size_t defaultLength = 20;
    size_t minLength = 4;
    size_t maxLength = 128;
    std::string uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
    std::string numberChars = "0123456789";
    std::string symbolChars = "!@#$%^&*()-_=+[]{}|;:,.<>?/";
    std::string ambiguousChars = "IOlo01|";
};

struct AppConfig {
    std::filesystem::path vaultPath = "vault.dat";
    int maxLoginAttempts = 3;
    SecurityConfig security;
    GeneratorConfig generator;
};

}
