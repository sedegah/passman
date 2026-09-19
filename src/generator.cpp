#include "generator.hpp"
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <cctype>

PasswordGenerator::PasswordGenerator(config::GeneratorConfig cfg) : config(std::move(cfg)) {
    std::random_device rd;
    rng.seed(rd());
}

std::string PasswordGenerator::generate(const PasswordOptions& options) {
    size_t targetLength = std::clamp(options.length, config.minLength, config.maxLength);
    if (targetLength == 0) {
        return "";
    }

    std::string uppercase = config.uppercaseChars;
    std::string lowercase = config.lowercaseChars;
    std::string numbers   = config.numberChars;
    std::string symbols   = config.symbolChars;

    if (options.excludeAmbiguous) {
        auto removeChars = [&](std::string& src) {
            src.erase(std::remove_if(src.begin(), src.end(), [&](char c) {
                return config.ambiguousChars.find(c) != std::string::npos;
            }), src.end());
        };
        removeChars(uppercase);
        removeChars(lowercase);
        removeChars(numbers);
        removeChars(symbols);
    }

    std::string pool;
    std::vector<std::string> mandatorySets;

    if (options.includeUppercase && !uppercase.empty()) {
        pool += uppercase;
        mandatorySets.push_back(uppercase);
    }
    if (options.includeLowercase && !lowercase.empty()) {
        pool += lowercase;
        mandatorySets.push_back(lowercase);
    }
    if (options.includeNumbers && !numbers.empty()) {
        pool += numbers;
        mandatorySets.push_back(numbers);
    }
    if (options.includeSymbols && !symbols.empty()) {
        pool += symbols;
        mandatorySets.push_back(symbols);
    }

    if (pool.empty()) {
        throw std::invalid_argument("Empty character pool");
    }

    std::string password;
    password.reserve(targetLength);

    for (const auto& set : mandatorySets) {
        if (password.length() < targetLength) {
            std::uniform_int_distribution<size_t> dist(0, set.size() - 1);
            password += set[dist(rng)];
        }
    }

    std::uniform_int_distribution<size_t> poolDist(0, pool.size() - 1);
    while (password.length() < targetLength) {
        password += pool[poolDist(rng)];
    }

    std::shuffle(password.begin(), password.end(), rng);

    return password;
}

PasswordStrength PasswordGenerator::evaluateStrength(std::string_view password) {
    if (password.empty()) return PasswordStrength::Weak;

    double entropy = calculateEntropy(password);

    if (entropy < 35.0 || password.length() < 8) {
        return PasswordStrength::Weak;
    } else if (entropy < 55.0 || password.length() < 12) {
        return PasswordStrength::Medium;
    } else if (entropy < 80.0 || password.length() < 16) {
        return PasswordStrength::Strong;
    } else {
        return PasswordStrength::VeryStrong;
    }
}

std::string_view PasswordGenerator::getStrengthLabel(PasswordStrength strength) {
    switch (strength) {
        case PasswordStrength::Weak:       return "Weak";
        case PasswordStrength::Medium:     return "Medium";
        case PasswordStrength::Strong:     return "Strong";
        case PasswordStrength::VeryStrong: return "Very Strong";
    }
    return "Unknown";
}

double PasswordGenerator::calculateEntropy(std::string_view password) {
    if (password.empty()) return 0.0;

    bool hasUpper = false, hasLower = false, hasDigit = false, hasSymbol = false;
    for (char c : password) {
        if (std::isupper(static_cast<unsigned char>(c))) hasUpper = true;
        else if (std::islower(static_cast<unsigned char>(c))) hasLower = true;
        else if (std::isdigit(static_cast<unsigned char>(c))) hasDigit = true;
        else hasSymbol = true;
    }

    size_t poolSize = 0;
    if (hasUpper) poolSize += 26;
    if (hasLower) poolSize += 26;
    if (hasDigit) poolSize += 10;
    if (hasSymbol) poolSize += 32;

    if (poolSize == 0) return 0.0;

    return static_cast<double>(password.length()) * (std::log2(static_cast<double>(poolSize)));
}
