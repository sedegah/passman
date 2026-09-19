#pragma once

#include "config.hpp"
#include <string>
#include <string_view>
#include <random>

struct PasswordOptions {
    size_t length = 20;
    bool includeUppercase = true;
    bool includeLowercase = true;
    bool includeNumbers = true;
    bool includeSymbols = true;
    bool excludeAmbiguous = false;
};

enum class PasswordStrength {
    Weak,
    Medium,
    Strong,
    VeryStrong
};

class PasswordGenerator {
private:
    config::GeneratorConfig config;
    std::mt19937 rng;

public:
    explicit PasswordGenerator(config::GeneratorConfig cfg = {});

    [[nodiscard]] std::string generate(const PasswordOptions& options);
    [[nodiscard]] static PasswordStrength evaluateStrength(std::string_view password);
    [[nodiscard]] static std::string_view getStrengthLabel(PasswordStrength strength);
    [[nodiscard]] static double calculateEntropy(std::string_view password);
};
