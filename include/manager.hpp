#pragma once

#include "vault.hpp"
#include "generator.hpp"
#include "config.hpp"
#include "terminal.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <functional>

class PasswordManager {
private:
    config::AppConfig appConfig;
    Vault vault;
    PasswordGenerator generator;
    terminal::Theme theme;

    std::unordered_map<std::string, std::function<int(const std::vector<std::string>&)>> commandHandlers;
    std::unordered_map<std::string, std::function<void()>> menuHandlers;

    void initializeHandlers();
    void displayBanner() const;
    void displayMenu() const;

    void handleAdd();
    void handleList();
    void handleSearch();
    void handleDelete();
    void handleGenerate();
    void handleChangePassword();

    bool authenticate();

public:
    explicit PasswordManager(config::AppConfig cfg = {});

    void runInteractive();
    int runCommand(const std::vector<std::string>& args);
};
