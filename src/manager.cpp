#include "manager.hpp"
#include <iostream>
#include <iomanip>
#include <limits>

PasswordManager::PasswordManager(config::AppConfig cfg)
    : appConfig(std::move(cfg)),
      vault(std::make_unique<storage::FileVaultStorage>(appConfig.vaultPath), appConfig.security),
      generator(appConfig.generator) {
    initializeHandlers();
}

void PasswordManager::initializeHandlers() {
    menuHandlers["1"] = [this]() { handleAdd(); };
    menuHandlers["2"] = [this]() { handleList(); };
    menuHandlers["3"] = [this]() { handleSearch(); };
    menuHandlers["4"] = [this]() { handleDelete(); };
    menuHandlers["5"] = [this]() { handleGenerate(); };
    menuHandlers["6"] = [this]() { handleChangePassword(); };

    commandHandlers["generate"] = [this](const std::vector<std::string>& args) {
        size_t len = appConfig.generator.defaultLength;
        if (args.size() > 1) {
            try {
                len = std::stoul(args[1]);
            } catch (...) {
                len = appConfig.generator.defaultLength;
            }
        }
        PasswordOptions opt;
        opt.length = len;
        std::cout << generator.generate(opt) << "\n";
        return 0;
    };
    commandHandlers["gen"] = commandHandlers["generate"];

    commandHandlers["list"] = [this](const std::vector<std::string>&) {
        if (!authenticate()) return 1;
        const auto& list = vault.getCredentials();
        if (list.empty()) {
            std::cout << "Vault is empty.\n";
            return 0;
        }
        for (const auto& cred : list) {
            std::cout << cred.website << " | " << cred.username << "\n";
        }
        return 0;
    };
    commandHandlers["ls"] = commandHandlers["list"];

    commandHandlers["search"] = [this](const std::vector<std::string>& args) {
        if (args.size() < 2) {
            std::cout << "Usage: passman search <term>\n";
            return 1;
        }
        if (!authenticate()) return 1;
        auto results = vault.search(args[1]);
        if (results.empty()) {
            std::cout << "No matches found for '" << args[1] << "'.\n";
            return 0;
        }
        for (const auto& cred : results) {
            std::cout << "Website:  " << cred.website << "\n";
            std::cout << "Username: " << cred.username << "\n";
            std::cout << "Password: " << cred.password << "\n";
            if (!cred.notes.empty()) std::cout << "Notes:    " << cred.notes << "\n";
            std::cout << "---------------------------------\n";
        }
        return 0;
    };
    commandHandlers["find"] = commandHandlers["search"];

    commandHandlers["add"] = [this](const std::vector<std::string>& args) {
        if (!authenticate()) return 1;
        std::string site = args.size() > 1 ? args[1] : "";
        std::string user = args.size() > 2 ? args[2] : "";
        std::string pass = args.size() > 3 ? args[3] : "";

        if (site.empty()) {
            std::cout << "Website: ";
            std::getline(std::cin, site);
        }
        if (user.empty()) {
            std::cout << "Username: ";
            std::getline(std::cin, user);
        }
        if (pass.empty()) {
            pass = terminal::readPassword("Password (or enter to generate): ");
            if (pass.empty()) {
                PasswordOptions opt;
                opt.length = appConfig.generator.defaultLength;
                pass = generator.generate(opt);
                std::cout << "Generated: " << pass << "\n";
            }
        }

        if (vault.addCredential(Credential{site, user, pass})) {
            std::cout << "Credential saved.\n";
            return 0;
        }
        std::cout << "Failed to save credential.\n";
        return 1;
    };

    commandHandlers["delete"] = [this](const std::vector<std::string>& args) {
        if (args.size() < 2) {
            std::cout << "Usage: passman delete <website>\n";
            return 1;
        }
        if (!authenticate()) return 1;
        if (vault.deleteCredential(args[1])) {
            std::cout << "Credential deleted.\n";
            return 0;
        }
        std::cout << "Credential not found.\n";
        return 1;
    };
    commandHandlers["del"] = commandHandlers["delete"];
    commandHandlers["rm"] = commandHandlers["delete"];
}

void PasswordManager::displayBanner() const {
    std::cout << theme.cyan << theme.bold;
    std::cout << R"(
================================
       PASSWORD MANAGER
================================
)" << theme.reset;
}

void PasswordManager::displayMenu() const {
    std::cout << "\n" << theme.bold << "Vault Actions:" << theme.reset << "\n";
    std::cout << "  " << theme.green << "1." << theme.reset << " Add credential\n";
    std::cout << "  " << theme.green << "2." << theme.reset << " View credentials\n";
    std::cout << "  " << theme.green << "3." << theme.reset << " Search credential\n";
    std::cout << "  " << theme.green << "4." << theme.reset << " Delete credential\n";
    std::cout << "  " << theme.green << "5." << theme.reset << " Generate password\n";
    std::cout << "  " << theme.yellow << "6." << theme.reset << " Change master password\n";
    std::cout << "  " << theme.red << "7." << theme.reset << " Exit\n\n";
    std::cout << theme.cyan << "Choose an option: " << theme.reset;
}

bool PasswordManager::authenticate() {
    terminal::init();

    if (!vault.exists()) {
        std::cout << theme.yellow << "No existing vault found. Create a master password.\n" << theme.reset;
        std::string pass1 = terminal::readPassword("Create Master Password: ");
        if (pass1.empty()) {
            std::cout << theme.red << "Master password cannot be empty.\n" << theme.reset;
            return false;
        }
        std::string pass2 = terminal::readPassword("Confirm Master Password: ");
        if (pass1 != pass2) {
            std::cout << theme.red << "Passwords do not match.\n" << theme.reset;
            return false;
        }

        if (vault.initialize(pass1)) {
            std::cout << theme.green << "Vault initialized successfully.\n" << theme.reset;
            return true;
        } else {
            std::cout << theme.red << "Failed to initialize vault storage.\n" << theme.reset;
            return false;
        }
    }

    int attempts = 0;
    while (attempts < appConfig.maxLoginAttempts) {
        std::string entered = terminal::readPassword("Enter Master Password: ");
        if (vault.unlock(entered)) {
            std::cout << theme.green << "Access granted.\nWelcome back.\n" << theme.reset;
            return true;
        } else {
            attempts++;
            std::cout << theme.red << "Incorrect master password. (" 
                      << (appConfig.maxLoginAttempts - attempts) << " attempts remaining)\n" << theme.reset;
        }
    }

    std::cout << theme.red << "Access denied.\n" << theme.reset;
    return false;
}

void PasswordManager::handleAdd() {
    std::cout << "\n" << theme.bold << "--- Add Credential ---" << theme.reset << "\n";
    std::string website, username, password, notes;

    std::cout << "Website: ";
    std::getline(std::cin, website);
    if (website.empty()) {
        std::cout << theme.red << "Website cannot be empty.\n" << theme.reset;
        return;
    }

    std::cout << "Username: ";
    std::getline(std::cin, username);

    std::cout << "Generate password? [Y/n]: ";
    std::string genChoice;
    std::getline(std::cin, genChoice);

    if (genChoice.empty() || genChoice[0] == 'y' || genChoice[0] == 'Y') {
        PasswordOptions opt;
        opt.length = appConfig.generator.defaultLength;
        password = generator.generate(opt);
        std::cout << "Generated password:\n" << theme.green << theme.bold << password << theme.reset << "\n";
    } else {
        password = terminal::readPassword("Password: ");
        if (password.empty()) {
            std::cout << theme.red << "Password cannot be empty.\n" << theme.reset;
            return;
        }
    }

    PasswordStrength strength = PasswordGenerator::evaluateStrength(password);
    std::cout << "Password strength: " << theme.yellow << PasswordGenerator::getStrengthLabel(strength) << theme.reset << "\n";

    std::cout << "Notes (optional): ";
    std::getline(std::cin, notes);

    if (vault.addCredential(Credential{website, username, password, notes})) {
        std::cout << theme.green << "Credential saved.\n" << theme.reset;
    } else {
        std::cout << theme.red << "Failed to save credential.\n" << theme.reset;
    }
}

void PasswordManager::handleList() {
    std::cout << "\n" << theme.bold << "Saved credentials:" << theme.reset << "\n";
    const auto& list = vault.getCredentials();

    if (list.empty()) {
        std::cout << theme.gray << "No credentials stored.\n" << theme.reset;
        return;
    }

    for (size_t i = 0; i < list.size(); ++i) {
        std::cout << (i + 1) << ". " << list[i].website << "\n";
    }

    std::cout << "\nReveal details? (Enter # or 0 to skip): ";
    int choice = 0;
    if (std::cin >> choice && choice > 0 && static_cast<size_t>(choice) <= list.size()) {
        const auto& item = list[choice - 1];
        std::cout << "\nWebsite:  " << item.website << "\n";
        std::cout << "Username: " << item.username << "\n";
        std::cout << "Password: " << theme.green << theme.bold << item.password << theme.reset << "\n";
        if (!item.notes.empty()) {
            std::cout << "Notes:    " << item.notes << "\n";
        }
    }
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

void PasswordManager::handleSearch() {
    std::cout << "\n" << theme.bold << "--- Search Credential ---" << theme.reset << "\n";
    std::cout << "Search: ";
    std::string query;
    std::getline(std::cin, query);

    if (query.empty()) return;

    auto results = vault.search(query);
    if (results.empty()) {
        std::cout << theme.yellow << "No matching credential found.\n" << theme.reset;
        return;
    }

    for (const auto& cred : results) {
        std::cout << "\nWebsite:  " << cred.website << "\n";
        std::cout << "Username: " << cred.username << "\n";
        std::cout << "Password: " << cred.password << "\n";
        if (!cred.notes.empty()) {
            std::cout << "Notes:    " << cred.notes << "\n";
        }
    }
}

void PasswordManager::handleDelete() {
    std::cout << "\n" << theme.bold << "--- Delete Credential ---" << theme.reset << "\n";
    std::cout << "Enter website: ";
    std::string site;
    std::getline(std::cin, site);

    if (site.empty()) return;

    if (vault.deleteCredential(site)) {
        std::cout << theme.green << "Credential deleted.\n" << theme.reset;
    } else {
        std::cout << theme.yellow << "Credential not found.\n" << theme.reset;
    }
}

void PasswordManager::handleGenerate() {
    std::cout << "\n" << theme.bold << "--- Generate Password ---" << theme.reset << "\n";
    std::cout << "Password length (default " << appConfig.generator.defaultLength << "): ";
    std::string lenStr;
    std::getline(std::cin, lenStr);

    size_t length = appConfig.generator.defaultLength;
    if (!lenStr.empty()) {
        try {
            length = std::stoul(lenStr);
        } catch (...) {
            length = appConfig.generator.defaultLength;
        }
    }

    PasswordOptions options;
    options.length = length;

    std::string generated = generator.generate(options);
    PasswordStrength strength = PasswordGenerator::evaluateStrength(generated);
    double entropy = PasswordGenerator::calculateEntropy(generated);

    std::cout << "\nGenerated password:\n";
    std::cout << theme.green << theme.bold << generated << theme.reset << "\n\n";
    std::cout << "Strength: " << theme.yellow << PasswordGenerator::getStrengthLabel(strength) << theme.reset 
              << " (" << std::fixed << std::setprecision(1) << entropy << " bits entropy)\n";
}

void PasswordManager::handleChangePassword() {
    std::cout << "\n" << theme.bold << "--- Change Master Password ---" << theme.reset << "\n";
    std::string oldPass = terminal::readPassword("Enter current master password: ");
    std::string newPass = terminal::readPassword("Enter new master password: ");
    std::string confirmPass = terminal::readPassword("Confirm new master password: ");

    if (newPass.empty()) {
        std::cout << theme.red << "New master password cannot be empty.\n" << theme.reset;
        return;
    }

    if (newPass != confirmPass) {
        std::cout << theme.red << "Passwords do not match.\n" << theme.reset;
        return;
    }

    if (vault.changeMasterPassword(oldPass, newPass)) {
        std::cout << theme.green << "Master password updated.\n" << theme.reset;
    } else {
        std::cout << theme.red << "Incorrect current master password.\n" << theme.reset;
    }
}

void PasswordManager::runInteractive() {
    displayBanner();

    if (!authenticate()) {
        return;
    }

    bool running = true;
    while (running) {
        displayMenu();
        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "7" || choice == "exit" || choice == "q") {
            vault.lock();
            running = false;
        } else if (auto it = menuHandlers.find(choice); it != menuHandlers.end()) {
            it->second();
        } else {
            std::cout << theme.red << "Invalid option.\n" << theme.reset;
        }
    }
}

int PasswordManager::runCommand(const std::vector<std::string>& args) {
    if (args.empty()) {
        runInteractive();
        return 0;
    }

    const std::string& cmd = args[0];
    if (auto it = commandHandlers.find(cmd); it != commandHandlers.end()) {
        return it->second(args);
    }

    std::cout << "Unknown command: " << cmd << "\n";
    std::cout << "Available commands: add, list, search, delete, generate\n";
    return 1;
}
