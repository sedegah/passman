#include "vault.hpp"
#include <sstream>
#include <algorithm>

Vault::Vault(std::unique_ptr<storage::IVaultStorage> storageBackend,
             config::SecurityConfig secConfig)
    : storage(std::move(storageBackend)), cryptoService(secConfig) {}

bool Vault::exists() const {
    return storage && storage->exists();
}

bool Vault::initialize(std::string_view newMasterPassword) {
    if (newMasterPassword.empty() || !storage) {
        return false;
    }

    salt = cryptoService.generateSalt();
    passwordHash = cryptoService.hashPassword(newMasterPassword, salt);
    masterPassword = std::string(newMasterPassword);
    credentials.clear();
    isUnlocked = true;

    return save();
}

bool Vault::unlock(std::string_view passwordAttempt) {
    if (!exists()) {
        return false;
    }

    auto contentOpt = storage->read();
    if (!contentOpt.has_value()) {
        return false;
    }

    std::istringstream file(contentOpt.value());
    std::string versionHeader;
    if (!std::getline(file, versionHeader) || versionHeader != "VAULT_V1") {
        return false;
    }
    if (!std::getline(file, salt)) {
        return false;
    }
    if (!std::getline(file, passwordHash)) {
        return false;
    }

    std::string computedHash = cryptoService.hashPassword(passwordAttempt, salt);
    if (computedHash != passwordHash) {
        return false;
    }

    masterPassword = std::string(passwordAttempt);
    isUnlocked = true;

    std::stringstream payloadStream;
    std::string line;
    while (std::getline(file, line)) {
        payloadStream << line;
    }

    std::string ciphertextHex = payloadStream.str();
    if (!ciphertextHex.empty()) {
        std::string plaintext = cryptoService.decrypt(ciphertextHex, masterPassword, salt);
        return parseVaultFile(plaintext);
    }

    credentials.clear();
    return true;
}

void Vault::lock() noexcept {
    isUnlocked = false;
    masterPassword.clear();
    credentials.clear();
}

bool Vault::changeMasterPassword(std::string_view oldPassword, std::string_view newPassword) {
    if (!isUnlocked || newPassword.empty()) {
        return false;
    }

    std::string computedHash = cryptoService.hashPassword(oldPassword, salt);
    if (computedHash != passwordHash) {
        return false;
    }

    salt = cryptoService.generateSalt();
    passwordHash = cryptoService.hashPassword(newPassword, salt);
    masterPassword = std::string(newPassword);

    return save();
}

std::string Vault::serializeVaultData() const {
    std::ostringstream oss;
    for (const auto& cred : credentials) {
        oss << cred.serialize() << "\n";
    }
    return oss.str();
}

bool Vault::parseVaultFile(std::string_view rawContent) {
    credentials.clear();
    std::string contentStr(rawContent);
    std::istringstream stream(contentStr);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        credentials.push_back(Credential::deserialize(line));
    }
    return true;
}

bool Vault::save() {
    if (!isUnlocked || !storage) {
        return false;
    }

    std::string plainData = serializeVaultData();
    std::string encryptedHex = cryptoService.encrypt(plainData, masterPassword, salt);

    std::ostringstream oss;
    oss << "VAULT_V1\n"
        << salt << "\n"
        << passwordHash << "\n"
        << encryptedHex << "\n";

    return storage->write(oss.str());
}

bool Vault::load() {
    if (!isUnlocked || masterPassword.empty()) {
        return false;
    }
    return unlock(masterPassword);
}

bool Vault::addCredential(Credential credential) {
    if (!isUnlocked || credential.website.empty()) {
        return false;
    }

    for (auto& cred : credentials) {
        if (cred.website == credential.website && cred.username == credential.username) {
            cred = std::move(credential);
            return save();
        }
    }

    credentials.push_back(std::move(credential));
    return save();
}

bool Vault::deleteCredential(std::string_view website) {
    if (!isUnlocked) {
        return false;
    }

    auto initialSize = credentials.size();
    credentials.erase(std::remove_if(credentials.begin(), credentials.end(), [&](const Credential& cred) {
        return cred.website == website;
    }), credentials.end());

    if (credentials.size() != initialSize) {
        return save();
    }
    return false;
}

bool Vault::updateCredential(Credential credential) {
    if (!isUnlocked) {
        return false;
    }

    for (auto& cred : credentials) {
        if (cred.website == credential.website) {
            cred = std::move(credential);
            return save();
        }
    }
    return false;
}

std::vector<Credential> Vault::search(std::string_view query) const {
    return filter([query](const Credential& cred) {
        return cred.matches(query);
    });
}

std::vector<Credential> Vault::filter(const std::function<bool(const Credential&)>& predicate) const {
    std::vector<Credential> results;
    if (!isUnlocked) return results;

    for (const auto& cred : credentials) {
        if (predicate(cred)) {
            results.push_back(cred);
        }
    }
    return results;
}

std::optional<Credential> Vault::findExact(std::string_view website) const {
    if (!isUnlocked) return std::nullopt;
    for (const auto& cred : credentials) {
        if (cred.website == website) {
            return cred;
        }
    }
    return std::nullopt;
}
