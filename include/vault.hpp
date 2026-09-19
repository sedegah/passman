#pragma once

#include "credential.hpp"
#include "storage.hpp"
#include "crypto.hpp"
#include "config.hpp"
#include <vector>
#include <string>
#include <string_view>
#include <memory>
#include <optional>
#include <functional>

class Vault {
private:
    std::unique_ptr<storage::IVaultStorage> storage;
    crypto::CryptoService cryptoService;
    std::vector<Credential> credentials;
    std::string masterPassword;
    std::string salt;
    std::string passwordHash;
    bool isUnlocked = false;

    bool parseVaultFile(std::string_view rawContent);
    [[nodiscard]] std::string serializeVaultData() const;

public:
    explicit Vault(std::unique_ptr<storage::IVaultStorage> storageBackend,
                   config::SecurityConfig secConfig = {});

    [[nodiscard]] bool exists() const;
    [[nodiscard]] bool unlocked() const noexcept { return isUnlocked; }

    bool initialize(std::string_view newMasterPassword);
    bool unlock(std::string_view passwordAttempt);
    void lock() noexcept;
    bool changeMasterPassword(std::string_view oldPassword, std::string_view newPassword);
    bool save();
    bool load();

    bool addCredential(Credential credential);
    bool deleteCredential(std::string_view website);
    bool updateCredential(Credential credential);

    [[nodiscard]] const std::vector<Credential>& getCredentials() const noexcept { return credentials; }
    [[nodiscard]] std::vector<Credential> search(std::string_view query) const;
    [[nodiscard]] std::vector<Credential> filter(const std::function<bool(const Credential&)>& predicate) const;
    [[nodiscard]] std::optional<Credential> findExact(std::string_view website) const;
    [[nodiscard]] size_t size() const noexcept { return credentials.size(); }
};
