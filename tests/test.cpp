#include "credential.hpp"
#include "crypto.hpp"
#include "generator.hpp"
#include "vault.hpp"
#include "storage.hpp"
#include <iostream>
#include <cassert>
#include <memory>

class InMemoryVaultStorage : public storage::IVaultStorage {
private:
    std::string data;
    bool hasData = false;

public:
    [[nodiscard]] bool exists() const override {
        return hasData;
    }

    bool write(std::string_view content) override {
        data = std::string(content);
        hasData = true;
        return true;
    }

    [[nodiscard]] std::optional<std::string> read() override {
        if (!hasData) return std::nullopt;
        return data;
    }
};

int main() {
    {
        Credential c1("github.com", "kimathi", "Secret123!", "Personal account");
        std::string serialized = c1.serialize();
        Credential c2 = Credential::deserialize(serialized);
        assert(c2.website == "github.com");
        assert(c2.username == "kimathi");
        assert(c2.password == "Secret123!");
        assert(c2.notes == "Personal account");
        assert(c2.matches("github"));
        assert(c2.matches("KIMATHI"));
        assert(!c2.matches("gitlab"));
    }

    {
        crypto::CryptoService cs;
        std::string hash1 = crypto::SHA256::hash("hello world");
        std::string hash2 = crypto::SHA256::hash("hello world");
        assert(hash1 == hash2);
        assert(hash1 == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");

        std::string salt = cs.generateSalt();
        assert(salt.length() == 16);

        std::string plaintext = "sensitive|vault|payload|data";
        std::string encrypted = cs.encrypt(plaintext, "masterpass123", salt);
        std::string decrypted = cs.decrypt(encrypted, "masterpass123", salt);
        assert(decrypted == plaintext);
    }

    {
        config::GeneratorConfig cfg;
        PasswordGenerator gen(cfg);
        PasswordOptions opt;
        opt.length = 24;
        opt.includeUppercase = true;
        opt.includeLowercase = true;
        opt.includeNumbers = true;
        opt.includeSymbols = true;

        std::string p = gen.generate(opt);
        assert(p.length() == 24);
        assert(PasswordGenerator::evaluateStrength(p) == PasswordStrength::VeryStrong);
    }

    {
        auto memStorage = std::make_unique<InMemoryVaultStorage>();
        Vault v(std::move(memStorage));

        assert(!v.exists());
        assert(v.initialize("MasterKey!234"));
        assert(v.exists());
        assert(v.unlocked());

        assert(v.addCredential(Credential{"discord.com", "kimathi", "pass123"}));
        assert(v.addCredential(Credential{"google.com", "kimathi@gmail.com", "pass456"}));
        assert(v.size() == 2);

        auto found = v.search("discord");
        assert(found.size() == 1);
        assert(found[0].username == "kimathi");

        v.lock();
        assert(!v.unlocked());
        assert(!v.unlock("wrongpass"));
        assert(v.unlock("MasterKey!234"));
        assert(v.unlocked());
        assert(v.size() == 2);

        assert(v.deleteCredential("discord.com"));
        assert(v.size() == 1);
    }

    std::cout << "All tests passed successfully.\n";
    return 0;
}
