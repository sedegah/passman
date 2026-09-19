#pragma once

#include <string>
#include <string_view>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <optional>

namespace storage {

class IVaultStorage {
public:
    virtual ~IVaultStorage() = default;
    [[nodiscard]] virtual bool exists() const = 0;
    virtual bool write(std::string_view content) = 0;
    [[nodiscard]] virtual std::optional<std::string> read() = 0;
};

class FileVaultStorage : public IVaultStorage {
private:
    std::filesystem::path path;

public:
    explicit FileVaultStorage(std::filesystem::path p) : path(std::move(p)) {}

    [[nodiscard]] bool exists() const override {
        return std::filesystem::exists(path);
    }

    bool write(std::string_view content) override {
        if (auto parent = path.parent_path(); !parent.empty()) {
            std::filesystem::create_directories(parent);
        }
        std::ofstream file(path, std::ios::trunc | std::ios::binary);
        if (!file.is_open()) return false;
        file.write(content.data(), content.size());
        return file.good();
    }

    [[nodiscard]] std::optional<std::string> read() override {
        if (!exists()) return std::nullopt;
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return std::nullopt;
        std::ostringstream ss;
        ss << file.rdbuf();
        return ss.str();
    }
};

}
