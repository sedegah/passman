#pragma once

#include <string>
#include <string_view>
#include <sstream>
#include <vector>
#include <utility>

struct Credential {
    std::string website;
    std::string username;
    std::string password;
    std::string notes;

    Credential() = default;
    Credential(std::string site, std::string user, std::string pass, std::string note = "")
        : website(std::move(site)), username(std::move(user)), password(std::move(pass)), notes(std::move(note)) {}

    [[nodiscard]] bool matches(std::string_view query) const {
        if (query.empty()) return true;

        auto containsCaseInsensitive = [](std::string_view text, std::string_view target) {
            if (target.empty()) return true;
            if (text.size() < target.size()) return false;
            for (size_t i = 0; i <= text.size() - target.size(); ++i) {
                bool match = true;
                for (size_t j = 0; j < target.size(); ++j) {
                    if (std::tolower(static_cast<unsigned char>(text[i + j])) != 
                        std::tolower(static_cast<unsigned char>(target[j]))) {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
            return false;
        };

        return containsCaseInsensitive(website, query) ||
               containsCaseInsensitive(username, query) ||
               containsCaseInsensitive(notes, query);
    }

    [[nodiscard]] std::string serialize(char delimiter = '|', char escapeChar = '\\') const {
        auto escape = [delimiter, escapeChar](std::string_view str) {
            std::string res;
            res.reserve(str.size() * 2);
            for (char c : str) {
                if (c == delimiter || c == escapeChar) {
                    res += escapeChar;
                }
                res += c;
            }
            return res;
        };

        return escape(website) + delimiter + escape(username) + delimiter + escape(password) + delimiter + escape(notes);
    }

    static Credential deserialize(std::string_view line, char delimiter = '|', char escapeChar = '\\') {
        std::vector<std::string> fields;
        std::string current;
        bool escaping = false;

        for (char c : line) {
            if (escaping) {
                current += c;
                escaping = false;
            } else if (c == escapeChar) {
                escaping = true;
            } else if (c == delimiter) {
                fields.push_back(std::move(current));
                current.clear();
            } else {
                current += c;
            }
        }
        fields.push_back(std::move(current));

        Credential cred;
        if (fields.size() > 0) cred.website = std::move(fields[0]);
        if (fields.size() > 1) cred.username = std::move(fields[1]);
        if (fields.size() > 2) cred.password = std::move(fields[2]);
        if (fields.size() > 3) cred.notes = std::move(fields[3]);

        return cred;
    }
};
