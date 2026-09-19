#pragma once

#include <iostream>
#include <string>
#include <string_view>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace terminal {

struct Theme {
    std::string_view reset   = "\033[0m";
    std::string_view bold    = "\033[1m";
    std::string_view red     = "\033[31m";
    std::string_view green   = "\033[32m";
    std::string_view yellow  = "\033[33m";
    std::string_view blue    = "\033[34m";
    std::string_view magenta = "\033[35m";
    std::string_view cyan    = "\033[36m";
    std::string_view white   = "\033[37m";
    std::string_view gray    = "\033[90m";
};

inline void init() {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
#endif
}

inline std::string readPassword(std::string_view prompt, bool mask = true, char maskChar = '*') {
    std::cout << prompt << std::flush;
    std::string password;

#ifdef _WIN32
    while (true) {
        int ch = _getch();
        if (ch == 13 || ch == 10) {
            std::cout << "\n";
            break;
        } else if (ch == 8) {
            if (!password.empty()) {
                password.pop_back();
                if (mask) {
                    std::cout << "\b \b" << std::flush;
                }
            }
        } else if (ch == 3) {
            std::cout << "\n";
            exit(0);
        } else if (ch >= 32 && ch <= 126) {
            password += static_cast<char>(ch);
            if (mask) {
                std::cout << maskChar << std::flush;
            }
        }
    }
#else
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    char ch = 0;
    while (read(STDIN_FILENO, &ch, 1) > 0) {
        if (ch == '\n' || ch == '\r') {
            std::cout << "\n";
            break;
        } else if (ch == 127 || ch == 8) {
            if (!password.empty()) {
                password.pop_back();
                if (mask) {
                    std::cout << "\b \b" << std::flush;
                }
            }
        } else if (ch >= 32 && ch <= 126) {
            password += ch;
            if (mask) {
                std::cout << maskChar << std::flush;
            }
        }
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

    return password;
}

}
