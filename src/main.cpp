#include "manager.hpp"
#include "config.hpp"
#include <vector>
#include <string>

int main(int argc, char* argv[]) {
    config::AppConfig appConfig;
    PasswordManager app(appConfig);

    if (argc > 1) {
        std::vector<std::string> args;
        args.reserve(argc - 1);
        for (int i = 1; i < argc; ++i) {
            args.emplace_back(argv[i]);
        }
        return app.runCommand(args);
    }

    app.runInteractive();
    return 0;
}
