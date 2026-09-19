cmake_minimum_required(VERSION 3.15)
project(passman VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

add_executable(passman
    src/main.cpp
    src/manager.cpp
    src/vault.cpp
    src/generator.cpp
)

add_executable(passman_tests
    tests/test.cpp
    src/vault.cpp
    src/generator.cpp
)
