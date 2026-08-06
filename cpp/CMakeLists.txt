cmake_minimum_required(VERSION 3.24)
project(dns_server CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

# Fetch FTXUI
FetchContent_Declare(
  ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
  GIT_TAG v5.0.0
)
FetchContent_MakeAvailable(ftxui)

add_executable(dns_server src/main.cpp)

# Link against FTXUI components
target_link_libraries(dns_server PRIVATE ftxui::screen ftxui::dom ftxui::component)