cmake_minimum_required(VERSION 3.24)
project(dns_server CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

# Fetch Standalone Asio
FetchContent_Declare(
    asio
    URL https://github.com/chriskohlhoff/asio/archive/asio-1-28-0.tar.gz
)
FetchContent_MakeAvailable(asio)

add_executable(dns_server src/main.cpp)

# Define include directories for asio
target_include_directories(dns_server PRIVATE ${asio_SOURCE_DIR}/asio/include)

# Link against system libraries and define macros
target_compile_definitions(dns_server PRIVATE ASIO_STANDALONE ASIO_HAS_CO_AWAIT)
