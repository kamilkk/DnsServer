#include <iostream>
#include <exception>
#include <asio.hpp>
#include "server.hpp"

int main() {
    try {
        asio::io_context io_context;
        DnsServer server(io_context, 15353);

        std::cout << "Starting Modern C++ DNS Server on port 15353...\n";
        
        asio::co_spawn(io_context, server.start(), asio::detached);
        
        io_context.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
