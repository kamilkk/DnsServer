# DNS Server Implementations

This repository covers the implementation of a fully functional DNS Server built from scratch in various backend programming languages. The project demonstrates core concepts like binary protocol parsing, networking, and language-specific modern features.

## Implemented Languages (Done Folders)

Currently, the DNS Server is implemented in the following languages:
- **[cpp](./cpp/)**: Modern C++ (C++23) implementation using Standalone Asio and C++20 Coroutines.

## Running and Testing

### C++

**Prerequisites:**
- C++23 Compiler (GCC 13+, Clang 16+, or MSVC 19.38+)
- CMake 3.24+

**Building:**
Navigate to the `cpp` folder and build the project using CMake:
```bash
cd cpp
mkdir build
cd build
cmake ..
make
```

**Running the Server:**
Start the DNS server (listens on port 15353 by default):
```bash
./dns_server
```

**Testing:**
In another terminal, you can query the server using standard command-line tools like `dig` or `nslookup`.

Using `dig` (Linux/macOS):
```bash
dig @127.0.0.1 -p 15353 example.local
```

Using `nslookup` (Windows):
```bash
nslookup -port=15353 example.local 127.0.0.1
```

You should receive a successful response pointing `example.local` to the configured IP address.
