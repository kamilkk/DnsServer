#pragma once
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <functional>
#include <thread>
#include <cerrno>
#include "dns.hpp"
#include "buffer.hpp"

class DnsServer {
    int socket_fd_;
    bool running_{false};
    std::unordered_map<std::string, uint32_t> records_;
    // For CLI integration
    std::function<void(const std::string&)> log_callback_;
    
public:
    DnsServer(uint16_t port, std::unordered_map<std::string, uint32_t> records) : records_(std::move(records)) {

        socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd_ < 0) {
            throw std::runtime_error("Failed to create socket");
        }
        
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);
        if (bind(socket_fd_, (const sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            close(socket_fd_);
            throw std::runtime_error("Failed to bind socket");
        }
    }

    ~DnsServer() {
        stop();
        close(socket_fd_);
    }

    void set_log_callback(std::function<void(const std::string&)> cb) {
        log_callback_ = std::move(cb);
    }

    void log(const std::string& msg) {
        if (log_callback_) log_callback_(msg);
        else std::cout << msg << std::endl;
    }

    void start() {
        running_ = true;
        std::vector<uint8_t> buffer(1024);
        while (running_) {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            ssize_t received = recvfrom(socket_fd_, buffer.data(), buffer.size(), 0, (sockaddr*)&client_addr, &client_len);
            
            if (received < 0) {
                if (running_ && errno != EAGAIN && errno != EWOULDBLOCK) log("Error receiving data");
                continue;
            }
            handle_query(std::span<const uint8_t>(buffer.data(), received), client_addr, client_len);
        }
    }

    void stop() {
        running_ = false;
        shutdown(socket_fd_, SHUT_RDWR);
    }

private:
void handle_query(std::span<const uint8_t> packet, sockaddr_in client_addr, socklen_t client_len) {
        ByteBuffer buf(packet);
        auto header_res = DnsHeader::from_bytes(packet);
        
        if (!header_res) {
            log("Invalid header received");
            return;
        }
        
        auto& header = *header_res;
        buf.skip(DnsHeader::SIZE);

        std::vector<DnsQuestion> questions;
        for (int i = 0; i < header.question_count; ++i) {
            if (auto q = DnsQuestion::parse(buf)) {
                questions.push_back(*q);
                log("Query received: " + q->name);
            }
        }

        // Construct response
        DnsHeader response_header = header;
        response_header.query_response = true;
        response_header.answer_count = 0;

        std::vector<uint8_t> response = response_header.to_bytes();
        
        // Example: Resolve if we have the record
        log("Processed query from " + std::string(inet_ntoa(client_addr.sin_addr)));
                
        sendto(socket_fd_, response.data(), response.size(), 0, (const sockaddr*)&client_addr, client_len);
    }
};
