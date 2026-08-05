#pragma once
#include <exception>
#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <iostream>
#include <unordered_map>
#include "dns.hpp"
#include "buffer.hpp"

using asio::awaitable;
using asio::ip::udp;

class DnsServer {
    udp::socket socket_;
    std::unordered_map<std::string, uint32_t> records_; // Domain -> IP

public:
    DnsServer(asio::io_context& io_context, uint16_t port)
        : socket_(io_context, udp::endpoint(udp::v4(), port)) {
        
        // Example mock record: example.local -> 192.168.1.10
        records_["example.local"] = (192 << 24) | (168 << 16) | (1 << 8) | 10;
    }

    awaitable<void> start() {
        std::vector<uint8_t> data(1024);
        
        while (true) {
            udp::endpoint sender_endpoint;
            
            // co_await yields execution until a packet arrives, freeing the thread
            size_t length = co_await socket_.async_receive_from(
                asio::buffer(data), sender_endpoint, asio::use_awaitable);

            // Spawn a new detached coroutine to handle the packet concurrently
            asio::co_spawn(socket_.get_executor(), 
                handle_query(std::vector<uint8_t>(data.begin(), data.begin() + length), sender_endpoint), 
                asio::detached);
        }
    }

private:
    awaitable<void> handle_query(std::vector<uint8_t> packet, udp::endpoint sender) {
        ByteBuffer buf(packet);
        auto header_res = DnsHeader::from_bytes(packet);
        
        if (!header_res) {
            std::cerr << "Invalid header: " << header_res.error().message() << "\n";
            co_return;
        }
        
        auto& header = *header_res;
        buf.skip(DnsHeader::SIZE);

        std::vector<DnsQuestion> questions;
        for (int i = 0; i < header.question_count; ++i) {
            if (auto q = DnsQuestion::parse(buf)) {
                questions.push_back(*q);
            }
        }

        // Construct response
        DnsHeader response_header = header;
        response_header.query_response = true;
        response_header.answer_count = 0;

        std::vector<uint8_t> response = response_header.to_bytes();
        
        // (In a real implementation, you would serialize questions and answers back into 'response' here)

        std::cout << "Processed query from " << sender.address().to_string() << "\n";
        
        // Send response asynchronously
        co_await socket_.async_send_to(asio::buffer(response), sender, asio::use_awaitable);
    }
};
