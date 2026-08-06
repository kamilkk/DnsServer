#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <mutex>
#include <vector>
#include <string>
#include <unordered_map>
#include <arpa/inet.h>
#include "server.hpp"
#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

std::unordered_map<std::string, uint32_t> load_records(const std::string& filename) {
    std::unordered_map<std::string, uint32_t> records;
    std::ifstream file(filename);
    std::string line;
    
    if (!file.is_open()) {
        std::cerr << "Could not open " << filename << "\n";
        return records;
    }
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string domain, type, ip_str;
        
        if (iss >> domain >> type >> ip_str) {
            if (type == "A") {
                uint32_t ip;
                inet_pton(AF_INET, ip_str.c_str(), &ip);
                records[domain] = ntohl(ip);
            }
        }
    }
    return records;
}

using namespace ftxui;

int main() {
    auto records = load_records("records.txt");
    
    // Create server on port 15353
    DnsServer server(15353, records);
    
    std::vector<std::string> logs;
    std::mutex logs_mutex;

    auto screen = ScreenInteractive::Fullscreen();
    // Callback to append logs and trigger a UI redraw
    server.set_log_callback([&](const std::string& msg) {
        std::lock_guard<std::mutex> lock(logs_mutex);
        logs.push_back(msg);
        if (logs.size() > 50) logs.erase(logs.begin()); // Keep last 50 logs
        screen.PostEvent(Event::Custom);
    });
    // Run server in background thread
    std::thread server_thread([&]() {
        server.start();
    });

    // Build the FTXUI Renderer
    auto renderer = Renderer([&] {
        std::lock_guard<std::mutex> lock(logs_mutex);

        // Build the records list UI
        Elements records_elements;
        for (const auto& [domain, ip] : records) {
            in_addr addr;
            addr.s_addr = htonl(ip);
            records_elements.push_back(
                hbox({text(domain) | flex, text(inet_ntoa(addr))})
            );
        }        

        auto left_panel = window(text(" DNS Records "), vbox(std::move(records_elements))) | flex;
        // Build the logs UI
        Elements log_elements;
        for (const auto& log : logs) {
            log_elements.push_back(text(log));
        }        

        auto right_panel = window(text(" Live Query Logs "), vbox(std::move(log_elements))) | flex;
        auto layout = hbox({
            left_panel,
            right_panel
        }) | border | color(Color::Cyan);
        
        return vbox({
            layout | flex,
            text(" Press x or X to quit ") | dim
        });
    });
    
    auto main_component = CatchEvent(renderer, [&](Event event) {
        if (event == Event::Character('x') || event == Event::Character('X')) {
            screen.ExitLoopClosure()();
            return true;
        }
        return false;
    });

    // Start the interactive UI loop (blocks until user quits)
    screen.Loop(main_component);
    // Stop server and clean up when UI closes
    server.stop();
    server_thread.join();
    
    return 0;
}