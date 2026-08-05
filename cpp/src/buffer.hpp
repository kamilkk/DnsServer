#pragma once
#include <span>
#include <vector>
#include <string>
#include "dns.hpp"

class ByteBuffer {
    std::span<const uint8_t> data_;
    size_t position_{0};

public:
    explicit ByteBuffer(std::span<const uint8_t> data) : data_(data) {}

    Result<uint8_t> read_u8() {
        if (position_ >= data_.size()) return std::unexpected(DnsErrorCode::BufferTooSmall);
        return data_[position_++];
    }

    Result<uint16_t> read_u16() {
        if (position_ + 2 > data_.size()) return std::unexpected(DnsErrorCode::BufferTooSmall);
        uint16_t val = (static_cast<uint16_t>(data_[position_]) << 8) | data_[position_ + 1];
        position_ += 2;
        return val;
    }

    Result<uint32_t> read_u32() {
        if (position_ + 4 > data_.size()) return std::unexpected(DnsErrorCode::BufferTooSmall);
        uint32_t val = (static_cast<uint32_t>(data_[position_]) << 24) |
                       (static_cast<uint32_t>(data_[position_ + 1]) << 16) |
                       (static_cast<uint32_t>(data_[position_ + 2]) << 8) |
                       static_cast<uint32_t>(data_[position_ + 3]);
        position_ += 4;
        return val;
    }

    Result<void> skip(size_t count) {
        if (position_ + count > data_.size()) return std::unexpected(DnsErrorCode::BufferTooSmall);
        position_ += count;
        return {};
    }

    Result<uint8_t> peek_u8() const {
        if (position_ >= data_.size()) return std::unexpected(DnsErrorCode::BufferTooSmall);
        return data_[position_];
    }

    size_t position() const { return position_; }
    void set_position(size_t pos) { position_ = pos; }
};

inline Result<std::string> parse_domain_name(ByteBuffer& buffer, size_t jumps) {
    // Prevent malicious packets from causing stack overflows via cyclic pointers
    if (jumps > 5) {
        return std::unexpected(DnsErrorCode::CompressionLoop);
    }

    std::string name;
    
    while (true) {
        auto len_res = buffer.peek_u8();
        if (!len_res) return std::unexpected(len_res.error());
        uint8_t len = *len_res;

        if ((len & 0xC0) == 0xC0) {
            // This is a compression pointer
            auto first = buffer.read_u8().value();
            auto second = buffer.read_u8();
            if (!second) return std::unexpected(second.error());
            
            uint16_t offset = ((first & 0x3F) << 8) | *second;
            size_t saved_pos = buffer.position();
            
            buffer.set_position(offset);
            
            // Note: We correctly pass jumps + 1 down the recursive stack
            auto part = parse_domain_name(buffer, jumps + 1);
            if (!part) return std::unexpected(part.error());
            
            name += *part;
            buffer.set_position(saved_pos);
            break;
        }

        if (len == 0) {
            buffer.read_u8(); // consume null byte
            break;
        }

        buffer.read_u8(); // consume length byte
        if (!name.empty()) name += ".";
        
        for (size_t i = 0; i < len; ++i) {
            auto ch = buffer.read_u8();
            if (!ch) return std::unexpected(ch.error());
            name += static_cast<char>(*ch);
        }
    }
    
    return name;
}

// Implementations for dns.hpp parse methods which require ByteBuffer

inline Result<DnsQuestion> DnsQuestion::parse(ByteBuffer& buffer) {
    auto name = parse_domain_name(buffer);
    if (!name) return std::unexpected(name.error());
    
    auto qtype = buffer.read_u16();
    if (!qtype) return std::unexpected(qtype.error());
    
    auto qclass = buffer.read_u16();
    if (!qclass) return std::unexpected(qclass.error());
    
    return DnsQuestion{*name, *qtype, *qclass};
}

inline Result<ResourceRecord> ResourceRecord::parse(ByteBuffer& buffer) {
    auto name = parse_domain_name(buffer);
    if (!name) return std::unexpected(name.error());
    
    auto rtype = buffer.read_u16();
    if (!rtype) return std::unexpected(rtype.error());
    
    auto rclass = buffer.read_u16();
    if (!rclass) return std::unexpected(rclass.error());
    
    auto ttl = buffer.read_u32();
    if (!ttl) return std::unexpected(ttl.error());
    
    auto rdlen = buffer.read_u16();
    if (!rdlen) return std::unexpected(rdlen.error());

    RData parsed_data;
    if (*rtype == 1 && *rdlen == 4) { // A Record
        auto ip = buffer.read_u32();
        if (!ip) return std::unexpected(ip.error());
        parsed_data = ARecord{*ip};
    } else if (*rtype == 28 && *rdlen == 16) { // AAAA Record
        IPv6Addr addr;
        for(int i = 0; i < 16; ++i) addr[i] = buffer.read_u8().value();
        parsed_data = AAAARecord{addr};
    } else { // Unknown
        UnknownRecord unknown;
        for(int i = 0; i < *rdlen; ++i) {
            unknown.data.push_back(buffer.read_u8().value());
        }
        parsed_data = std::move(unknown);
    }

    return ResourceRecord{*name, *rtype, *rclass, *ttl, std::move(parsed_data)};
}
