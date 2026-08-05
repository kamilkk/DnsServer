#pragma once
#include <system_error>
#include <expected>
#include <string>

enum class DnsErrorCode {
    BufferTooSmall = 1,
    InvalidDomainName,
    CompressionLoop,
    NetworkError,
    NotImplemented
};

// Custom error category for DNS errors
struct DnsErrorCategory : std::error_category {
    const char* name() const noexcept override { return "dns"; }
    std::string message(int ev) const override {
        switch (static_cast<DnsErrorCode>(ev)) {
            case DnsErrorCode::BufferTooSmall: return "Buffer too small";
            case DnsErrorCode::InvalidDomainName: return "Invalid domain name";
            case DnsErrorCode::CompressionLoop: return "Compression loop detected";
            case DnsErrorCode::NetworkError: return "Network error";
            case DnsErrorCode::NotImplemented: return "Not implemented";
            default: return "Unknown DNS error";
        }
    }
};

inline const DnsErrorCategory& dns_category() {
    static DnsErrorCategory instance;
    return instance;
}

inline std::error_code make_error_code(DnsErrorCode e) {
    return {static_cast<int>(e), dns_category()};
}

namespace std {
    template <>
    struct is_error_code_enum<DnsErrorCode> : true_type {};
}

template <typename T>
using Result = std::expected<T, std::error_code>;

#include <cstdint>
#include <bit>
#include <vector>
#include <span>

struct DnsHeader {
    uint16_t id{0};
    bool query_response{false};
    uint8_t opcode{0};
    bool authoritative_answer{false};
    bool truncation{false};
    bool recursion_desired{false};
    bool recursion_available{false};
    uint8_t z{0};
    uint8_t response_code{0};
    
    uint16_t question_count{0};
    uint16_t answer_count{0};
    uint16_t nameserver_count{0};
    uint16_t additional_count{0};

    static constexpr size_t SIZE = 12;

    std::vector<uint8_t> to_bytes() const {
        std::vector<uint8_t> buf(SIZE, 0);
        
        auto write_u16 = [&buf](size_t offset, uint16_t val) {
            buf[offset] = (val >> 8) & 0xFF;
            buf[offset + 1] = val & 0xFF;
        };

        write_u16(0, id);

        uint16_t flags = 0;
        flags |= (query_response ? 1 : 0) << 15;
        flags |= (opcode & 0xF) << 11;
        flags |= (authoritative_answer ? 1 : 0) << 10;
        flags |= (truncation ? 1 : 0) << 9;
        flags |= (recursion_desired ? 1 : 0) << 8;
        flags |= (recursion_available ? 1 : 0) << 7;
        flags |= (z & 0x7) << 4;
        flags |= (response_code & 0xF);
        
        write_u16(2, flags);
        write_u16(4, question_count);
        write_u16(6, answer_count);
        write_u16(8, nameserver_count);
        write_u16(10, additional_count);

        return buf;
    }

    static Result<DnsHeader> from_bytes(std::span<const uint8_t> data) {
        if (data.size() < SIZE) {
            return std::unexpected(DnsErrorCode::BufferTooSmall);
        }

        auto read_u16 = [&data](size_t offset) -> uint16_t {
            uint16_t val = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
            return val;
        };

        DnsHeader header;
        header.id = read_u16(0);
        uint16_t flags = read_u16(2);
        
        header.query_response = (flags >> 15) & 1;
        header.opcode = (flags >> 11) & 0xF;
        header.authoritative_answer = (flags >> 10) & 1;
        header.truncation = (flags >> 9) & 1;
        header.recursion_desired = (flags >> 8) & 1;
        header.recursion_available = (flags >> 7) & 1;
        header.z = (flags >> 4) & 0x7;
        header.response_code = flags & 0xF;

        header.question_count = read_u16(4);
        header.answer_count = read_u16(6);
        header.nameserver_count = read_u16(8);
        header.additional_count = read_u16(10);

        return header;
    }
};

#include <variant>
#include <array>

// Forward declaration for ByteBuffer needed by parse functions
class ByteBuffer;
Result<std::string> parse_domain_name(ByteBuffer& buffer, size_t jumps = 0);

struct DnsQuestion {
    std::string name;
    uint16_t qtype;
    uint16_t qclass;

    static Result<DnsQuestion> parse(ByteBuffer& buffer);
};

using IPv4Addr = uint32_t;
using IPv6Addr = std::array<uint8_t, 16>;

struct ARecord { IPv4Addr addr; };
struct AAAARecord { IPv6Addr addr; };
struct CNAMERecord { std::string domain; };
struct NSRecord { std::string domain; };
struct UnknownRecord { std::vector<uint8_t> data; };

// std::variant prevents unsafe casting and invalid memory access
using RData = std::variant<ARecord, AAAARecord, CNAMERecord, NSRecord, UnknownRecord>;

struct ResourceRecord {
    std::string name;
    uint16_t rtype;
    uint16_t rclass;
    uint32_t ttl;
    RData rdata;

    static Result<ResourceRecord> parse(ByteBuffer& buffer);
};
