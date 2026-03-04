#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <optional>

#include <magic_enum/magic_enum.hpp>

namespace SapphireHook {

template<typename E>
constexpr std::string_view EnumName(E value) noexcept {
    return magic_enum::enum_name(value);
}

template<typename E>
std::string EnumNameOr(E value, std::string_view fallback = "?") {
    auto name = magic_enum::enum_name(value);
    return name.empty() ? std::string(fallback) : std::string(name);
}

template<typename E>
std::string EnumNameFromInt(std::underlying_type_t<E> value, std::string_view fallback = "?") {
    auto enumVal = magic_enum::enum_cast<E>(value);
    if (enumVal.has_value()) {
        auto name = magic_enum::enum_name(*enumVal);
        return name.empty() ? std::string(fallback) : std::string(name);
    }
    return std::string(fallback);
}

template<typename E>
constexpr size_t EnumCount() noexcept {
    return magic_enum::enum_count<E>();
}

template<typename E>
std::optional<E> EnumParse(std::string_view name) noexcept {
    return magic_enum::enum_cast<E>(name);
}

}   

#include <xxhash.h>

namespace SapphireHook {

inline uint64_t FastHash64(const void* data, size_t length, uint64_t seed = 0) noexcept {
    return XXH64(data, length, seed);
}

inline uint64_t FastHash64(std::string_view str, uint64_t seed = 0) noexcept {
    return XXH64(str.data(), str.size(), seed);
}

inline uint32_t FastHash32(const void* data, size_t length, uint32_t seed = 0) noexcept {
    return XXH32(data, length, seed);
}

inline uint32_t FastHash32(std::string_view str, uint32_t seed = 0) noexcept {
    return XXH32(str.data(), str.size(), seed);
}

class IncrementalHash64 {
public:
    IncrementalHash64(uint64_t seed = 0) {
        m_state = XXH64_createState();
        XXH64_reset(m_state, seed);
    }
    
    ~IncrementalHash64() {
        if (m_state) XXH64_freeState(m_state);
    }
    
    IncrementalHash64(const IncrementalHash64&) = delete;
    IncrementalHash64& operator=(const IncrementalHash64&) = delete;
    
    IncrementalHash64(IncrementalHash64&& other) noexcept : m_state(other.m_state) {
        other.m_state = nullptr;
    }
    
    IncrementalHash64& operator=(IncrementalHash64&& other) noexcept {
        if (this != &other) {
            if (m_state) XXH64_freeState(m_state);
            m_state = other.m_state;
            other.m_state = nullptr;
        }
        return *this;
    }
    
    void Update(const void* data, size_t length) {
        if (m_state) XXH64_update(m_state, data, length);
    }
    
    void Update(std::string_view str) {
        Update(str.data(), str.size());
    }
    
    uint64_t Digest() const {
        return m_state ? XXH64_digest(m_state) : 0;
    }
    
    void Reset(uint64_t seed = 0) {
        if (m_state) XXH64_reset(m_state, seed);
    }
    
private:
    XXH64_state_t* m_state = nullptr;
};

}   

#include <fmt/core.h>
#include <fmt/format.h>
#include <fmt/chrono.h>

namespace SapphireHook {

template<typename... Args>
std::string Format(fmt::format_string<Args...> fmt, Args&&... args) {
    return fmt::format(fmt, std::forward<Args>(args)...);
}

template<typename OutputIt, typename... Args>
OutputIt FormatTo(OutputIt out, fmt::format_string<Args...> fmt, Args&&... args) {
    return fmt::format_to(out, fmt, std::forward<Args>(args)...);
}

template<typename... Args>
std::string FormatLimited(size_t maxSize, fmt::format_string<Args...> fmt, Args&&... args) {
    std::string result;
    result.reserve(maxSize);
    fmt::format_to(std::back_inserter(result), fmt, std::forward<Args>(args)...);
    if (result.size() > maxSize) {
        result.resize(maxSize);
    }
    return result;
}

}   
