#pragma once

#include <capstone/capstone.h>
#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <variant>
#include <optional>
#include <atomic>

namespace SapphireHook {

    enum class CapstoneError {
        None,
        OpenFailed,
        InvalidMode,
        DisasmFailed,
        NullCallback,
        NoBuffer,
        ZeroSize,
        MemoryReadFailed
    };

    inline const char* CapstoneErrorToString(CapstoneError e) {
        switch (e) {
        case CapstoneError::None: return "None";
        case CapstoneError::OpenFailed: return "OpenFailed";
        case CapstoneError::InvalidMode: return "InvalidMode";
        case CapstoneError::DisasmFailed: return "DisasmFailed";
        case CapstoneError::NullCallback: return "NullCallback";
        case CapstoneError::NoBuffer: return "NoBuffer";
        case CapstoneError::ZeroSize: return "ZeroSize";
        case CapstoneError::MemoryReadFailed: return "MemoryReadFailed";
        default: return "Unknown";
        }
    }

    template<typename T>
    class Result {
    public:
        Result(T&& v) : m_storage(std::move(v)) {}
        Result(const T& v) : m_storage(v) {}
        Result(CapstoneError e) : m_storage(e) {}

        bool ok() const { return std::holds_alternative<T>(m_storage); }
        const T& value() const { return std::get<T>(m_storage); }
        T& value() { return std::get<T>(m_storage); }
        CapstoneError error() const {
            return ok() ? CapstoneError::None : std::get<CapstoneError>(m_storage);
        }
    private:
        std::variant<T, CapstoneError> m_storage;
    };

    struct DecodedInsn {
        uintptr_t address{};
        uint8_t size{};
        uint8_t bytes[16]{};
        std::string mnemonic;
        std::string operands;
        bool isRet{};
        bool isCall{};
        bool isBranch{};
        uintptr_t target{};
    };

    class CapstoneWrapper {
    public:
        CapstoneWrapper();
        ~CapstoneWrapper();

        CapstoneWrapper(const CapstoneWrapper&) = delete;
        CapstoneWrapper& operator=(const CapstoneWrapper&) = delete;
        CapstoneWrapper(CapstoneWrapper&&) noexcept;
        CapstoneWrapper& operator=(CapstoneWrapper&&) noexcept;

        bool valid() const { return m_handle != 0; }

        // Disassemble a memory buffer already read into memory (preferred).
        Result<std::vector<DecodedInsn>> DisassembleBuffer(const uint8_t* data,
            size_t size,
            uintptr_t startAddress,
            size_t maxInstructions = 0);

    private:
        csh m_handle{};
        void Close();
    };

} // namespace SapphireHook