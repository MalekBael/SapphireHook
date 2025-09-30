#include "CapstoneWrapper.h"
#include "../Logger/Logger.h"
#include <cstring>

namespace SapphireHook {

    CapstoneWrapper::CapstoneWrapper() {
        csh h{};
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) {
            LogError("CapstoneWrapper: cs_open failed");
            return;
        }
        cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
        m_handle = h;
    }

    CapstoneWrapper::~CapstoneWrapper() {
        Close();
    }

    CapstoneWrapper::CapstoneWrapper(CapstoneWrapper&& other) noexcept {
        m_handle = other.m_handle;
        other.m_handle = 0;
    }

    CapstoneWrapper& CapstoneWrapper::operator=(CapstoneWrapper&& other) noexcept {
        if (this != &other) {
            Close();
            m_handle = other.m_handle;
            other.m_handle = 0;
        }
        return *this;
    }

    void CapstoneWrapper::Close() {
        if (m_handle) {
            cs_close(&m_handle);
            m_handle = 0;
        }
    }

    Result<std::vector<DecodedInsn>>
        CapstoneWrapper::DisassembleBuffer(const uint8_t* data,
            size_t size,
            uintptr_t startAddress,
            size_t maxInstructions) {
        if (!m_handle) {
            return CapstoneError::OpenFailed;
        }
        if (!data) {
            return CapstoneError::NoBuffer;
        }
        if (size == 0) {
            return CapstoneError::ZeroSize;
        }

        cs_insn* insn = nullptr;
        size_t count = cs_disasm(m_handle, data, size, startAddress,
            0, &insn);
        if (!count) {
            return CapstoneError::DisasmFailed;
        }

        std::vector<DecodedInsn> out;
        out.reserve(count);

        for (size_t i = 0; i < count; ++i) {
            if (maxInstructions && out.size() >= maxInstructions)
                break;

            DecodedInsn di{};
            di.address = insn[i].address;
            di.size = static_cast<uint8_t>(insn[i].size > 16 ? 16 : insn[i].size);
            std::memcpy(di.bytes, insn[i].bytes, di.size);
            di.mnemonic = insn[i].mnemonic;
            di.operands = insn[i].op_str;
            switch (insn[i].id) {
            case X86_INS_RET: di.isRet = true; break;
            case X86_INS_JMP:
            case X86_INS_JA: case X86_INS_JAE: case X86_INS_JB: case X86_INS_JBE:
            case X86_INS_JE: case X86_INS_JNE: case X86_INS_JG: case X86_INS_JGE:
            case X86_INS_JL: case X86_INS_JLE: case X86_INS_JP: case X86_INS_JNP:
            case X86_INS_JS: case X86_INS_JNS:
                di.isBranch = true; break;
            case X86_INS_CALL:
                di.isCall = true; break;
            }
            if ((di.isBranch || di.isCall) && insn[i].detail) {
                const cs_x86& x = insn[i].detail->x86;
                for (uint8_t opi = 0; opi < x.op_count; ++opi) {
                    if (x.operands[opi].type == X86_OP_IMM) {
                        di.target = static_cast<uintptr_t>(x.operands[opi].imm);
                        break;
                    }
                }
            }
            out.push_back(std::move(di));
            if (di.isRet) {
                // Early break on first RET for Phase 1
                break;
            }
        }

        cs_free(insn, count);
        return out;
    }

} // namespace SapphireHook