#pragma once
#include <deque>  
#include "../UI/UIModule.h"
#include "../vendor/imgui/imgui.h"
#include "../vendor/hex_editor/imgui_hex.h"
#include "../Core/SafeMemory.h"
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include <memory>
#include <optional>
#include <atomic>
#include <future>
#include <mutex>
#include <unordered_map>

struct DisassembledInstr {
    uintptr_t address{};
    std::string bytes;
    std::string mnemonic;
    std::string operands;
    bool isBranch{};
    bool isCall{};
    bool isRet{};
    uintptr_t target{};
};

struct PseudoVariable {
    enum Kind { Stack, Register, Immediate, Memory };
    Kind kind;
    std::string name;
    int64_t value{};
    PseudoVariable(Kind k = Register, const std::string& n = "", int64_t v = 0)
        : kind(k), name(n), value(v) {}
};

struct PseudoStatement {
    enum Type {
        Assign,
        IfCond,
        Goto,
        Return,
        Call,
        Label,
        Comment
    };
    Type type;
    std::string lhs;
    std::string rhs;
    std::string condition;
    uintptr_t target{};
    std::string label;
    std::string comment;
    PseudoStatement(Type t = Comment) : type(t) {}
};

struct PseudoFunctionIR {
    uintptr_t start{};
    size_t size{};
    std::vector<PseudoStatement> statements;
    bool truncated{false};
    int stackFrameSize{0};
};

class IDisassemblyBackend {
public:
    virtual ~IDisassemblyBackend() = default;
    virtual bool Disassemble(uintptr_t start, size_t maxBytes,
        std::vector<DisassembledInstr>& out,
        size_t& bytesConsumed) = 0;
};

class IDecompilerBackend {
public:
    virtual ~IDecompilerBackend() = default;
    virtual bool Decompile(uintptr_t start, size_t codeSize,
        std::string& pseudoC) = 0;
};

class CapstoneBackend : public IDisassemblyBackend {
public:
    CapstoneBackend();
    ~CapstoneBackend() override;
    bool Disassemble(uintptr_t start, size_t maxBytes,
        std::vector<DisassembledInstr>& out,
        size_t& bytesConsumed) override;
private:
    void* m_handle{};
};

class PseudoDecompilerBackend : public IDecompilerBackend {
public:
    struct Timings {
        double disasmMs{};
        double analyzeMs{};
        double genMs{};
        double totalMs{};
    };
    bool Decompile(uintptr_t start, size_t codeSize,
        std::string& pseudoC) override;
    const Timings& GetLastTimings() const { return m_lastTimings; }
private:
    Timings m_lastTimings{};
    std::string ConvertToCppStyle(const std::string& operand);
    std::string ConvertConditionToCpp(const std::string& condition);
    std::string ConvertCallToCpp(const std::string& call);
    bool DisassembleFunction(uintptr_t start, size_t maxSize,
        std::vector<DisassembledInstr>& instructions);
    PseudoFunctionIR AnalyzeInstructions(const std::vector<DisassembledInstr>& instructions);
    std::string GeneratePseudocode(const PseudoFunctionIR& ir);
    std::string NormalizeOperand(const std::string& operand);
    bool IsStackReference(const std::string& operand);
    std::string GetConditionFromJump(const std::string& mnemonic);
};

struct PseudoCacheEntry {
    std::string pseudocode;
    std::string error;
    std::atomic<bool> ready{ false };
    size_t codeSize{};
    uint64_t buildHash{};
    uint64_t memoryVersion{};
    double tDecodeMs{};
    double tIRMs{};
    double tGenMs{};
    double tTotalMs{};
};

class MemoryViewerModule : public SapphireHook::UIModule {
public:
    const char* GetName() const override { return "memory_viewer"; }
    const char* GetDisplayName() const override { return "Memory Viewer"; }

    void Initialize() override;
    void Shutdown() override;
    ~MemoryViewerModule() override;

    void RenderMenu() override {}
    void RenderWindow() override;

    bool IsWindowOpen() const override { return m_windowOpen; }
    void SetWindowOpen(bool open) override { m_windowOpen = open; }

    static bool SafeRead(uintptr_t address, void* outBuf, size_t size);
    static bool SafeWrite(uintptr_t address, const void* inBuf, size_t size);
    static bool SafeStaticRead(uintptr_t addr, void* out, size_t sz);

private:
    static int  StaticReadCallback(ImGuiHexEditorState* state, int offset, void* buf, int size);
    static int  StaticWriteCallback(ImGuiHexEditorState* state, int offset, void* buf, int size);
    static bool StaticGetAddressNameCallback(ImGuiHexEditorState* state, int offset, char* buf, int size);
    static ImGuiHexEditorHighlightFlags StaticSingleHighlightCallback(ImGuiHexEditorState* state, int offset, ImColor* color, ImColor* text_color, ImColor* border_color);

    void EnsureBufferSize(size_t size);
    void RefreshBuffer();
    void OnBytesModified(uintptr_t address, size_t size);

    bool m_windowOpen = false;
    uintptr_t m_viewAddress = 0;
    int m_viewSize = 0x400;
    bool m_readOnly = true;
    bool m_autoRefresh = false;
    float m_refreshInterval = 0.5f;
    float m_timeSinceLastRefresh = 0.0f;

    char m_addressInput[32] = "0x0";

    int   m_hlFrom = -1;
    int   m_hlTo = -1;
    ImVec4 m_hlColor = ImVec4(0.2f, 0.6f, 1.0f, 0.35f);
    bool  m_hlAscii = true;
    bool  m_hlBorder = true;
    bool  m_hlFullSized = true;

    ImGuiHexEditorState m_hexState{};
    std::vector<std::uint8_t> m_buffer;

    std::unique_ptr<IDisassemblyBackend> m_disBackend;
    std::unique_ptr<IDecompilerBackend>  m_decompBackend;

    std::vector<DisassembledInstr> m_lastDisasm;
    uintptr_t m_lastFuncStart{ 0 };
    size_t    m_lastFuncSize{ 0 };
    bool      m_disasmDirty{ true };

    std::mutex m_pcMutex;
    std::unordered_map<uintptr_t, std::shared_ptr<PseudoCacheEntry>> m_pseudoCache;

    std::atomic<bool> m_workerRun{ false };
    std::thread       m_worker;
    struct WorkItem {
        enum Type { Decompile } type;
        uintptr_t start;
        size_t size;
    };
    std::mutex m_wqMutex;
    std::deque<WorkItem> m_workQueue;

    std::atomic<bool> m_abortDecompile{ false };
    std::atomic<int> m_pseudoProgress{ 0 };
    size_t m_pseudoMaxBytes{ 0x4000 };
    int m_pseudoTimeoutMs{ 5000 };

    std::atomic<uint64_t> m_memoryMutationCounter{ 0 };
    uint64_t m_lastDisasmMemoryVersion{ 0 };
    double   m_lastDecodeMs{ 0.0 };

    bool m_pendingPseudoRequest{ false };
    bool m_showSideBySide{ false };

    // Selectable pseudocode buffer
    std::string m_pseudoDisplayBuffer;
    uint64_t    m_pseudoDisplayBufferVersion{ 0 };
    bool        m_useSelectablePseudo{ true };

    // Export UI
    bool  m_exportPopupOpen{ false };
    char  m_exportPath[260]{};
    bool  m_exportOverwriteConfirm{ false };
    std::string m_lastExportStatus;

    void InitAnalysisBackends();
    void ShutdownAnalysisBackends();

    bool BuildDisassembly(uintptr_t anyAddressInFunction);
    uintptr_t FindFunctionStartHeuristic(uintptr_t addr);
    size_t    DetermineFunctionSize(uintptr_t start);

    void QueueDecompile(uintptr_t start, size_t size);
    void WorkerLoop();
    uint64_t ComputeImageHash() const;

    void RenderDisassemblyTab();
    void RenderPseudocodeTab();
    void RenderAnalysisToolbar();

    // Export helpers
    std::string BuildExportText(const PseudoCacheEntry& entry) const;
    bool WriteTextFileUTF8(const char* path, const std::string& content, bool overwrite, std::string& err);
};