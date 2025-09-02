# Copilot Instructions for SapphireHook Development

## Project Overview
SapphireHook is a C++20 native hook library for FFXIV, designed with modern C++ practices and safety-first principles. We have access to Dalamud projects as **reference material only** - we learn from their approaches but implement our own solutions.

## Core Principles

### 1. **Learning from Dalamud, Not Copying**
- **Study their patterns**: Signature scanning, memory management, hook architecture
- **Understand their design decisions**: Why they chose certain approaches
- **Implement our own**: Create C++ equivalents using modern C++20 features
- **Respect their work**: No direct code copying, only learning from public interfaces

### 2. **Memory Management Philosophy**
Based on Dalamud's approach, focus on:
- **Safety first**: Always validate memory before access
- **RAII patterns**: Use smart pointers and automatic cleanup
- **Caching**: Cache expensive operations like signature scans
- **Modular design**: Separate concerns (scanning, hooking, memory management)

## Architecture Guidelines

### Memory Management Classes

#### MemoryBuffer (C++20 Implementation)
// Our modern C++20 approach inspired by Dalamud's buffer management class MemoryBuffer { private: std::unique_ptr<uint8_t[]> m_data; size_t m_size;
public: // C++20 span interface for safe memory views stdspan<uint8_t> GetSpan() const; stdspan<const uint8_t> GetConstSpan() const;
// Range-based loop support
uint8_t* begin() const;
uint8_t* end() const;
};


**Learning from Dalamud's CircularBuffer and MemoryBufferHelper**:
- They use sophisticated buffer management for injection
- We implement simpler but safer C++20 patterns
- Focus on RAII and automatic resource management

#### Pattern Scanner (Inspired by SigScanner.cs)

**Dalamud's approach we can learn from**:
- Caching signatures to disk for performance
- Separating text vs data scanning
- Thread-safe scanning operations
- Robust error handling and fallbacks

**Our C++20 implementation**:

class PatternScanner { // Modern C++20 features static stdoptional<ScanResult> ScanPattern(stdstring_view pattern);
// Concepts for type safety
template<ScanableMemory T>
static std::optional<ScanResult> ScanPattern(const T& memory, std::string_view pattern);

// Caching (learning from Dalamud's JSON cache)
static void LoadCache(const std::filesystem::path& cacheFile);
static void SaveCache(const std::filesystem::path& cacheFile);
};

Avoid stubs and pseudocode where possible; provide real implementations or detailed class/method signatures.

### Hook Management (Learning from GameInteropProvider)

**Dalamud's lessons**:
- Centralized hook tracking for cleanup
- Different hook types (address, import, symbol)
- Plugin-scoped hook management
- Automatic cleanup on shutdown

**Our approach**:

not yet implemented

### Module Information (Inspired by ProcessModule handling)

**Learning from Dalamud's module management**:
- Robust module enumeration
- Caching module information
- Safe memory access validation
- Export table parsing

**Our implementation**:

not yet implemented


## Development Practices

### 1. **Safety-First Design**
Inspired by Dalamud's defensive programming:
- Always validate pointers before use
- Use exceptions for unrecoverable errors
- Prefer `std::optional` for potentially failing operations
- Implement comprehensive error logging

### 2. **Modern C++23 Features**
Where Dalamud uses C# generics, we use:
- **Concepts**: Type-safe template constraints
- **Spans**: Safe memory views without ownership  
- **Expected**: Rich error handling instead of just optional
- **String views**: Efficient string parameter passing
- **Stacktrace**: Enhanced debugging capabilities
- **Print/Println**: Type-safe formatted output

### 3. **Build Configuration**
- Visual Studio 2022 (17.8+) with C++23 standard
- Static linking where possible for deployment simplicity
- Debug builds with extensive logging and assertions

### 4. **Testing Strategy**
Inspired by Dalamud's robust testing:
- Unit tests for pattern scanning
- Memory safety tests
- Hook installation/removal tests
- Integration tests with dummy processes

## Dalamud Reference Points

### Key Classes to Study (No Copying!)
- `SigScanner.cs`: Signature scanning patterns and caching
- `GameInteropProvider*.cs`: Hook management architecture  
- `Injector.cs`: Process injection techniques
- `SignatureHelper.cs`: Attribute-based signature resolution
- `MemoryBufferHelper`: Memory management patterns

### Design Patterns to Learn
1. **Service Management**: How Dalamud organizes dependencies
2. **Plugin Scoping**: Isolated resource management per plugin
3. **Fallback Strategies**: Graceful degradation when signatures fail
4. **Performance Monitoring**: Timing and metrics collection
5. **Configuration Management**: Runtime settings and persistence

## Code Style Guidelines

### Naming Conventions

class MyClass {           // PascalCase for classes private: int m_memberVar;      // m_ prefix for members
public: void DoSomething();   // PascalCase for methods int GetValue() const; // Explicit const correctness };
namespace SapphireHook {  // Project namespace // Free functions bool ValidateMemory(std::span<const uint8_t> data); }


### Error Handling
// Prefer stdoptional for fallible operations stdoptional<uintptr_t> FindPattern(std::string_view pattern);
// Use exceptions for programming errors void ValidateAddress(uintptr_t addr) { if (addr == 0) { throw std::invalid_argument("Address cannot be null"); } }


### Memory Safety

// Always use RAII class ResourceWrapper { std::unique_ptr<Resource> m_resource; public: ~ResourceWrapper() = default; // Automatic cleanup };
// Prefer spans over raw pointers void ProcessData(std::span<const uint8_t> data) { // Safe access with bounds checking for (auto byte : data) { // Process byte } }


## Project-Specific Guidelines

### 1. **File Organization**
src/ ├── Core/           # Memory management, pattern scanning ├── Hooking/        # Hook installation and management
├── Modules/        # Feature modules (commands, UI, etc.) ├── UI/             # ImGui interface components └── Entry/          # DLL entry point and initialization


### 2. **Dependencies**
- **ImGui**: UI rendering (learning from Dalamud's interface patterns)
- **MinHook**: Function hooking (studying Dalamud's hook management)
- **C++20 STL**: Modern standard library features

### 3. **Build Configuration**
- Visual Studio 2022 (17.8+) with C++23 standard
- Static linking where possible for deployment simplicity
- Debug builds with extensive logging and assertions

## Learning Resources

### Dalamud Study Points
1. **Memory Management**: How they handle process memory safely
2. **Signature Scanning**: Their pattern matching and caching strategies  
3. **Hook Architecture**: Plugin isolation and resource management
4. **Error Recovery**: Graceful failure handling
5. **Performance**: Optimization techniques for real-time operation

### Implementation Notes
- Study Dalamud's public interfaces, not internal implementation
- Focus on understanding the "why" behind their design choices
- Adapt their patterns to C++ strengths (RAII, templates, etc.)
- Maintain our own coding style and error handling approaches

## Contributing Guidelines

### When Adding New Features
1. **Research**: Study how Dalamud handles similar functionality
2. **Design**: Create C++20-native solution inspired by their approach
3. **Implement**: Write defensive, well-tested code
4. **Document**: Explain design decisions and Dalamud inspiration
5. **Test**: Verify safety and functionality thoroughly

### Code Review Focus
- Memory safety and RAII compliance
- C++20 feature usage appropriateness  
- Performance implications
- Error handling completeness
- API design consistency

Remember: We learn from Dalamud's excellent design but implement our own solutions using C++20's strengths. Respect their work by understanding and adapting, not copying.

