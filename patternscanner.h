#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

bool PatternToBytes(const char* pattern, std::vector<int>& bytes);
uintptr_t patternscan(uintptr_t start, size_t length, const char* pattern);
uintptr_t GetModuleBaseAddress(const wchar_t* moduleName, size_t& outSize);
