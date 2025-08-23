#include "patternscanner.h"
#include <windows.h>
#include <psapi.h>
#include <vector>
#include <cstdlib>

bool PatternToBytes(const char* pattern, std::vector<int>& bytes)
{
	bytes.clear();
	const char* current = pattern;
	while (*current)
	{
		if (*current == ' ')
		{
			current++;
			continue;
		}
		if (*current == '?')
		{
			current++;
			if (*current == '?') current++;
			bytes.push_back(-1);
		}
		else
		{
			char byteString[3] = { 0 };
			byteString[0] = *current++;
			byteString[1] = *current++;
			int byte = strtoul(byteString, nullptr, 16);
			bytes.push_back(byte);
		}
	}
	return !bytes.empty();
}

uintptr_t patternscan(uintptr_t start, size_t length, const char* pattern)
{
	std::vector<int> patternBytes;
	if (!PatternToBytes(pattern, patternBytes))
		return 0;

	size_t patternLength = patternBytes.size();
	const unsigned char* scanBytes = reinterpret_cast<const unsigned char*>(start);

	for (size_t i = 0; i <= length - patternLength; i++)
	{
		bool found = true;
		for (size_t j = 0; j < patternLength; j++)
		{
			if (patternBytes[j] != -1 && scanBytes[i + j] != patternBytes[j])
			{
				found = false;
				break;
			}
		}
		if (found)
		{
			return start + i;
		}
	}
	return 0;
}

uintptr_t GetModuleBaseAddress(const wchar_t* moduleName, size_t& outSize)
{
	HMODULE hModule;

	// If moduleName is NULL, get the current module (exe)
	if (!moduleName)
	{
		hModule = GetModuleHandleW(NULL);
	}
	else
	{
		hModule = GetModuleHandleW(moduleName);
	}

	if (!hModule)
		return 0;

	MODULEINFO modInfo = { 0 };
	if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo)))
		return 0;

	outSize = (size_t)modInfo.SizeOfImage;
	return (uintptr_t)modInfo.lpBaseOfDll;
}