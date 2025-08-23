#pragma once

class HookManager {
public:
	static void Initialize();
	static void SetSpeedMultiplier(float multiplier);
	static void Shutdown();
};

void InitHooks();