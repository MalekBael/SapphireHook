#include "../Tools/LiveTraceMonitor.h"
#include "../Logger/Logger.h"
#include "../vendor/imgui/imgui.h"
#include <algorithm>
#include <unordered_map>
#include <cstdint>

using namespace SapphireHook;

LiveTraceMonitor* LiveTraceMonitor::s_instance = nullptr;

LiveTraceMonitor::LiveTraceMonitor() = default;

LiveTraceMonitor::~LiveTraceMonitor()
{
	// Ensure background thread is stopped
	m_samplingActive.store(false);
	if (m_samplingThread.joinable()) {
		try { m_samplingThread.join(); }
		catch (...) {}
	}
	if (s_instance == this) s_instance = nullptr;
}

void LiveTraceMonitor::Initialize()
{
	s_instance = this;
	LogInfo("LiveTraceMonitor initialized");
}

void LiveTraceMonitor::RenderMenu()
{
	if (ImGui::MenuItem(GetDisplayName(), nullptr, m_windowOpen))
		m_windowOpen = !m_windowOpen;
}

void LiveTraceMonitor::RenderWindow()
{
	if (!m_windowOpen) return;

	ImGui::SetNextWindowSize(ImVec2(900, 600), ImGuiCond_FirstUseEver);
	if (!ImGui::Begin(GetDisplayName(), &m_windowOpen)) {
		ImGui::End();
		return;
	}

	// Control buttons
	if (!m_traceState.capturing) {
		if (ImGui::Button("Start Capture")) StartCapture();
	}
	else {
		if (ImGui::Button("Stop Capture")) StopCapture();
		ImGui::SameLine();
		if (ImGui::Button("Clear")) ClearTrace();
	}

	ImGui::SameLine();
	ImGui::Text("Total Calls: %zu | Unique: %zu | CPS: %.2f",
		m_traceState.totalCalls,
		m_traceState.uniqueFunctions.size(),
		m_traceState.callsPerSecond);

	ImGui::Separator();

	// Render the actual trace data
	RenderTraceTable();

	// Render metrics panel
	RenderMetrics();

	ImGui::End();
}

void LiveTraceMonitor::StartCapture()
{
	std::scoped_lock lk(m_traceState.mutex);
	m_traceState.capturing = true;
	m_traceState.totalCalls = 0;
	m_traceState.callsPerSecond = 0.0f;
	m_traceState.startTime = std::chrono::steady_clock::now();
	m_traceState.lastUpdateTime = m_traceState.startTime;

	if (!m_samplingActive.exchange(true)) {
		m_samplingThread = std::thread([this]() { UpdateMetrics(); });
	}

	LogInfo("Live trace capture started");
}

void LiveTraceMonitor::StopCapture()
{
	{
		std::scoped_lock lk(m_traceState.mutex);
		m_traceState.capturing = false;
	}
	m_samplingActive.store(false);
	if (m_samplingThread.joinable()) {
		try { m_samplingThread.join(); }
		catch (...) {}
	}

	LogInfo("Live trace capture stopped");
}

void LiveTraceMonitor::ClearTrace()
{
	std::scoped_lock lk(m_traceState.mutex);
	m_traceState.entries.clear();
	m_traceState.uniqueFunctions.clear();
	m_traceState.totalCalls = 0;
	m_traceState.callsPerSecond = 0.0f;
	m_traceState.startTime = std::chrono::steady_clock::now();
	m_traceState.lastUpdateTime = m_traceState.startTime;

	LogInfo("Live trace data cleared");
}

void LiveTraceMonitor::AddTraceEntry(uintptr_t address, uintptr_t callerAddress, const std::string& functionName)
{
	if (!m_traceState.capturing) return;

	std::scoped_lock lk(m_traceState.mutex);
	TraceEntry e;
	e.timestamp = std::chrono::steady_clock::now();
	e.address = address;
	e.callerAddress = callerAddress;
	e.functionName = functionName;
	m_traceState.entries.emplace_back(std::move(e));
	m_traceState.uniqueFunctions.insert(address);
	++m_traceState.totalCalls;
}

void LiveTraceMonitor::UpdateMetrics()
{
	size_t lastTotal = 0;

	while (m_samplingActive.load()) {
		{
			std::scoped_lock lk(m_traceState.mutex);
			const auto now = std::chrono::steady_clock::now();
			const float dt = std::chrono::duration<float>(now - m_traceState.lastUpdateTime).count();
			if (dt >= 0.25f) {
				const size_t delta = (m_traceState.totalCalls >= lastTotal)
					? (m_traceState.totalCalls - lastTotal)
					: 0;
				m_traceState.callsPerSecond = (dt > 0.0f) ? (static_cast<float>(delta) / dt) : 0.0f;
				m_traceState.lastUpdateTime = now;
				lastTotal = m_traceState.totalCalls;

				// Trim buffer if needed
				constexpr size_t kMaxEntries = 5000;
				if (m_traceState.entries.size() > kMaxEntries) {
					const auto removeCount = m_traceState.entries.size() - kMaxEntries;
					m_traceState.entries.erase(
						m_traceState.entries.begin(),
						m_traceState.entries.begin() + static_cast<std::ptrdiff_t>(removeCount));
				}
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

void LiveTraceMonitor::RenderTraceTable()
{
	if (ImGui::BeginTable("LiveTraceTable", 4,
		ImGuiTableFlags_ScrollY | ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg))
	{
		ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 80.0f);
		ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthStretch);
		ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
		ImGui::TableSetupColumn("Caller", ImGuiTableColumnFlags_WidthFixed, 140.0f);
		ImGui::TableSetupScrollFreeze(0, 1); // Freeze header row
		ImGui::TableHeadersRow();

		std::scoped_lock lk(m_traceState.mutex);

		// Show most recent entries first
		for (auto it = m_traceState.entries.rbegin(); it != m_traceState.entries.rend(); ++it)
		{
			const auto& entry = *it;
			ImGui::TableNextRow();

			// Time column
			ImGui::TableSetColumnIndex(0);
			auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
				entry.timestamp - m_traceState.startTime).count();
			ImGui::Text("%d.%03ds", static_cast<int>(elapsed / 1000), static_cast<int>(elapsed % 1000));

			// Function name column
			ImGui::TableSetColumnIndex(1);
			ImGui::Text("%s", entry.functionName.c_str());

			// Address column
			ImGui::TableSetColumnIndex(2);
			ImGui::Text("0x%016llX", static_cast<unsigned long long>(entry.address));

			// Caller column
			ImGui::TableSetColumnIndex(3);
			ImGui::Text("0x%016llX", static_cast<unsigned long long>(entry.callerAddress));
		}

		ImGui::EndTable();
	}
}

void LiveTraceMonitor::RenderMetrics()
{
	ImGui::Separator();
	ImGui::Text("Metrics:");

	std::scoped_lock lk(m_traceState.mutex);

	if (m_traceState.capturing) {
		auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::steady_clock::now() - m_traceState.startTime).count();
		ImGui::Text("Capture Time: %llds", elapsed);
	}

	ImGui::Text("Buffer Usage: %zu / %zu entries",
		m_traceState.entries.size(), size_t(5000));

	// Top functions by call count
	std::unordered_map<uintptr_t, size_t> callCounts;
	for (const auto& entry : m_traceState.entries) {
		callCounts[entry.address]++;
	}

	if (!callCounts.empty()) {
		ImGui::Separator();
		ImGui::Text("Top Functions:");

		// Sort by call count
		std::vector<std::pair<uintptr_t, size_t>> sorted(callCounts.begin(), callCounts.end());
		std::sort(sorted.begin(), sorted.end(),
			[](const auto& a, const auto& b) { return a.second > b.second; });

		// Show top 5
		for (size_t i = 0; i < (std::min)(sorted.size(), size_t(5)); ++i) {
			ImGui::Text("  0x%016llX: %zu calls",
				static_cast<unsigned long long>(sorted[i].first),
				sorted[i].second);
		}
	}
}