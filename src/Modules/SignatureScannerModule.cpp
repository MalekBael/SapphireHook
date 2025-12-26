#include "SignatureScannerModule.h"
#include "../Logger/Logger.h"
#include "../Core/SignatureDatabase.h"
#include "../Core/SafeMemory.h"
#include "../vendor/imgui/imgui.h"
#include <format>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <thread>
#include <Windows.h>
#include <Psapi.h>

namespace SapphireHook {

// Static signature database for the module
static SignatureDatabase s_signatureDb;
static bool s_signatureDbLoaded = false;

void SignatureScannerModule::Initialize() {
    if (m_initialized) return;

    auto& scanner = AsyncPatternScanner::GetInstance();
    
    // Initialize with half the CPU cores (minimum 2)
    size_t threadCount = std::max(2u, std::thread::hardware_concurrency() / 2);
    scanner.Initialize(threadCount);

    // Try to load signature database
    if (!s_signatureDbLoaded) {
        if (s_signatureDb.Load("data/data-sig.json") || s_signatureDb.Load("data-sig.json")) {
            s_signatureDbLoaded = true;
            LogInfo("SignatureScannerModule: Loaded signature database");
        } else {
            LogWarning("SignatureScannerModule: Could not load signature database");
        }
    }

    LogInfo(std::format("SignatureScannerModule initialized with {} worker threads", threadCount));
    
    // Initialize default prologue patterns
    m_prologuePatterns = {
        {"push rbx; sub rsp", "40 53 48 83 EC", true},
        {"mov [rsp+8],rbx; mov [rsp+10h],rsi", "48 89 5C 24 08 48 89 74 24 10", true},
        {"mov [rsp+8],rbx; mov [rsp+10h],rbp", "48 89 5C 24 08 48 89 6C 24 10", true},
        {"mov [rsp+8],rbx; push rdi", "48 89 5C 24 08 57", true},
        {"push rbp; mov rbp,rsp", "55 48 8B EC", true},
        {"sub rsp,XX; mov [rsp+XX],rbx", "48 83 EC ?? 48 89 5C 24", true},
        {"mov [rsp+8],rcx", "48 89 4C 24 08", true},
        {"push rdi; push rsi; push rbx", "57 56 53", false},  // Less common
        {"mov r11,rsp", "4C 8B DC", false},
    };
    
    // Initialize static pointer patterns (RIP-relative addressing)
    m_staticPatterns = {
        {"MOV RAX, [rip+xx]", "48 8B 05", "MOV", true},
        {"MOV RCX, [rip+xx]", "48 8B 0D", "MOV", true},
        {"MOV RDX, [rip+xx]", "48 8B 15", "MOV", true},
        {"MOV RBX, [rip+xx]", "48 8B 1D", "MOV", true},
        {"MOV R8, [rip+xx]", "4C 8B 05", "MOV", true},
        {"MOV R9, [rip+xx]", "4C 8B 0D", "MOV", true},
        {"LEA RAX, [rip+xx]", "48 8D 05", "LEA", true},
        {"LEA RCX, [rip+xx]", "48 8D 0D", "LEA", true},
        {"LEA RDX, [rip+xx]", "48 8D 15", "LEA", true},
        {"LEA RBX, [rip+xx]", "48 8D 1D", "LEA", true},
        {"LEA R8, [rip+xx]", "4C 8D 05", "LEA", true},
        {"LEA R9, [rip+xx]", "4C 8D 0D", "LEA", true},
        {"CMP [rip+xx], 0", "48 83 3D", "CMP", true},
        {"MOV [rip+xx], RAX", "48 89 05", "STORE", false},
    };
    
    m_initialized = true;
}

void SignatureScannerModule::Shutdown() {
    if (!m_initialized) return;

    CancelAllScans();
    AsyncPatternScanner::GetInstance().Shutdown();

    LogInfo("SignatureScannerModule shutdown");
    m_initialized = false;
}

void SignatureScannerModule::RenderMenu() {
    if (ImGui::MenuItem(GetDisplayName(), nullptr, m_windowOpen)) {
        m_windowOpen = !m_windowOpen;
    }
}

void SignatureScannerModule::RenderWindow() {
    if (!m_windowOpen) return;

    ImGui::SetNextWindowSize(ImVec2(900, 600), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin(GetDisplayName(), &m_windowOpen)) {
        // Header with quick stats
        auto& scanner = AsyncPatternScanner::GetInstance();
        
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 1.0f, 1.0f), "Async Pattern Scanner");
        ImGui::SameLine(ImGui::GetWindowWidth() - 350);
        ImGui::Text("Pending: %zu | Cache: %zu hits / %zu misses",
            scanner.GetPendingJobCount(),
            scanner.GetCacheHitCount(),
            scanner.GetCacheMissCount());
        ImGui::Separator();

        // Tab bar
        if (ImGui::BeginTabBar("ScannerTabs")) {
            if (ImGui::BeginTabItem("Single Scan")) {
                RenderSingleScanTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Batch Scan")) {
                RenderBatchScanTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Results")) {
                RenderResultsTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Discovery")) {
                RenderDiscoveryTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("RTTI")) {
                RenderRTTITab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("VTables")) {
                RenderVTableTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Static Ptrs")) {
                RenderStaticPointerTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Statistics")) {
                RenderStatisticsTab();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }

        // Always show job queue at bottom
        ImGui::Separator();
        RenderJobQueue();
    }
    ImGui::End();

    // Cleanup old completed jobs periodically
    CleanupOldJobs();
}

void SignatureScannerModule::RenderSingleScanTab() {
    ImGui::TextColored(ImVec4(0.8f, 1.0f, 0.8f, 1.0f), "Single Pattern Scan");
    ImGui::Spacing();

    // Name input
    ImGui::SetNextItemWidth(200);
    ImGui::InputTextWithHint("##scanname", "Scan Name", m_nameInput, sizeof(m_nameInput));
    ImGui::SameLine();
    ImGui::TextDisabled("(?)");
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("A friendly name for this scan job");
    }

    // Pattern input
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - 100);
    ImGui::InputTextWithHint("##pattern", "Pattern (e.g., 48 89 5C 24 ? 48 89 74 24 ?)", 
        m_patternInput, sizeof(m_patternInput));

    // Options row
    ImGui::Checkbox("Find All Matches", &m_findAll);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100);
    ImGui::SliderInt("Priority", &m_priority, 0, 10);
    ImGui::SameLine();
    ImGui::TextDisabled("(?)");
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip("Higher priority jobs are processed first");
    }

    // Action buttons
    ImGui::Spacing();
    bool canScan = strlen(m_patternInput) > 0;
    
    if (!canScan) ImGui::BeginDisabled();
    if (ImGui::Button("Start Scan", ImVec2(120, 30))) {
        StartSingleScan();
    }
    if (!canScan) ImGui::EndDisabled();

    ImGui::SameLine();
    if (ImGui::Button("Clear", ImVec2(80, 30))) {
        m_patternInput[0] = '\0';
        m_nameInput[0] = '\0';
        std::strcpy(m_nameInput, "Custom Scan");
    }

    // Common patterns quick-select
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "Common Patterns:");
    
    struct QuickPattern {
        const char* name;
        const char* pattern;
    };
    static const QuickPattern quickPatterns[] = {
        {"Function Prologue (push rbx)", "40 53 48 83 EC"},
        {"Function Prologue (mov [rsp])", "48 89 5C 24 ? 48 89 74 24 ?"},
        {"LEA RIP-relative", "48 8D 0D ?? ?? ?? ??"},
        {"MOV from static", "48 8B 05 ?? ?? ?? ??"},
        {"Call indirect", "FF 15 ?? ?? ?? ??"},
        {"VTable access", "48 8B 01 FF 50"},
    };

    ImGui::Columns(3, nullptr, false);
    for (const auto& qp : quickPatterns) {
        if (ImGui::Selectable(qp.name, false)) {
            std::strcpy(m_patternInput, qp.pattern);
            std::strcpy(m_nameInput, qp.name);
        }
        ImGui::NextColumn();
    }
    ImGui::Columns(1);
}

void SignatureScannerModule::RenderBatchScanTab() {
    ImGui::TextColored(ImVec4(1.0f, 0.9f, 0.6f, 1.0f), "Batch Pattern Scan");
    ImGui::Spacing();

    // Add pattern to batch
    ImGui::Text("Add Pattern:");
    ImGui::SetNextItemWidth(150);
    ImGui::InputTextWithHint("##batchname", "Name", m_batchNameInput, sizeof(m_batchNameInput));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - 80);
    ImGui::InputTextWithHint("##batchpattern", "Pattern", m_batchPatternInput, sizeof(m_batchPatternInput));
    ImGui::SameLine();
    
    bool canAdd = strlen(m_batchNameInput) > 0 && strlen(m_batchPatternInput) > 0;
    if (!canAdd) ImGui::BeginDisabled();
    if (ImGui::Button("Add")) {
        m_batchPatterns.push_back({m_batchNameInput, m_batchPatternInput, true});
        m_batchNameInput[0] = '\0';
        m_batchPatternInput[0] = '\0';
    }
    if (!canAdd) ImGui::EndDisabled();

    // Batch controls
    ImGui::Spacing();
    if (ImGui::Button("Import from Signature Database")) {
        ImportPatternsFromDatabase();
    }
    ImGui::SameLine();
    if (ImGui::Button("Select All")) {
        for (auto& bp : m_batchPatterns) bp.selected = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Deselect All")) {
        for (auto& bp : m_batchPatterns) bp.selected = false;
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear List")) {
        m_batchPatterns.clear();
    }

    // Batch list
    ImGui::Spacing();
    ImGui::Separator();
    
    if (ImGui::BeginTable("BatchPatterns", 4, 
        ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
        ImVec2(0, 200))) {
        
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 200.0f);
        ImGui::TableSetupColumn("Pattern", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableHeadersRow();

        int toRemove = -1;
        for (size_t i = 0; i < m_batchPatterns.size(); ++i) {
            auto& bp = m_batchPatterns[i];
            ImGui::TableNextRow();
            
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));
            ImGui::Checkbox("##sel", &bp.selected);
            
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(bp.name.c_str());
            
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", bp.pattern.c_str());
            
            ImGui::TableNextColumn();
            if (ImGui::SmallButton("Remove")) {
                toRemove = static_cast<int>(i);
            }
            ImGui::PopID();
        }

        if (toRemove >= 0) {
            m_batchPatterns.erase(m_batchPatterns.begin() + toRemove);
        }

        ImGui::EndTable();
    }

    // Batch execution
    ImGui::Spacing();
    size_t selectedCount = std::count_if(m_batchPatterns.begin(), m_batchPatterns.end(),
        [](const BatchEntry& e) { return e.selected; });

    ImGui::Text("Selected: %zu / %zu patterns", selectedCount, m_batchPatterns.size());

    if (m_batchInProgress) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), 
            "Scanning... %d / %d", m_batchCompleted.load(), m_batchTotal.load());
        
        float progress = m_batchTotal > 0 ? 
            static_cast<float>(m_batchCompleted) / static_cast<float>(m_batchTotal) : 0.0f;
        ImGui::ProgressBar(progress, ImVec2(-1, 0));
    }

    bool canStartBatch = selectedCount > 0 && !m_batchInProgress;
    if (!canStartBatch) ImGui::BeginDisabled();
    if (ImGui::Button("Start Batch Scan", ImVec2(150, 30))) {
        StartBatchScan();
    }
    if (!canStartBatch) ImGui::EndDisabled();

    ImGui::SameLine();
    if (m_batchInProgress) {
        if (ImGui::Button("Cancel Batch", ImVec2(120, 30))) {
            CancelAllScans();
        }
    }
}

void SignatureScannerModule::RenderResultsTab() {
    ImGui::TextColored(ImVec4(0.6f, 1.0f, 0.6f, 1.0f), "Scan Results");
    ImGui::Spacing();

    // Filter and controls
    ImGui::SetNextItemWidth(200);
    ImGui::InputTextWithHint("##filter", "Filter results...", m_resultFilter, sizeof(m_resultFilter));
    ImGui::SameLine();
    if (ImGui::Button("Clear Results")) {
        ClearResults();
    }
    ImGui::SameLine();
    if (ImGui::Button("Export")) {
        ExportResults();
    }
    ImGui::SameLine();
    ImGui::Checkbox("Auto-scroll", &m_autoScroll);

    ImGui::Spacing();
    ImGui::Separator();

    // Results table
    if (ImGui::BeginTable("ResultsTable", 5,
        ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable | 
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Sortable,
        ImVec2(0, 0))) {

        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Pattern", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        std::string filterLower = m_resultFilter;
        std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::tolower);

        std::lock_guard<std::mutex> lock(m_jobsMutex);
        for (const auto& result : m_completedResults) {
            // Apply filter
            if (!filterLower.empty()) {
                std::string nameLower = result.name;
                std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
                if (nameLower.find(filterLower) == std::string::npos) continue;
            }

            ImGui::TableNextRow();

            // Status column
            ImGui::TableNextColumn();
            ImVec4 statusColor = GetStatusColor(result.status);
            ImGui::TextColored(statusColor, "%s", GetStatusText(result.status));

            // Name column
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(result.name.c_str());

            // Address column
            ImGui::TableNextColumn();
            if (result.WasSuccessful() && result.result) {
                ImGui::Text("0x%llX", static_cast<unsigned long long>(result.result->address));
                if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) {
                    // Right-click copy
                    std::string addrStr = std::format("0x{:X}", result.result->address);
                    ImGui::SetClipboardText(addrStr.c_str());
                }
            } else if (!result.allResults.empty()) {
                ImGui::Text("%zu matches", result.allResults.size());
            } else {
                ImGui::TextDisabled("Not found");
            }

            // Time column
            ImGui::TableNextColumn();
            ImGui::Text("%s", FormatDuration(result.GetDurationMs()).c_str());

            // Pattern column (truncated)
            ImGui::TableNextColumn();
            std::string patternDisplay = result.pattern;
            if (patternDisplay.length() > 40) {
                patternDisplay = patternDisplay.substr(0, 37) + "...";
            }
            ImGui::TextDisabled("%s", patternDisplay.c_str());
            if (ImGui::IsItemHovered() && result.pattern.length() > 40) {
                ImGui::SetTooltip("%s", result.pattern.c_str());
            }
        }

        if (m_autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
            ImGui::SetScrollHereY(1.0f);
        }

        ImGui::EndTable();
    }
}

void SignatureScannerModule::RenderStatisticsTab() {
    ImGui::TextColored(ImVec4(0.8f, 0.8f, 1.0f, 1.0f), "Scanner Statistics");
    ImGui::Spacing();

    auto& scanner = AsyncPatternScanner::GetInstance();

    // Cache statistics
    ImGui::Text("Cache Performance:");
    ImGui::Indent();
    size_t hits = scanner.GetCacheHitCount();
    size_t misses = scanner.GetCacheMissCount();
    size_t total = hits + misses;
    float hitRate = total > 0 ? (100.0f * hits / total) : 0.0f;
    
    ImGui::Text("Hits: %zu", hits);
    ImGui::Text("Misses: %zu", misses);
    ImGui::Text("Hit Rate: %.1f%%", hitRate);
    
    // Hit rate bar
    ImGui::ProgressBar(hitRate / 100.0f, ImVec2(200, 0), std::format("{:.1f}%", hitRate).c_str());
    ImGui::Unindent();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Session statistics
    ImGui::Text("Session Statistics:");
    ImGui::Indent();
    ImGui::Text("Total Scans: %llu", m_totalScans.load());
    ImGui::Text("Successful: %llu", m_successfulScans.load());
    ImGui::Text("Success Rate: %.1f%%", 
        m_totalScans > 0 ? (100.0 * m_successfulScans / m_totalScans) : 0.0);
    ImGui::Text("Total Scan Time: %s", FormatDuration(m_totalScanTimeMs).c_str());
    ImGui::Text("Avg Scan Time: %s", 
        FormatDuration(m_totalScans > 0 ? m_totalScanTimeMs / m_totalScans : 0.0).c_str());
    ImGui::Unindent();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Queue status
    ImGui::Text("Queue Status:");
    ImGui::Indent();
    ImGui::Text("Pending Jobs: %zu", scanner.GetPendingJobCount());
    ImGui::Text("Active Jobs: %zu", m_activeJobs.size());
    ImGui::Unindent();

    ImGui::Spacing();
    if (ImGui::Button("Clear Cache")) {
        scanner.ClearCache();
    }
    ImGui::SameLine();
    if (ImGui::Button("Reset Statistics")) {
        m_totalScans = 0;
        m_successfulScans = 0;
        m_totalScanTimeMs = 0.0;
    }
}

void SignatureScannerModule::RenderJobQueue() {
    ImGui::Text("Active Jobs:");
    
    std::lock_guard<std::mutex> lock(m_jobsMutex);
    
    if (m_activeJobs.empty()) {
        ImGui::TextDisabled("No active jobs");
        return;
    }

    // Show last few active jobs
    size_t showCount = std::min(m_activeJobs.size(), size_t(5));
    for (size_t i = 0; i < showCount; ++i) {
        const auto& job = m_activeJobs[i];
        
        ImGui::PushID(static_cast<int>(job.jobId));
        
        // Status indicator
        ImVec4 color = GetStatusColor(job.status);
        ImGui::TextColored(color, "[%s]", GetStatusText(job.status));
        ImGui::SameLine();
        
        // Job name
        ImGui::Text("%s", job.name.c_str());
        ImGui::SameLine();
        
        // Progress bar for running jobs
        if (job.status == AsyncScanStatus::Running) {
            ImGui::ProgressBar(job.progress, ImVec2(100, 0));
            ImGui::SameLine();
        }

        // Cancel button
        if (job.status == AsyncScanStatus::Pending || job.status == AsyncScanStatus::Running) {
            if (ImGui::SmallButton("Cancel")) {
                AsyncPatternScanner::GetInstance().CancelJob(job.jobId);
            }
        }

        ImGui::PopID();
    }

    if (m_activeJobs.size() > showCount) {
        ImGui::TextDisabled("... and %zu more", m_activeJobs.size() - showCount);
    }
}

void SignatureScannerModule::StartSingleScan() {
    if (strlen(m_patternInput) == 0) return;

    auto& scanner = AsyncPatternScanner::GetInstance();

    // Completion callback
    auto completeCb = [this](const AsyncScanResult& result) {
        OnScanComplete(result.jobId, result);
    };

    // Use QueueScan with full config for priority and options
    AsyncScanConfig config;
    config.name = m_nameInput;
    config.pattern = m_patternInput;
    config.priority = m_priority;
    config.findAll = m_findAll;
    config.useCache = true;
    config.onComplete = completeCb;

    uint32_t jobId = scanner.QueueScan(config);

    // Track the job
    {
        std::lock_guard<std::mutex> lock(m_jobsMutex);
        JobDisplay job;
        job.jobId = jobId;
        job.name = m_nameInput;
        job.pattern = m_patternInput;
        job.status = AsyncScanStatus::Pending;
        job.progress = 0.0f;
        job.startTime = std::chrono::steady_clock::now();
        m_activeJobs.push_front(job);

        // Limit active job tracking
        while (m_activeJobs.size() > kMaxActiveJobs) {
            m_activeJobs.pop_back();
        }
    }

    LogInfo(std::format("Started scan job {}: '{}'", jobId, m_nameInput));
}

void SignatureScannerModule::StartBatchScan() {
    if (m_batchInProgress) return;

    std::vector<std::pair<std::string, std::string>> patterns;
    for (const auto& bp : m_batchPatterns) {
        if (bp.selected) {
            patterns.emplace_back(bp.name, bp.pattern);
        }
    }

    if (patterns.empty()) return;

    m_batchInProgress = true;
    m_batchCompleted = 0;
    m_batchTotal = static_cast<int>(patterns.size());

    auto& scanner = AsyncPatternScanner::GetInstance();

    // Queue batch with completion callback
    auto jobIds = scanner.QueueBatchScan(patterns, 
        [this](const std::vector<AsyncScanResult>& results) {
            m_batchInProgress = false;
            for (const auto& result : results) {
                OnScanComplete(result.jobId, result);
            }
            LogInfo(std::format("Batch scan complete: {} patterns processed", results.size()));
        });

    // Track all jobs
    {
        std::lock_guard<std::mutex> lock(m_jobsMutex);
        size_t idx = 0;
        for (uint32_t jobId : jobIds) {
            if (idx < patterns.size()) {
                JobDisplay job;
                job.jobId = jobId;
                job.name = patterns[idx].first;
                job.pattern = patterns[idx].second;
                job.status = AsyncScanStatus::Pending;
                job.startTime = std::chrono::steady_clock::now();
                m_activeJobs.push_front(job);
                ++idx;
            }
        }
    }

    LogInfo(std::format("Started batch scan with {} patterns", patterns.size()));
}

void SignatureScannerModule::CancelAllScans() {
    AsyncPatternScanner::GetInstance().CancelAllJobs();
    m_batchInProgress = false;
    
    std::lock_guard<std::mutex> lock(m_jobsMutex);
    for (auto& job : m_activeJobs) {
        if (job.status == AsyncScanStatus::Pending || job.status == AsyncScanStatus::Running) {
            job.status = AsyncScanStatus::Cancelled;
        }
    }
    
    LogInfo("Cancelled all pending scans");
}

void SignatureScannerModule::ClearResults() {
    std::lock_guard<std::mutex> lock(m_jobsMutex);
    m_completedResults.clear();
}

void SignatureScannerModule::ExportResults() {
    std::lock_guard<std::mutex> lock(m_jobsMutex);
    
    std::string content = "# Signature Scan Results\n";
    content += std::format("# Exported: {}\n", "N/A"); // Would add timestamp
    content += "# Format: Status | Name | Address | Time (ms) | Pattern\n\n";

    for (const auto& result : m_completedResults) {
        std::string addrStr = result.WasSuccessful() && result.result 
            ? std::format("0x{:X}", result.result->address) 
            : "NOT_FOUND";
        
        content += std::format("{} | {} | {} | {:.2f} | {}\n",
            GetStatusText(result.status),
            result.name,
            addrStr,
            result.GetDurationMs(),
            result.pattern);
    }

    // Write to temp directory
    auto tempDir = Logger::GetDefaultTempDir();
    auto tempPath = (tempDir / "scan_results.txt").string();
    std::ofstream ofs(tempPath);
    if (ofs) {
        ofs << content;
        ofs.close();
        LogInfo(std::format("Exported {} results to {}", m_completedResults.size(), tempPath));
    } else {
        LogError("Failed to export results");
    }
}

void SignatureScannerModule::ImportPatternsFromDatabase() {
    if (!s_signatureDbLoaded) {
        // Try to load again
        if (s_signatureDb.Load("data/data-sig.json") || s_signatureDb.Load("data-sig.json")) {
            s_signatureDbLoaded = true;
        } else {
            LogError("Could not load signature database for import");
            return;
        }
    }

    // Get all signature entries from the database
    auto allSigs = s_signatureDb.GetAllEntries();
    
    for (const auto& [name, entry] : allSigs) {
        // Check if already in batch list
        bool exists = std::any_of(m_batchPatterns.begin(), m_batchPatterns.end(),
            [&name](const BatchEntry& e) { return e.name == name; });
        
        if (!exists && !entry.signature.empty()) {
            m_batchPatterns.push_back({name, entry.signature, true});
        }
    }

    LogInfo(std::format("Imported {} patterns from signature database", m_batchPatterns.size()));
}

void SignatureScannerModule::OnScanProgress(uint32_t jobId, float progress) {
    std::lock_guard<std::mutex> lock(m_jobsMutex);
    
    for (auto& job : m_activeJobs) {
        if (job.jobId == jobId) {
            job.progress = progress;
            job.status = AsyncScanStatus::Running;
            break;
        }
    }
}

void SignatureScannerModule::OnScanComplete(uint32_t jobId, const AsyncScanResult& result) {
    // Update statistics
    m_totalScans++;
    m_totalScanTimeMs = m_totalScanTimeMs + result.GetDurationMs();
    if (result.WasSuccessful()) {
        m_successfulScans++;
    }

    // Update job status and add to completed
    {
        std::lock_guard<std::mutex> lock(m_jobsMutex);
        
        // Update active job
        for (auto& job : m_activeJobs) {
            if (job.jobId == jobId) {
                job.status = result.status;
                job.progress = 1.0f;
                job.result = result;
                break;
            }
        }

        // Add to completed results
        AddCompletedResult(result);
    }
}

void SignatureScannerModule::AddCompletedResult(const AsyncScanResult& result) {
    m_completedResults.push_front(result);
    while (m_completedResults.size() > kMaxCompletedResults) {
        m_completedResults.pop_back();
    }
}

void SignatureScannerModule::CleanupOldJobs() {
    std::lock_guard<std::mutex> lock(m_jobsMutex);
    
    // Remove completed jobs older than 30 seconds
    auto now = std::chrono::steady_clock::now();
    m_activeJobs.erase(
        std::remove_if(m_activeJobs.begin(), m_activeJobs.end(),
            [&now](const JobDisplay& job) {
                if (job.status != AsyncScanStatus::Completed && 
                    job.status != AsyncScanStatus::Failed &&
                    job.status != AsyncScanStatus::Cancelled) {
                    return false;
                }
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - job.startTime);
                return elapsed.count() > 30;
            }),
        m_activeJobs.end());
}

std::string SignatureScannerModule::FormatDuration(double ms) const {
    if (ms < 1.0) {
        return std::format("{:.2f}us", ms * 1000.0);
    } else if (ms < 1000.0) {
        return std::format("{:.2f}ms", ms);
    } else {
        return std::format("{:.2f}s", ms / 1000.0);
    }
}

std::string SignatureScannerModule::FormatAddress(uintptr_t addr) const {
    return std::format("0x{:X}", addr);
}

ImVec4 SignatureScannerModule::GetStatusColor(AsyncScanStatus status) const {
    switch (status) {
        case AsyncScanStatus::Pending:   return ImVec4(0.7f, 0.7f, 0.7f, 1.0f);  // Gray
        case AsyncScanStatus::Running:   return ImVec4(1.0f, 1.0f, 0.0f, 1.0f);  // Yellow
        case AsyncScanStatus::Completed: return ImVec4(0.0f, 1.0f, 0.0f, 1.0f);  // Green
        case AsyncScanStatus::Failed:    return ImVec4(1.0f, 0.3f, 0.3f, 1.0f);  // Red
        case AsyncScanStatus::Cancelled: return ImVec4(1.0f, 0.5f, 0.0f, 1.0f);  // Orange
        default:                         return ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
    }
}

const char* SignatureScannerModule::GetStatusText(AsyncScanStatus status) const {
    switch (status) {
        case AsyncScanStatus::Pending:   return "Pending";
        case AsyncScanStatus::Running:   return "Running";
        case AsyncScanStatus::Completed: return "Found";
        case AsyncScanStatus::Failed:    return "Failed";
        case AsyncScanStatus::Cancelled: return "Cancelled";
        default:                         return "Unknown";
    }
}

// ============================================================================
// Signature Discovery Implementation
// ============================================================================

void SignatureScannerModule::RenderDiscoveryTab() {
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.4f, 1.0f), "Signature Discovery");
    ImGui::TextDisabled("Scan for function prologues and generate IDA-compatible signatures");
    ImGui::Spacing();

    // Settings section
    if (ImGui::CollapsingHeader("Discovery Settings", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::SetNextItemWidth(100);
        ImGui::SliderInt("Signature Length", &m_sigLength, 8, 64, "%d bytes");
        ImGui::SameLine();
        ImGui::TextDisabled("(?)");
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Number of bytes to extract for each signature.\nLonger = more specific but may break between versions.");
        }

        ImGui::SetNextItemWidth(100);
        ImGui::SliderInt("Max Functions", &m_maxFunctions, 100, 5000);
        ImGui::SameLine();
        ImGui::TextDisabled("(?)");
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Maximum number of functions to discover per pattern.");
        }

        ImGui::Checkbox("Auto-Wildcard Offsets", &m_autoWildcard);
        ImGui::SameLine();
        ImGui::TextDisabled("(?)");
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("Automatically replace RIP-relative offsets with wildcards (?).\nMakes signatures more portable between versions.");
        }

        ImGui::SameLine(300);
        ImGui::Checkbox("Only Show Unique", &m_onlyUnique);
    }

    // Prologue patterns section
    if (ImGui::CollapsingHeader("Prologue Patterns", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextDisabled("Select which function prologues to scan for:");
        
        ImGui::Columns(2, nullptr, false);
        for (auto& pp : m_prologuePatterns) {
            ImGui::Checkbox(pp.name, &pp.enabled);
            ImGui::NextColumn();
        }
        ImGui::Columns(1);

        if (ImGui::Button("Enable All")) {
            for (auto& pp : m_prologuePatterns) pp.enabled = true;
        }
        ImGui::SameLine();
        if (ImGui::Button("Disable All")) {
            for (auto& pp : m_prologuePatterns) pp.enabled = false;
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Action buttons
    bool anyEnabled = std::any_of(m_prologuePatterns.begin(), m_prologuePatterns.end(),
        [](const ProloguePattern& p) { return p.enabled; });

    if (m_discoveryInProgress) {
        float progress = m_discoveryTotal > 0 
            ? static_cast<float>(m_discoveryProgress) / static_cast<float>(m_discoveryTotal) 
            : 0.0f;
        ImGui::ProgressBar(progress, ImVec2(200, 0));
        ImGui::SameLine();
        ImGui::Text("Discovering... %d / %d", m_discoveryProgress.load(), m_discoveryTotal.load());
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            CancelDiscovery();
        }
    } else {
        if (!anyEnabled) ImGui::BeginDisabled();
        if (ImGui::Button("Start Discovery", ImVec2(150, 30))) {
            StartDiscovery();
        }
        if (!anyEnabled) ImGui::EndDisabled();
    }

    ImGui::SameLine();
    
    bool hasDiscoveredSigs = false;
    {
        std::lock_guard<std::mutex> lock(m_discoveryMutex);
        hasDiscoveredSigs = !m_discoveredSigs.empty();
    }
    
    if (!hasDiscoveredSigs) ImGui::BeginDisabled();
    
    if (m_validationInProgress) {
        float valProgress = m_validationTotal > 0
            ? static_cast<float>(m_validationProgress) / static_cast<float>(m_validationTotal)
            : 0.0f;
        ImGui::ProgressBar(valProgress, ImVec2(120, 0));
        ImGui::SameLine();
        ImGui::Text("Validating %d/%d", m_validationProgress.load(), m_validationTotal.load());
    } else {
        if (ImGui::Button("Validate Uniqueness")) {
            ValidateSignatureUniqueness();
        }
    }
    
    ImGui::SameLine();
    if (ImGui::Button("Export IDA Sigs")) {
        ExportDiscoveredSigs();
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        ClearDiscoveredSigs();
    }
    if (!hasDiscoveredSigs) ImGui::EndDisabled();

    // Filter
    ImGui::Spacing();
    ImGui::SetNextItemWidth(200);
    ImGui::InputTextWithHint("##discfilter", "Filter by name or address...", m_discoveryFilter, sizeof(m_discoveryFilter));
    ImGui::SameLine();
    ImGui::Text("Discovered: %zu signatures", m_discoveredSigs.size());

    // Results table
    ImGui::Spacing();
    
    if (ImGui::BeginTable("DiscoveredSigs", 5,
        ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Sortable,
        ImVec2(0, 0))) {

        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 180.0f);
        ImGui::TableSetupColumn("Signature", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Unique", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableHeadersRow();

        std::string filterLower = m_discoveryFilter;
        std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::tolower);

        // Copy the signatures to avoid holding the lock during rendering
        std::vector<DiscoveredSignature> sigsCopy;
        {
            std::lock_guard<std::mutex> lock(m_discoveryMutex);
            sigsCopy = m_discoveredSigs;
        }
        
        for (size_t sigIdx = 0; sigIdx < sigsCopy.size(); ++sigIdx) {
            auto& sig = sigsCopy[sigIdx];
            // Apply filters
            if (m_onlyUnique && !sig.isUnique) continue;
            
            if (!filterLower.empty()) {
                std::string nameLower = sig.suggestedName;
                std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
                std::string addrStr = std::format("{:X}", sig.address);
                std::transform(addrStr.begin(), addrStr.end(), addrStr.begin(), ::tolower);
                if (nameLower.find(filterLower) == std::string::npos && 
                    addrStr.find(filterLower) == std::string::npos) {
                    continue;
                }
            }

            ImGui::TableNextRow();

            // Checkbox
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(sig.address));
            bool selected = sig.selected;
            if (ImGui::Checkbox("##sel", &selected)) {
                // Write back to original
                std::lock_guard<std::mutex> lock(m_discoveryMutex);
                if (sigIdx < m_discoveredSigs.size()) {
                    m_discoveredSigs[sigIdx].selected = selected;
                }
            }
            ImGui::PopID();

            // Address
            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", static_cast<unsigned long long>(sig.address));
            if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) {
                ImGui::SetClipboardText(std::format("0x{:X}", sig.address).c_str());
            }

            // Name
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(sig.suggestedName.c_str());

            // Signature
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", sig.signature.c_str());
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Raw: %s\n\nClick to copy signature", sig.rawBytes.c_str());
            }
            if (ImGui::IsItemClicked()) {
                ImGui::SetClipboardText(sig.signature.c_str());
            }

            // Unique indicator
            ImGui::TableNextColumn();
            if (sig.isUnique) {
                ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Yes");
            } else {
                ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "No");
            }
        }

        ImGui::EndTable();
    }
}

void SignatureScannerModule::StartDiscovery() {
    if (m_discoveryInProgress) return;

    // Get module info
    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) {
        LogError("Failed to get module handle for discovery");
        return;
    }

    MODULEINFO modInfo{};
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        LogError("Failed to get module information for discovery");
        return;
    }

    uintptr_t moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
    size_t moduleSize = modInfo.SizeOfImage;

    // Count enabled patterns
    std::vector<std::pair<std::string, std::string>> enabledPatterns;
    for (const auto& pp : m_prologuePatterns) {
        if (pp.enabled) {
            enabledPatterns.emplace_back(pp.name, pp.pattern);
        }
    }

    if (enabledPatterns.empty()) return;

    m_discoveryInProgress = true;
    m_discoveryProgress = 0;
    m_discoveryTotal = static_cast<int>(enabledPatterns.size());

    // Clear previous results
    {
        std::lock_guard<std::mutex> lock(m_discoveryMutex);
        m_discoveredSigs.clear();
    }

    // Run discovery in background thread
    std::thread([this, moduleBase, moduleSize, enabledPatterns, sigLen = m_sigLength, maxFuncs = m_maxFunctions, autoWild = m_autoWildcard]() {
        LogInfo("Starting signature discovery...");
        
        size_t totalFound = 0;
        int patternIdx = 0;

        for (const auto& [name, pattern] : enabledPatterns) {
            if (!m_discoveryInProgress) break;  // Cancelled

            // Scan for all matches of this pattern
            auto results = PatternScanner::ScanAllPatterns(moduleBase, moduleSize, pattern);
            
            int funcCount = 0;
            for (const auto& result : results) {
                if (!m_discoveryInProgress) break;
                if (funcCount >= maxFuncs) break;

                uintptr_t addr = result.address;

                // Generate signature
                std::string sig = GenerateSignature(addr, sigLen, autoWild);
                if (sig.empty()) continue;

                // Generate raw bytes
                std::string raw;
                if (IsValidMemoryAddress(addr, sigLen)) {
                    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(addr);
                    for (size_t i = 0; i < static_cast<size_t>(sigLen); ++i) {
                        if (i > 0) raw += " ";
                        raw += std::format("{:02X}", bytes[i]);
                    }
                }

                // Create discovered signature entry
                DiscoveredSignature ds;
                ds.address = addr;
                ds.signature = sig;
                ds.rawBytes = raw;
                ds.suggestedName = std::format("sub_{:X}", addr);
                ds.byteCount = sigLen;
                ds.isUnique = false;  // Will be validated later
                ds.selected = false;

                {
                    std::lock_guard<std::mutex> lock(m_discoveryMutex);
                    m_discoveredSigs.push_back(ds);
                }

                ++funcCount;
                ++totalFound;
            }

            m_discoveryProgress = ++patternIdx;
        }

        m_discoveryInProgress = false;
        LogInfo(std::format("Discovery complete: found {} signatures", totalFound));
    }).detach();
}

void SignatureScannerModule::CancelDiscovery() {
    m_discoveryInProgress = false;
}

void SignatureScannerModule::ClearDiscoveredSigs() {
    std::lock_guard<std::mutex> lock(m_discoveryMutex);
    m_discoveredSigs.clear();
}

std::string SignatureScannerModule::GenerateSignature(uintptr_t address, size_t length, bool autoWildcard) {
    if (!IsValidMemoryAddress(address, length)) {
        return "";
    }

    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(address);
    std::string result;

    for (size_t i = 0; i < length; ++i) {
        if (i > 0) result += " ";

        bool shouldWildcard = false;

        if (autoWildcard && i >= 1 && i + 3 < length) {
            // Check for RIP-relative addressing patterns
            // Common patterns: 48 8B 05 XX XX XX XX (mov rax, [rip+offset])
            //                  48 8D 0D XX XX XX XX (lea rcx, [rip+offset])
            //                  E8 XX XX XX XX (call rel32)
            //                  E9 XX XX XX XX (jmp rel32)
            
            uint8_t prev = bytes[i - 1];
            
            // Check for call/jmp rel32
            if (i >= 1 && (bytes[i-1] == 0xE8 || bytes[i-1] == 0xE9) && i < 5) {
                // We're in the offset bytes of a call/jmp
                if (i >= 1 && i <= 4) {
                    size_t offsetInCall = i;  // 1-4 means offset bytes
                    if (offsetInCall <= 4) shouldWildcard = true;
                }
            }
            
            // Check for MOD R/M with RIP-relative (mod=00, r/m=101)
            // After checking if previous bytes indicate RIP-relative
            if (i >= 2) {
                uint8_t modRM = bytes[i - 1];
                if ((modRM & 0xC7) == 0x05) {
                    // RIP-relative addressing - wildcard next 4 bytes
                    shouldWildcard = true;
                }
            }
            
            // Simple heuristic: wildcard bytes that look like they could be offsets
            // (within the 4-byte window after common prefixes)
        }

        if (shouldWildcard) {
            result += "??";
        } else {
            result += std::format("{:02X}", bytes[i]);
        }
    }

    return result;
}

void SignatureScannerModule::ValidateSignatureUniqueness() {
    if (m_validationInProgress) return;

    size_t sigCount = 0;
    {
        std::lock_guard<std::mutex> lock(m_discoveryMutex);
        sigCount = m_discoveredSigs.size();
    }

    if (sigCount == 0) return;

    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) return;

    MODULEINFO modInfo{};
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) return;

    uintptr_t moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
    size_t moduleSize = modInfo.SizeOfImage;

    m_validationInProgress = true;
    m_validationProgress = 0;
    m_validationTotal = static_cast<int>(sigCount);

    // Run validation in background thread to avoid freezing
    std::thread([this, moduleBase, moduleSize]() {
        LogInfo("Validating signature uniqueness (async)...");
        
        int validated = 0;
        size_t totalSigs = 0;
        
        {
            std::lock_guard<std::mutex> lock(m_discoveryMutex);
            totalSigs = m_discoveredSigs.size();
        }

        for (size_t i = 0; i < totalSigs && m_validationInProgress; ++i) {
            std::string pattern;
            {
                std::lock_guard<std::mutex> lock(m_discoveryMutex);
                if (i < m_discoveredSigs.size()) {
                    pattern = m_discoveredSigs[i].signature;
                }
            }

            if (!pattern.empty()) {
                // Scan for this pattern
                auto results = PatternScanner::ScanAllPatterns(moduleBase, moduleSize, pattern);
                bool isUnique = (results.size() == 1);

                {
                    std::lock_guard<std::mutex> lock(m_discoveryMutex);
                    if (i < m_discoveredSigs.size()) {
                        m_discoveredSigs[i].isUnique = isUnique;
                    }
                }
            }

            m_validationProgress = ++validated;
        }

        size_t uniqueCount = 0;
        {
            std::lock_guard<std::mutex> lock(m_discoveryMutex);
            uniqueCount = std::count_if(m_discoveredSigs.begin(), m_discoveredSigs.end(),
                [](const DiscoveredSignature& s) { return s.isUnique; });
        }

        m_validationInProgress = false;
        LogInfo(std::format("Validation complete: {} / {} signatures are unique", uniqueCount, totalSigs));
    }).detach();
}

void SignatureScannerModule::ExportDiscoveredSigs() {
    std::lock_guard<std::mutex> lock(m_discoveryMutex);

    if (m_discoveredSigs.empty()) return;

    // Build IDA-style signature file
    std::string content;
    content += "; SapphireHook Signature Export\n";
    content += "; Format: name pattern\n";
    content += "; Use in IDA with sigmaker or similar plugins\n\n";

    // Count selected, or export all if none selected
    size_t selectedCount = std::count_if(m_discoveredSigs.begin(), m_discoveredSigs.end(),
        [](const DiscoveredSignature& s) { return s.selected; });
    bool exportAll = (selectedCount == 0);

    for (const auto& sig : m_discoveredSigs) {
        if (!exportAll && !sig.selected) continue;
        if (m_onlyUnique && !sig.isUnique) continue;

        content += std::format("{} {}\n", sig.suggestedName, sig.signature);
    }

    content += "\n; JSON format for programmatic use:\n";
    content += "/*\n[\n";

    bool first = true;
    for (const auto& sig : m_discoveredSigs) {
        if (!exportAll && !sig.selected) continue;
        if (m_onlyUnique && !sig.isUnique) continue;

        if (!first) content += ",\n";
        first = false;

        content += std::format("  {{\"name\": \"{}\", \"pattern\": \"{}\", \"address\": \"0x{:X}\", \"unique\": {}}}",
            sig.suggestedName,
            sig.signature,
            sig.address,
            sig.isUnique ? "true" : "false");
    }

    content += "\n]\n*/\n";

    // Write to file
    auto tempDir = Logger::GetDefaultTempDir();
    auto tempPath = (tempDir / "discovered_signatures.txt").string();
    std::ofstream ofs(tempPath);
    if (ofs) {
        ofs << content;
        ofs.close();
        LogInfo(std::format("Exported signatures to {}", tempPath));
    } else {
        LogError("Failed to export signatures");
    }
}

// ============================================================================
// RTTI Scanner Implementation
// ============================================================================

void SignatureScannerModule::RenderRTTITab() {
    ImGui::TextColored(ImVec4(0.8f, 0.6f, 1.0f, 1.0f), "RTTI Class Scanner");
    ImGui::TextDisabled("Scan for C++ Run-Time Type Information to discover class names");
    ImGui::Spacing();

    // Action buttons
    if (m_rttiScanInProgress) {
        float progress = m_rttiScanTotal > 0
            ? static_cast<float>(m_rttiScanProgress) / static_cast<float>(m_rttiScanTotal)
            : 0.0f;
        ImGui::ProgressBar(progress, ImVec2(200, 0));
        ImGui::SameLine();
        ImGui::Text("Scanning... %d / %d", m_rttiScanProgress.load(), m_rttiScanTotal.load());
        ImGui::SameLine();
        if (ImGui::Button("Cancel##rtti")) {
            CancelRTTIScan();
        }
    } else {
        if (ImGui::Button("Start RTTI Scan", ImVec2(150, 30))) {
            StartRTTIScan();
        }
    }

    ImGui::SameLine();
    
    bool hasResults = false;
    {
        std::lock_guard<std::mutex> lock(m_rttiMutex);
        hasResults = !m_rttiClasses.empty();
    }
    
    if (!hasResults) ImGui::BeginDisabled();
    if (ImGui::Button("Export##rtti")) {
        ExportRTTIResults();
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear##rtti")) {
        ClearRTTIResults();
    }
    if (!hasResults) ImGui::EndDisabled();

    ImGui::SameLine(300);
    ImGui::Checkbox("Only with VTable", &m_rttiShowOnlyWithVtable);

    // Filter
    ImGui::Spacing();
    ImGui::SetNextItemWidth(300);
    ImGui::InputTextWithHint("##rttifilter", "Filter by class name...", m_rttiFilter, sizeof(m_rttiFilter));
    
    size_t rttiCount = 0;
    {
        std::lock_guard<std::mutex> lock(m_rttiMutex);
        rttiCount = m_rttiClasses.size();
    }
    ImGui::SameLine();
    ImGui::Text("Found: %zu classes", rttiCount);

    ImGui::Spacing();
    ImGui::Separator();

    // Results table
    if (ImGui::BeginTable("RTTITable", 5,
        ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Sortable,
        ImVec2(0, 0))) {

        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableSetupColumn("Type Descriptor", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("VTable", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Class Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Hierarchy", ImGuiTableColumnFlags_WidthFixed, 200.0f);
        ImGui::TableHeadersRow();

        std::string filterLower = m_rttiFilter;
        std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::tolower);

        std::vector<RTTIClass> classesCopy;
        {
            std::lock_guard<std::mutex> lock(m_rttiMutex);
            classesCopy = m_rttiClasses;
        }

        for (size_t i = 0; i < classesCopy.size(); ++i) {
            const auto& cls = classesCopy[i];

            // Apply filters
            if (m_rttiShowOnlyWithVtable && cls.vtable == 0) continue;

            if (!filterLower.empty()) {
                std::string nameLower = cls.demangledName;
                std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
                if (nameLower.find(filterLower) == std::string::npos) continue;
            }

            ImGui::TableNextRow();

            // Checkbox
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(cls.typeDescriptor));
            bool selected = cls.selected;
            if (ImGui::Checkbox("##sel", &selected)) {
                std::lock_guard<std::mutex> lock(m_rttiMutex);
                if (i < m_rttiClasses.size()) {
                    m_rttiClasses[i].selected = selected;
                }
            }
            ImGui::PopID();

            // Type Descriptor
            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", static_cast<unsigned long long>(cls.typeDescriptor));
            if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) {
                ImGui::SetClipboardText(std::format("0x{:X}", cls.typeDescriptor).c_str());
            }

            // VTable
            ImGui::TableNextColumn();
            if (cls.vtable != 0) {
                ImGui::Text("0x%llX", static_cast<unsigned long long>(cls.vtable));
                if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) {
                    ImGui::SetClipboardText(std::format("0x{:X}", cls.vtable).c_str());
                }
            } else {
                ImGui::TextDisabled("N/A");
            }

            // Class Name
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(cls.demangledName.c_str());
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("Mangled: %s", cls.mangledName.c_str());
            }
            if (ImGui::IsItemClicked()) {
                ImGui::SetClipboardText(cls.demangledName.c_str());
            }

            // Hierarchy
            ImGui::TableNextColumn();
            if (!cls.hierarchy.empty()) {
                ImGui::TextDisabled("%s", cls.hierarchy.c_str());
            }
        }

        ImGui::EndTable();
    }
}

void SignatureScannerModule::StartRTTIScan() {
    if (m_rttiScanInProgress) return;

    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) {
        LogError("Failed to get module handle for RTTI scan");
        return;
    }

    MODULEINFO modInfo{};
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        LogError("Failed to get module information for RTTI scan");
        return;
    }

    uintptr_t moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
    size_t moduleSize = modInfo.SizeOfImage;

    m_rttiScanInProgress = true;
    m_rttiScanProgress = 0;
    m_rttiScanTotal = 100; // Estimate

    {
        std::lock_guard<std::mutex> lock(m_rttiMutex);
        m_rttiClasses.clear();
    }

    std::thread([this, moduleBase, moduleSize]() {
        LogInfo("Starting RTTI scan...");

        // Scan for RTTI type descriptor pattern: ".?AV" prefix in class names
        // Type descriptors have structure: VTable ptr, spare ptr, decorated name
        const char* rttiMarker = ".?AV";
        const size_t markerLen = 4;

        size_t found = 0;
        const uint8_t* base = reinterpret_cast<const uint8_t*>(moduleBase);

        for (size_t offset = 0; offset < moduleSize - markerLen && m_rttiScanInProgress; offset += 4) {
            if (std::memcmp(base + offset, rttiMarker, markerLen) == 0) {
                // Found a type descriptor name
                // The name starts here, read until null terminator
                const char* nameStart = reinterpret_cast<const char*>(base + offset);
                size_t maxLen = moduleSize - offset;
                size_t nameLen = strnlen(nameStart, (std::min)(maxLen, size_t(512)));

                if (nameLen > 4 && nameLen < 500) {
                    std::string mangledName(nameStart, nameLen);
                    
                    // The type descriptor is 16 bytes before the name
                    // Structure: pVFTable(8) + spare(8) + name
                    uintptr_t typeDescAddr = moduleBase + offset - 16;

                    RTTIClass cls;
                    cls.typeDescriptor = typeDescAddr;
                    cls.mangledName = mangledName;
                    cls.demangledName = DemangleName(mangledName);
                    cls.vtable = 0;  // Will try to find later

                    // Try to find vtable by searching for references to this type descriptor
                    // VTables have COL (Complete Object Locator) that points to type descriptor

                    {
                        std::lock_guard<std::mutex> lock(m_rttiMutex);
                        m_rttiClasses.push_back(cls);
                    }

                    ++found;
                }
            }

            // Update progress periodically
            if (offset % (moduleSize / 100) == 0) {
                m_rttiScanProgress = static_cast<int>((offset * 100) / moduleSize);
            }
        }

        m_rttiScanProgress = 100;
        m_rttiScanInProgress = false;
        LogInfo(std::format("RTTI scan complete: found {} classes", found));
    }).detach();
}

void SignatureScannerModule::CancelRTTIScan() {
    m_rttiScanInProgress = false;
}

void SignatureScannerModule::ClearRTTIResults() {
    std::lock_guard<std::mutex> lock(m_rttiMutex);
    m_rttiClasses.clear();
}

std::string SignatureScannerModule::DemangleName(const std::string& mangled) {
    // Simple demangling for MSVC names
    // Format: .?AV<classname>@@
    std::string result = mangled;
    
    // Remove ".?AV" prefix
    if (result.size() > 4 && result.substr(0, 4) == ".?AV") {
        result = result.substr(4);
    }
    
    // Remove "@@" suffix
    size_t atPos = result.find("@@");
    if (atPos != std::string::npos) {
        result = result.substr(0, atPos);
    }
    
    // Handle nested classes (separated by @)
    std::string demangled;
    size_t pos = 0;
    std::vector<std::string> parts;
    
    while (pos < result.size()) {
        size_t nextAt = result.find('@', pos);
        if (nextAt == std::string::npos) {
            parts.push_back(result.substr(pos));
            break;
        }
        parts.push_back(result.substr(pos, nextAt - pos));
        pos = nextAt + 1;
    }
    
    // Reverse order for proper namespace display
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        if (!it->empty()) {
            if (!demangled.empty()) demangled += "::";
            demangled += *it;
        }
    }
    
    return demangled.empty() ? mangled : demangled;
}

void SignatureScannerModule::ExportRTTIResults() {
    std::lock_guard<std::mutex> lock(m_rttiMutex);

    if (m_rttiClasses.empty()) return;

    std::string content;
    content += "; SapphireHook RTTI Export\n";
    content += "; Format: TypeDescriptor | VTable | ClassName\n\n";

    for (const auto& cls : m_rttiClasses) {
        content += std::format("0x{:X} | {} | {}\n",
            cls.typeDescriptor,
            cls.vtable ? std::format("0x{:X}", cls.vtable) : "N/A",
            cls.demangledName);
    }

    content += "\n/* JSON format:\n[\n";
    bool first = true;
    for (const auto& cls : m_rttiClasses) {
        if (!first) content += ",\n";
        first = false;
        content += std::format("  {{\"typeDescriptor\": \"0x{:X}\", \"vtable\": \"{}\", \"name\": \"{}\", \"mangled\": \"{}\"}}",
            cls.typeDescriptor,
            cls.vtable ? std::format("0x{:X}", cls.vtable) : "null",
            cls.demangledName,
            cls.mangledName);
    }
    content += "\n]\n*/\n";

    auto tempDir = Logger::GetDefaultTempDir();
    auto tempPath = (tempDir / "rtti_classes.txt").string();
    std::ofstream ofs(tempPath);
    if (ofs) {
        ofs << content;
        ofs.close();
        LogInfo(std::format("Exported {} RTTI classes to {}", m_rttiClasses.size(), tempPath));
    }
}

// ============================================================================
// VTable Scanner Implementation
// ============================================================================

void SignatureScannerModule::RenderVTableTab() {
    ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.8f, 1.0f), "VTable Scanner");
    ImGui::TextDisabled("Scan for virtual function tables in .rdata section");
    ImGui::Spacing();

    // Settings
    ImGui::SetNextItemWidth(100);
    ImGui::SliderInt("Min Functions", &m_vtableMinFunctions, 1, 20);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100);
    ImGui::SliderInt("Max Functions", &m_vtableMaxFunctions, 10, 500);

    ImGui::Spacing();

    // Action buttons
    if (m_vtableScanInProgress) {
        float progress = m_vtableScanTotal > 0
            ? static_cast<float>(m_vtableScanProgress) / static_cast<float>(m_vtableScanTotal)
            : 0.0f;
        ImGui::ProgressBar(progress, ImVec2(200, 0));
        ImGui::SameLine();
        ImGui::Text("Scanning... %d / %d", m_vtableScanProgress.load(), m_vtableScanTotal.load());
        ImGui::SameLine();
        if (ImGui::Button("Cancel##vtable")) {
            CancelVTableScan();
        }
    } else {
        if (ImGui::Button("Start VTable Scan", ImVec2(150, 30))) {
            StartVTableScan();
        }
    }

    ImGui::SameLine();
    
    bool hasResults = false;
    {
        std::lock_guard<std::mutex> lock(m_vtableMutex);
        hasResults = !m_vtables.empty();
    }
    
    if (!hasResults) ImGui::BeginDisabled();
    if (ImGui::Button("Export##vtable")) {
        ExportVTableResults();
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear##vtable")) {
        ClearVTableResults();
    }
    if (!hasResults) ImGui::EndDisabled();

    // Filter
    ImGui::Spacing();
    ImGui::SetNextItemWidth(300);
    ImGui::InputTextWithHint("##vtablefilter", "Filter by address or class name...", m_vtableFilter, sizeof(m_vtableFilter));
    
    size_t vtableCount = 0;
    {
        std::lock_guard<std::mutex> lock(m_vtableMutex);
        vtableCount = m_vtables.size();
    }
    ImGui::SameLine();
    ImGui::Text("Found: %zu vtables", vtableCount);

    ImGui::Spacing();
    ImGui::Separator();

    // Split view: vtable list on left, functions on right
    ImGui::Columns(2, "vtableCols", true);
    
    // Left: VTable list
    if (ImGui::BeginTable("VTableList", 4,
        ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg,
        ImVec2(0, -1))) {

        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableSetupColumn("VTable", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Class", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Funcs", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableHeadersRow();

        std::string filterLower = m_vtableFilter;
        std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::tolower);

        std::vector<VTableEntry> vtablesCopy;
        {
            std::lock_guard<std::mutex> lock(m_vtableMutex);
            vtablesCopy = m_vtables;
        }

        for (size_t i = 0; i < vtablesCopy.size(); ++i) {
            const auto& vt = vtablesCopy[i];

            // Apply filter
            if (!filterLower.empty()) {
                std::string addrStr = std::format("{:X}", vt.vtableAddress);
                std::transform(addrStr.begin(), addrStr.end(), addrStr.begin(), ::tolower);
                std::string nameLower = vt.className;
                std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
                if (addrStr.find(filterLower) == std::string::npos && 
                    nameLower.find(filterLower) == std::string::npos) continue;
            }

            ImGui::TableNextRow();

            // Selection
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(vt.vtableAddress));
            bool isSelected = (m_selectedVtableIdx == static_cast<int>(i));
            if (ImGui::Selectable("##sel", isSelected, ImGuiSelectableFlags_SpanAllColumns)) {
                m_selectedVtableIdx = static_cast<int>(i);
            }
            ImGui::PopID();

            // VTable address
            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", static_cast<unsigned long long>(vt.vtableAddress));

            // Class name
            ImGui::TableNextColumn();
            if (!vt.className.empty()) {
                ImGui::TextUnformatted(vt.className.c_str());
            } else {
                ImGui::TextDisabled("Unknown");
            }

            // Function count
            ImGui::TableNextColumn();
            ImGui::Text("%zu", vt.functionCount);
        }

        ImGui::EndTable();
    }

    ImGui::NextColumn();

    // Right: Function list for selected vtable
    ImGui::Text("Functions:");
    
    std::vector<uintptr_t> selectedFunctions;
    std::string selectedClassName;
    {
        std::lock_guard<std::mutex> lock(m_vtableMutex);
        if (m_selectedVtableIdx >= 0 && m_selectedVtableIdx < static_cast<int>(m_vtables.size())) {
            selectedFunctions = m_vtables[m_selectedVtableIdx].functions;
            selectedClassName = m_vtables[m_selectedVtableIdx].className;
        }
    }

    if (selectedFunctions.empty()) {
        ImGui::TextDisabled("Select a vtable to view functions");
    } else {
        if (ImGui::BeginTable("VTableFuncs", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg,
            ImVec2(0, -1))) {

            ImGui::TableSetupColumn("Idx", ImGuiTableColumnFlags_WidthFixed, 40.0f);
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
            ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableHeadersRow();

            HMODULE hModule = GetModuleHandle(nullptr);
            uintptr_t baseAddr = reinterpret_cast<uintptr_t>(hModule);

            for (size_t i = 0; i < selectedFunctions.size(); ++i) {
                uintptr_t funcAddr = selectedFunctions[i];
                
                ImGui::TableNextRow();

                ImGui::TableNextColumn();
                ImGui::Text("%zu", i);

                ImGui::TableNextColumn();
                ImGui::Text("0x%llX", static_cast<unsigned long long>(funcAddr));
                if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) {
                    ImGui::SetClipboardText(std::format("0x{:X}", funcAddr).c_str());
                }

                ImGui::TableNextColumn();
                ImGui::TextDisabled("+0x%llX", static_cast<unsigned long long>(funcAddr - baseAddr));
            }

            ImGui::EndTable();
        }
    }

    ImGui::Columns(1);
}

void SignatureScannerModule::StartVTableScan() {
    if (m_vtableScanInProgress) return;

    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) {
        LogError("Failed to get module handle for VTable scan");
        return;
    }

    MODULEINFO modInfo{};
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        LogError("Failed to get module information for VTable scan");
        return;
    }

    uintptr_t moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
    size_t moduleSize = modInfo.SizeOfImage;

    m_vtableScanInProgress = true;
    m_vtableScanProgress = 0;
    m_vtableScanTotal = 100;

    {
        std::lock_guard<std::mutex> lock(m_vtableMutex);
        m_vtables.clear();
    }

    int minFuncs = m_vtableMinFunctions;
    int maxFuncs = m_vtableMaxFunctions;

    std::thread([this, moduleBase, moduleSize, minFuncs, maxFuncs]() {
        LogInfo("Starting VTable scan...");

        // Get .rdata section bounds (vtables are typically in .rdata)
        // For simplicity, scan the entire module but look for arrays of valid function pointers

        const uintptr_t* ptr = reinterpret_cast<const uintptr_t*>(moduleBase);
        size_t count = moduleSize / sizeof(uintptr_t);
        
        size_t found = 0;

        for (size_t i = 0; i < count - minFuncs && m_vtableScanInProgress; ++i) {
            // Check if this looks like a vtable start
            uintptr_t potentialVtable = moduleBase + i * sizeof(uintptr_t);

            // Count consecutive valid function pointers
            int validCount = 0;
            std::vector<uintptr_t> functions;

            for (int j = 0; j < maxFuncs && (i + j) < count; ++j) {
                uintptr_t val = ptr[i + j];
                
                if (IsValidFunctionPointer(val, moduleBase, moduleSize)) {
                    functions.push_back(val);
                    validCount++;
                } else {
                    break;
                }
            }

            if (validCount >= minFuncs) {
                VTableEntry vt;
                vt.vtableAddress = potentialVtable;
                vt.functions = functions;
                vt.functionCount = functions.size();

                // Try to find class name from RTTI
                // Check 8 bytes before vtable for RTTI pointer
                if (i > 0) {
                    uintptr_t rttiPtr = ptr[i - 1];
                    if (rttiPtr >= moduleBase && rttiPtr < moduleBase + moduleSize) {
                        // Could be COL pointer - try to extract name
                        vt.rttiAddress = rttiPtr;
                        // Would need more complex parsing here
                    }
                }

                {
                    std::lock_guard<std::mutex> lock(m_vtableMutex);
                    m_vtables.push_back(vt);
                }

                ++found;
                i += validCount;  // Skip past this vtable
            }

            if (i % (count / 100) == 0) {
                m_vtableScanProgress = static_cast<int>((i * 100) / count);
            }
        }

        m_vtableScanProgress = 100;
        m_vtableScanInProgress = false;
        LogInfo(std::format("VTable scan complete: found {} vtables", found));
    }).detach();
}

bool SignatureScannerModule::IsValidFunctionPointer(uintptr_t addr, uintptr_t moduleBase, size_t moduleSize) {
    // Must be within module
    if (addr < moduleBase || addr >= moduleBase + moduleSize) {
        return false;
    }

    // Must be aligned
    if (addr % 16 != 0 && addr % 4 != 0) {
        return false;
    }

    // Check first byte is a valid instruction start
    if (!IsValidMemoryAddress(addr, 1)) {
        return false;
    }

    uint8_t firstByte = *reinterpret_cast<const uint8_t*>(addr);
    
    // Common function prologue first bytes
    // 0x40-0x4F: REX prefixes
    // 0x48: REX.W
    // 0x55: push rbp
    // 0x53: push rbx
    // 0x56: push rsi
    // 0x57: push rdi
    // 0x41: REX.B
    // 0xCC: int3 (padding/breakpoint)
    // 0x90: nop
    
    static const uint8_t validFirstBytes[] = {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x33, // xor
        0x8B, // mov
        0x89, // mov
        0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, // mov reg, imm
        0xE8, // call
        0xE9, // jmp
        0xEB, // jmp short
        0xC3, // ret
        0xCC, // int3
    };

    for (uint8_t valid : validFirstBytes) {
        if (firstByte == valid) return true;
    }

    return false;
}

void SignatureScannerModule::CancelVTableScan() {
    m_vtableScanInProgress = false;
}

void SignatureScannerModule::ClearVTableResults() {
    std::lock_guard<std::mutex> lock(m_vtableMutex);
    m_vtables.clear();
    m_selectedVtableIdx = -1;
}

void SignatureScannerModule::ExportVTableResults() {
    std::lock_guard<std::mutex> lock(m_vtableMutex);

    if (m_vtables.empty()) return;

    std::string content;
    content += "; SapphireHook VTable Export\n";
    content += "; Format: VTableAddr | FuncCount | ClassName\n\n";

    HMODULE hModule = GetModuleHandle(nullptr);
    uintptr_t baseAddr = reinterpret_cast<uintptr_t>(hModule);

    for (const auto& vt : m_vtables) {
        content += std::format("VTable 0x{:X} (RVA +0x{:X}) - {} functions\n",
            vt.vtableAddress,
            vt.vtableAddress - baseAddr,
            vt.functionCount);
        
        if (!vt.className.empty()) {
            content += std::format("  Class: {}\n", vt.className);
        }

        for (size_t i = 0; i < vt.functions.size(); ++i) {
            content += std::format("  [{}] 0x{:X}\n", i, vt.functions[i]);
        }
        content += "\n";
    }

    auto tempDir = Logger::GetDefaultTempDir();
    auto tempPath = (tempDir / "vtables.txt").string();
    std::ofstream ofs(tempPath);
    if (ofs) {
        ofs << content;
        ofs.close();
        LogInfo(std::format("Exported {} vtables to {}", m_vtables.size(), tempPath));
    }
}

// ============================================================================
// Static Pointer Scanner Implementation
// ============================================================================

void SignatureScannerModule::RenderStaticPointerTab() {
    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.4f, 1.0f), "Static Pointer Scanner");
    ImGui::TextDisabled("Find RIP-relative memory accesses (singletons, globals, etc.)");
    ImGui::Spacing();

    // Pattern selection
    if (ImGui::CollapsingHeader("Access Patterns", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::Columns(2, nullptr, false);
        for (auto& pp : m_staticPatterns) {
            ImGui::Checkbox(pp.name, &pp.enabled);
            ImGui::NextColumn();
        }
        ImGui::Columns(1);

        if (ImGui::Button("Enable All##static")) {
            for (auto& pp : m_staticPatterns) pp.enabled = true;
        }
        ImGui::SameLine();
        if (ImGui::Button("Disable All##static")) {
            for (auto& pp : m_staticPatterns) pp.enabled = false;
        }
    }

    ImGui::Spacing();

    // Action buttons
    bool anyEnabled = std::any_of(m_staticPatterns.begin(), m_staticPatterns.end(),
        [](const StaticPointerPattern& p) { return p.enabled; });

    if (m_staticScanInProgress) {
        float progress = m_staticScanTotal > 0
            ? static_cast<float>(m_staticScanProgress) / static_cast<float>(m_staticScanTotal)
            : 0.0f;
        ImGui::ProgressBar(progress, ImVec2(200, 0));
        ImGui::SameLine();
        ImGui::Text("Scanning... %d / %d", m_staticScanProgress.load(), m_staticScanTotal.load());
        ImGui::SameLine();
        if (ImGui::Button("Cancel##static")) {
            CancelStaticPointerScan();
        }
    } else {
        if (!anyEnabled) ImGui::BeginDisabled();
        if (ImGui::Button("Start Static Ptr Scan", ImVec2(160, 30))) {
            StartStaticPointerScan();
        }
        if (!anyEnabled) ImGui::EndDisabled();
    }

    ImGui::SameLine();
    
    bool hasResults = false;
    {
        std::lock_guard<std::mutex> lock(m_staticMutex);
        hasResults = !m_staticPointers.empty();
    }
    
    if (!hasResults) ImGui::BeginDisabled();
    if (ImGui::Button("Validate##static")) {
        ValidateStaticPointerUniqueness();
    }
    ImGui::SameLine();
    if (ImGui::Button("Export##static")) {
        ExportStaticPointerResults();
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear##static")) {
        ClearStaticPointerResults();
    }
    if (!hasResults) ImGui::EndDisabled();

    ImGui::SameLine(400);
    ImGui::Checkbox("Only Unique", &m_staticOnlyUnique);

    // Filter
    ImGui::Spacing();
    ImGui::SetNextItemWidth(300);
    ImGui::InputTextWithHint("##staticfilter", "Filter by address or pattern...", m_staticFilter, sizeof(m_staticFilter));
    
    size_t staticCount = 0;
    {
        std::lock_guard<std::mutex> lock(m_staticMutex);
        staticCount = m_staticPointers.size();
    }
    ImGui::SameLine();
    ImGui::Text("Found: %zu pointers", staticCount);

    ImGui::Spacing();
    ImGui::Separator();

    // Results table
    if (ImGui::BeginTable("StaticPtrTable", 6,
        ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable |
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Sortable,
        ImVec2(0, 0))) {

        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Target", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Pattern", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Unique", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableHeadersRow();

        std::string filterLower = m_staticFilter;
        std::transform(filterLower.begin(), filterLower.end(), filterLower.begin(), ::tolower);

        std::vector<StaticPointer> ptrsCopy;
        {
            std::lock_guard<std::mutex> lock(m_staticMutex);
            ptrsCopy = m_staticPointers;
        }

        for (size_t i = 0; i < ptrsCopy.size(); ++i) {
            const auto& sp = ptrsCopy[i];

            // Apply filters
            if (m_staticOnlyUnique && !sp.isUnique) continue;

            if (!filterLower.empty()) {
                std::string addrStr = std::format("{:X}", sp.targetAddress);
                std::transform(addrStr.begin(), addrStr.end(), addrStr.begin(), ::tolower);
                std::string patternLower = sp.pattern;
                std::transform(patternLower.begin(), patternLower.end(), patternLower.begin(), ::tolower);
                if (addrStr.find(filterLower) == std::string::npos && 
                    patternLower.find(filterLower) == std::string::npos) continue;
            }

            ImGui::TableNextRow();

            // Checkbox
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(sp.instructionAddress));
            bool selected = sp.selected;
            if (ImGui::Checkbox("##sel", &selected)) {
                std::lock_guard<std::mutex> lock(m_staticMutex);
                if (i < m_staticPointers.size()) {
                    m_staticPointers[i].selected = selected;
                }
            }
            ImGui::PopID();

            // Instruction address
            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", static_cast<unsigned long long>(sp.instructionAddress));
            if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) {
                ImGui::SetClipboardText(std::format("0x{:X}", sp.instructionAddress).c_str());
            }

            // Target address
            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", static_cast<unsigned long long>(sp.targetAddress));
            if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(1)) {
                ImGui::SetClipboardText(std::format("0x{:X}", sp.targetAddress).c_str());
            }

            // Access type
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", sp.accessType.c_str());

            // Pattern
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", sp.pattern.c_str());
            if (ImGui::IsItemClicked()) {
                ImGui::SetClipboardText(sp.pattern.c_str());
            }

            // Unique
            ImGui::TableNextColumn();
            if (sp.isUnique) {
                ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Yes");
            } else {
                ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "No");
            }
        }

        ImGui::EndTable();
    }
}

void SignatureScannerModule::StartStaticPointerScan() {
    if (m_staticScanInProgress) return;

    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) {
        LogError("Failed to get module handle for static pointer scan");
        return;
    }

    MODULEINFO modInfo{};
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        LogError("Failed to get module information for static pointer scan");
        return;
    }

    uintptr_t moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
    size_t moduleSize = modInfo.SizeOfImage;

    // Collect enabled patterns
    std::vector<std::pair<std::string, std::string>> enabledPatterns;
    for (const auto& pp : m_staticPatterns) {
        if (pp.enabled) {
            enabledPatterns.emplace_back(pp.pattern, pp.accessType);
        }
    }

    if (enabledPatterns.empty()) return;

    m_staticScanInProgress = true;
    m_staticScanProgress = 0;
    m_staticScanTotal = static_cast<int>(enabledPatterns.size());

    {
        std::lock_guard<std::mutex> lock(m_staticMutex);
        m_staticPointers.clear();
    }

    std::thread([this, moduleBase, moduleSize, enabledPatterns]() {
        LogInfo("Starting static pointer scan...");

        size_t found = 0;
        int patternIdx = 0;

        for (const auto& [pattern, accessType] : enabledPatterns) {
            if (!m_staticScanInProgress) break;

            // Scan for this pattern
            auto results = PatternScanner::ScanAllPatterns(moduleBase, moduleSize, pattern);

            for (const auto& result : results) {
                if (!m_staticScanInProgress) break;

                uintptr_t instrAddr = result.address;
                size_t patternLen = (pattern.size() + 1) / 3;  // "XX XX XX" -> 3 bytes

                // Read the offset (4 bytes after the pattern prefix)
                if (!IsValidMemoryAddress(instrAddr + patternLen, 4)) continue;

                int32_t offset = *reinterpret_cast<const int32_t*>(instrAddr + patternLen);
                
                // Calculate target: RIP + offset (RIP is after instruction)
                // Instruction is typically: prefix(3) + offset(4) = 7 bytes
                uintptr_t targetAddr = instrAddr + patternLen + 4 + offset;

                // Verify target is within module or is valid memory
                if (targetAddr < moduleBase || targetAddr >= moduleBase + moduleSize) {
                    continue;  // Outside module, skip
                }

                // Generate signature (first 7 bytes with wildcarded offset)
                std::string sig;
                if (IsValidMemoryAddress(instrAddr, patternLen + 4)) {
                    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(instrAddr);
                    for (size_t i = 0; i < patternLen; ++i) {
                        if (i > 0) sig += " ";
                        sig += std::format("{:02X}", bytes[i]);
                    }
                    sig += " ?? ?? ?? ??";  // Wildcard the offset
                }

                StaticPointer sp;
                sp.instructionAddress = instrAddr;
                sp.targetAddress = targetAddr;
                sp.pattern = sig;
                sp.accessType = accessType;
                sp.suggestedName = std::format("g_{:X}", targetAddr);
                sp.isUnique = false;  // Validate later

                {
                    std::lock_guard<std::mutex> lock(m_staticMutex);
                    m_staticPointers.push_back(sp);
                }

                ++found;
            }

            m_staticScanProgress = ++patternIdx;
        }

        // Remove duplicates by target address
        {
            std::lock_guard<std::mutex> lock(m_staticMutex);
            std::sort(m_staticPointers.begin(), m_staticPointers.end(),
                [](const StaticPointer& a, const StaticPointer& b) {
                    return a.targetAddress < b.targetAddress;
                });
            // Keep unique by target
            auto last = std::unique(m_staticPointers.begin(), m_staticPointers.end(),
                [](const StaticPointer& a, const StaticPointer& b) {
                    return a.targetAddress == b.targetAddress;
                });
            m_staticPointers.erase(last, m_staticPointers.end());
        }

        m_staticScanProgress = m_staticScanTotal.load();
        m_staticScanInProgress = false;
        LogInfo(std::format("Static pointer scan complete: found {} unique targets", m_staticPointers.size()));
    }).detach();
}

void SignatureScannerModule::CancelStaticPointerScan() {
    m_staticScanInProgress = false;
}

void SignatureScannerModule::ClearStaticPointerResults() {
    std::lock_guard<std::mutex> lock(m_staticMutex);
    m_staticPointers.clear();
}

void SignatureScannerModule::ValidateStaticPointerUniqueness() {
    size_t count = 0;
    {
        std::lock_guard<std::mutex> lock(m_staticMutex);
        count = m_staticPointers.size();
    }

    if (count == 0) return;

    HMODULE hModule = GetModuleHandle(nullptr);
    if (!hModule) return;

    MODULEINFO modInfo{};
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) return;

    uintptr_t moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
    size_t moduleSize = modInfo.SizeOfImage;

    // Run async
    std::thread([this, moduleBase, moduleSize, count]() {
        LogInfo("Validating static pointer uniqueness...");

        for (size_t i = 0; i < count; ++i) {
            std::string pattern;
            {
                std::lock_guard<std::mutex> lock(m_staticMutex);
                if (i < m_staticPointers.size()) {
                    pattern = m_staticPointers[i].pattern;
                }
            }

            if (!pattern.empty()) {
                auto results = PatternScanner::ScanAllPatterns(moduleBase, moduleSize, pattern);
                bool isUnique = (results.size() == 1);

                std::lock_guard<std::mutex> lock(m_staticMutex);
                if (i < m_staticPointers.size()) {
                    m_staticPointers[i].isUnique = isUnique;
                }
            }
        }

        size_t uniqueCount = 0;
        {
            std::lock_guard<std::mutex> lock(m_staticMutex);
            uniqueCount = std::count_if(m_staticPointers.begin(), m_staticPointers.end(),
                [](const StaticPointer& s) { return s.isUnique; });
        }

        LogInfo(std::format("Static pointer validation complete: {} / {} unique", uniqueCount, count));
    }).detach();
}

void SignatureScannerModule::ExportStaticPointerResults() {
    std::lock_guard<std::mutex> lock(m_staticMutex);

    if (m_staticPointers.empty()) return;

    HMODULE hModule = GetModuleHandle(nullptr);
    uintptr_t baseAddr = reinterpret_cast<uintptr_t>(hModule);

    std::string content;
    content += "; SapphireHook Static Pointer Export\n";
    content += "; Format: InstrAddr | TargetAddr | Type | Pattern | Unique\n\n";

    for (const auto& sp : m_staticPointers) {
        if (m_staticOnlyUnique && !sp.isUnique) continue;

        content += std::format("0x{:X} | 0x{:X} (RVA +0x{:X}) | {} | {} | {}\n",
            sp.instructionAddress,
            sp.targetAddress,
            sp.targetAddress - baseAddr,
            sp.accessType,
            sp.pattern,
            sp.isUnique ? "Unique" : "Multiple");
    }

    content += "\n/* JSON format:\n[\n";
    bool first = true;
    for (const auto& sp : m_staticPointers) {
        if (m_staticOnlyUnique && !sp.isUnique) continue;

        if (!first) content += ",\n";
        first = false;

        content += std::format("  {{\"instr\": \"0x{:X}\", \"target\": \"0x{:X}\", \"type\": \"{}\", \"pattern\": \"{}\", \"unique\": {}}}",
            sp.instructionAddress,
            sp.targetAddress,
            sp.accessType,
            sp.pattern,
            sp.isUnique ? "true" : "false");
    }
    content += "\n]\n*/\n";

    auto tempDir = Logger::GetDefaultTempDir();
    auto tempPath = (tempDir / "static_pointers.txt").string();
    std::ofstream ofs(tempPath);
    if (ofs) {
        ofs << content;
        ofs.close();
        LogInfo(std::format("Exported {} static pointers to {}", m_staticPointers.size(), tempPath));
    }
}

} // namespace SapphireHook
