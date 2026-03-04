#include "RetainerCacheInspectorModule.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <deque>
#include <future>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>


#include "../Core/SafeMemory.h"
#include "../Logger/Logger.h"
#include "../Monitor/NetworkMonitor.h" // PacketCapture snapshots
#include "../Network/OpcodeNames.h"
#include "../vendor/imgui/imgui.h"
#include "../vendor/imgui/misc/cpp/imgui_stdlib.h"

namespace SapphireHook {

namespace {
constexpr size_t kEntrySize = 64;
constexpr size_t kJobOffset = 0x39;
constexpr size_t kFlagsOffset = 0x3C;

static bool TryReadMemory(const void *src, void *dst, size_t len) {
  __try {
    std::memcpy(dst, src, len);
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

struct SlotSnapshot {
  std::array<uint8_t, kEntrySize> bytes{};
  bool valid = false;
};

struct ChangeEvent {
  std::chrono::system_clock::time_point ts{};
  uint32_t slotIndex = 0;

  uint8_t oldJob = 0;
  uint8_t newJob = 0;
  uint32_t oldFlags = 0;
  uint32_t newFlags = 0;

  PacketCapture::LastIpcSnapshot lastIncoming{};
};

static std::string FormatTime(const std::chrono::system_clock::time_point &tp) {
  const std::time_t t = std::chrono::system_clock::to_time_t(tp);
  std::tm tm{};
  localtime_s(&tm, &t);
  char buf[32]{};
  std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tm.tm_hour, tm.tm_min,
                tm.tm_sec);
  return std::string(buf);
}

static std::optional<uintptr_t> TryParseUintptr(const std::string &s) {
  std::string t;
  t.reserve(s.size());
  for (char c : s) {
    if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
      t.push_back(c);
  }
  if (t.empty())
    return std::nullopt;

  int base = 10;
  if (t.size() > 2 && (t[0] == '0') && (t[1] == 'x' || t[1] == 'X')) {
    base = 16;
    t = t.substr(2);
  }
  if (t.empty())
    return std::nullopt;

  try {
    size_t consumed = 0;
    const unsigned long long v = std::stoull(t, &consumed, base);
    if (consumed != t.size())
      return std::nullopt;
    return static_cast<uintptr_t>(v);
  } catch (...) {
    return std::nullopt;
  }
}

static bool SafeReadBytes(uintptr_t addr, void *out, size_t len) {
  if (!out || len == 0)
    return false;
  if (!IsValidMemoryAddress(addr, len))
    return false;
  std::memcpy(out, reinterpret_cast<const void *>(addr), len);
  return true;
}

static uint8_t ReadU8(const uint8_t *p, size_t off) { return p[off]; }

static uint32_t ReadU32LE(const uint8_t *p, size_t off) {
  uint32_t v = 0;
  std::memcpy(&v, p + off, sizeof(v));
  return v;
}

struct CandidateBase {
  uintptr_t base = 0;
  int score = 0;
  int plausibleJobs = 0;
  int jobsInRange = 0;
  int jobsNotOne = 0;
  int plausibleFlags = 0;
  uint8_t sampleJob = 0;
  uint32_t sampleFlags = 0;
};

static std::string ToHexPtr(uintptr_t v) {
  std::ostringstream os;
  os << "0x" << std::hex << std::uppercase << v;
  return os.str();
}

static bool IsReadableProtect(DWORD protect) {
  if (protect & PAGE_GUARD)
    return false;
  if (protect & PAGE_NOACCESS)
    return false;
  const DWORD base = protect & 0xFF;
  return base == PAGE_READONLY || base == PAGE_READWRITE ||
         base == PAGE_WRITECOPY || base == PAGE_EXECUTE_READ ||
         base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

static int Popcount32(uint32_t v) {
#if defined(_MSC_VER)
  return __popcnt(v);
#else
  // Fallback (not expected on MSVC builds)
  int c = 0;
  while (v) {
    v &= (v - 1);
    ++c;
  }
  return c;
#endif
}

static CandidateBase ScoreCandidate(uintptr_t base, int slotCount) {
  CandidateBase c{};
  c.base = base;
  if (slotCount <= 0)
    return c;

  int plausibleJobs = 0;
  int jobsInRange = 0;
  int jobsNotOne = 0;
  int plausibleFlags = 0;
  uint8_t sampleJob = 0;
  uint32_t sampleFlags = 0;
  bool capturedSample = false;

  for (int i = 0; i < slotCount; ++i) {
    const uintptr_t entry = base + static_cast<uintptr_t>(i) * kEntrySize;

    uint8_t job = 0;
    uint32_t flags = 0;
    if (!TryReadMemory(reinterpret_cast<const void *>(entry + kJobOffset), &job,
                       sizeof(job)))
      continue;
    if (!TryReadMemory(reinterpret_cast<const void *>(entry + kFlagsOffset),
                       &flags, sizeof(flags)))
      continue;

    // job (ClassJob) should generally be 0 or within a small range.
    // Count non-zero jobs separately; that helps avoid lots of false positives.
    if (job == 0 || job <= 50) {
      plausibleJobs++;
      if (job >= 1 && job <= 50) {
        jobsInRange++;
        if (job != 1) {
          jobsNotOne++;
        }
        if (!capturedSample) {
          sampleJob = job;
        }
      }
    }

    // flags: we only know it's a bitmask; filter obvious garbage
    if (flags != 0 && flags != 0xFFFFFFFFu) {
      // Reject very "random" looking values with lots of high bits set.
      if ((flags & 0xFF000000u) == 0) {
        // Further reject "random" by limiting bit density.
        const int bits = Popcount32(flags & 0x00FFFFFFu);
        if (bits > 0 && bits <= 12) {
          plausibleFlags++;
          if (!capturedSample) {
            if (sampleJob == 0)
              sampleJob = job;
            sampleFlags = flags;
            capturedSample = true;
          }
        }
      }
    }
  }

  c.plausibleJobs = plausibleJobs;
  c.jobsInRange = jobsInRange;
  c.jobsNotOne = jobsNotOne;
  c.plausibleFlags = plausibleFlags;
  c.sampleJob = sampleJob;
  c.sampleFlags = sampleFlags;

  // Weighted score: flags are informative; non-zero jobs are a strong signal.
  // Heavily bias away from the very-common false-positive pattern where job==1
  // everywhere.
  c.score =
      plausibleFlags * 8 + jobsInRange * 6 + jobsNotOne * 10 + plausibleJobs;
  return c;
}

static std::vector<CandidateBase>
ClusterCandidates(std::vector<CandidateBase> in) {
  if (in.empty())
    return {};

  // Many false positives come back as a dense run of 0x40-aligned bases.
  // Cluster nearby bases and keep the best scoring one per cluster.
  std::sort(in.begin(), in.end(),
            [](const CandidateBase &a, const CandidateBase &b) {
              return a.base < b.base;
            });

  std::vector<CandidateBase> clustered;
  clustered.reserve(in.size());

  constexpr uintptr_t kClusterSpan = 0x400; // 16 entries
  CandidateBase best = in.front();
  uintptr_t clusterStart = in.front().base;

  for (size_t i = 1; i < in.size(); ++i) {
    const auto &c = in[i];
    if (c.base - clusterStart <= kClusterSpan) {
      if (c.score > best.score)
        best = c;
      continue;
    }
    clustered.push_back(best);
    best = c;
    clusterStart = c.base;
  }
  clustered.push_back(best);

  std::sort(clustered.begin(), clustered.end(),
            [](const CandidateBase &a, const CandidateBase &b) {
              return a.score > b.score;
            });
  if (clustered.size() > 20)
    clustered.resize(20);
  return clustered;
}

static std::vector<CandidateBase>
ScanForCandidates(std::atomic<float> &progress, std::atomic<bool> &cancel,
                  int slotCount, bool fullScan) {
  std::vector<CandidateBase> out;
  out.reserve(32);

  SYSTEM_INFO si{};
  GetSystemInfo(&si);
  const uintptr_t minAddr =
      reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
  const uintptr_t maxAddr =
      reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

  uintptr_t addr = minAddr;
  MEMORY_BASIC_INFORMATION mbi{};

  // Fast scan steps over memory and only evaluates candidates occasionally.
  const size_t step = fullScan ? 0x40 : 0x200;

  // Dedupe bases we already accepted.
  std::unordered_set<uintptr_t> accepted;
  accepted.reserve(128);

  // Cap scan to keep it practical in-game (still enough to find the heap
  // structures)
  constexpr size_t kMaxRegionsToScan = 6000;
  size_t regionsScanned = 0;

  const size_t bytesNeeded = static_cast<size_t>(slotCount) * kEntrySize;
  if (bytesNeeded == 0)
    return out;

  while (addr < maxAddr && !cancel.load()) {
    const SIZE_T q =
        VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
    if (q == 0)
      break;

    const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    const uintptr_t regionEnd =
        regionBase + static_cast<uintptr_t>(mbi.RegionSize);
    addr = regionEnd;

    if (++regionsScanned > kMaxRegionsToScan)
      break;
    progress.store(static_cast<float>(regionBase - minAddr) /
                       static_cast<float>((maxAddr - minAddr) + 1),
                   std::memory_order_relaxed);

    if (mbi.State != MEM_COMMIT)
      continue;
    if (mbi.Type != MEM_PRIVATE)
      continue; // keep scan focused
    if (!IsReadableProtect(mbi.Protect))
      continue;
    if (mbi.RegionSize < bytesNeeded)
      continue;

    // Ensure we start on a 0x40 boundary.
    uintptr_t p = (regionBase + 0x3F) & ~uintptr_t(0x3F);
    const uintptr_t stop = regionEnd - static_cast<uintptr_t>(bytesNeeded);

    for (; p <= stop && !cancel.load(); p += step) {
      const uintptr_t base = p & ~uintptr_t(0x3F);

      // Quick pre-check: try to avoid lots of expensive scoring.
      // We only touch a couple bytes; if they're totally wild, skip.
      uint8_t j0 = 0;
      if (!TryReadMemory(reinterpret_cast<const void *>(base + kJobOffset), &j0,
                         sizeof(j0)))
        continue;
      if (!(j0 == 0 || j0 <= 50))
        continue;

      CandidateBase cand = ScoreCandidate(base, slotCount);

      // Threshold tuned to prefer "looks-structured" blocks.
      if (cand.plausibleFlags >= 1 && cand.jobsInRange >= 1 &&
          cand.plausibleJobs >= (std::max)(2, slotCount / 2)) {
        if (!accepted.insert(cand.base).second)
          continue;
        out.push_back(cand);

        // Keep only top N candidates by score.
        std::sort(out.begin(), out.end(),
                  [](const CandidateBase &a, const CandidateBase &b) {
                    return a.score > b.score;
                  });
        if (out.size() > 30)
          out.resize(30);

        // Local refine around candidate to improve odds of finding the true
        // base even with coarse stepping.
        if (!fullScan) {
          const uintptr_t refineStart =
              (base > 0x4000) ? (base - 0x4000) : base;
          const uintptr_t refineEnd = base + 0x4000;
          for (uintptr_t r = refineStart; r < refineEnd && !cancel.load();
               r += 0x40) {
            const uintptr_t rb = r & ~uintptr_t(0x3F);
            uint8_t jj = 0;
            if (!TryReadMemory(reinterpret_cast<const void *>(rb + kJobOffset),
                               &jj, sizeof(jj)))
              continue;
            if (!(jj == 0 || jj <= 50))
              continue;
            CandidateBase cc = ScoreCandidate(rb, slotCount);
            if (cc.plausibleFlags >= 1 && cc.jobsInRange >= 1 &&
                cc.plausibleJobs >= (std::max)(2, slotCount / 2)) {
              if (!accepted.insert(cc.base).second)
                continue;
              out.push_back(cc);
            }
          }
          std::sort(out.begin(), out.end(),
                    [](const CandidateBase &a, const CandidateBase &b) {
                      return a.score > b.score;
                    });
          if (out.size() > 30)
            out.resize(30);
        }
      }
    }
  }

  progress.store(1.0f, std::memory_order_relaxed);
  return ClusterCandidates(std::move(out));
}

static std::string FormatIpc(const PacketCapture::LastIpcSnapshot &snap) {
  if (!snap.valid)
    return "(no IPC)";

  const uint16_t conn = (snap.connType == 0 || snap.connType == 0xFFFF)
                            ? 1
                            : snap.connType; // default Zone
  const char *name = LookupOpcodeName(snap.opcode, false,
                                      static_cast<Net::ConnectionType>(conn));

  char buf[128]{};
  std::snprintf(buf, sizeof(buf), "0x%04X %s (conn=%u)%s", snap.opcode,
                (name && name[0]) ? name : "?", static_cast<unsigned>(conn),
                snap.compressed ? " [compressed]" : "");
  return std::string(buf);
}
} // namespace

void RetainerCacheInspectorModule::RenderMenu() {
  // Toggled from Tools menu only.
}

void RetainerCacheInspectorModule::RenderWindow() {
  if (!m_windowOpen)
    return;

  static std::string s_baseStr = "0x0";
  static int s_slotCount = 10;
  static bool s_autoRefresh = true;
  static bool s_logOnChange = true;
  static int s_refreshMs = 200;

  // Auto-find state
  static bool s_fullScan = false;
  static std::atomic<bool> s_findCancel{false};
  static std::atomic<float> s_findProgress{0.0f};
  static std::future<std::vector<CandidateBase>> s_findTask;
  static std::vector<CandidateBase> s_candidates;
  static std::string s_findStatus;

  static std::vector<SlotSnapshot> s_prev;
  static std::deque<ChangeEvent> s_history;
  static uint32_t s_selectedSlot = 0;
  static std::chrono::steady_clock::time_point s_nextRefresh{};

  ImGui::SetNextWindowSize(ImVec2(1100, 650), ImGuiCond_FirstUseEver);
  if (!ImGui::Begin("Retainer Cache Inspector", &m_windowOpen)) {
    ImGui::End();
    return;
  }

  ImGui::TextDisabled("Watches %zu-byte entries; job @ +0x%zX, flags @ +0x%zX",
                      kEntrySize, kJobOffset, kFlagsOffset);
  ImGui::TextDisabled("Tip: open the retainer bell/list first, then Auto-Find "
                      "(more reliable after the cache is populated).");

  ImGui::Separator();

  ImGui::InputText("Base address", &s_baseStr);
  ImGui::SameLine();
  if (ImGui::Button("Clear"))
    s_baseStr = "0x0";

  ImGui::SameLine();
  {
    const bool running = s_findTask.valid() &&
                         s_findTask.wait_for(std::chrono::milliseconds(0)) !=
                             std::future_status::ready;
    if (running)
      ImGui::BeginDisabled();
    if (ImGui::Button("Auto-Find")) {
      s_findCancel.store(false);
      s_findProgress.store(0.0f);
      s_findStatus = "Scanning memory...";
      s_candidates.clear();
      const int slotCountForScan = (std::max)(1, (std::min)(s_slotCount, 64));
      const bool full = s_fullScan;
      s_findTask = std::async(std::launch::async, [slotCountForScan, full]() {
        return ScanForCandidates(s_findProgress, s_findCancel, slotCountForScan,
                                 full);
      });
    }
    if (running)
      ImGui::EndDisabled();
  }

  ImGui::SameLine();
  {
    const bool canAutoUse = !s_candidates.empty();
    if (!canAutoUse)
      ImGui::BeginDisabled();
    if (ImGui::Button("Auto-Use Best")) {
      // Prefer candidates that avoid the job==1 false positive, then highest
      // score.
      auto bestIt =
          std::max_element(s_candidates.begin(), s_candidates.end(),
                           [](const CandidateBase &a, const CandidateBase &b) {
                             if (a.jobsNotOne != b.jobsNotOne)
                               return a.jobsNotOne < b.jobsNotOne;
                             return a.score < b.score;
                           });
      if (bestIt != s_candidates.end()) {
        s_baseStr = ToHexPtr(bestIt->base);
      }
    }
    if (!canAutoUse)
      ImGui::EndDisabled();
  }

  ImGui::SameLine();
  ImGui::Checkbox("Full scan", &s_fullScan);
  ImGui::SetItemTooltip(
      "Full scan checks every 0x40-aligned candidate (slower).\nFast scan is "
      "usually enough if you have the retainer UI open.");

  ImGui::InputInt("Slot count", &s_slotCount);
  s_slotCount = (std::max)(0, (std::min)(s_slotCount, 64));

  ImGui::Checkbox("Auto refresh", &s_autoRefresh);
  ImGui::SameLine();
  ImGui::Checkbox("Log changes", &s_logOnChange);

  ImGui::SliderInt("Refresh (ms)", &s_refreshMs, 16, 2000);

  const auto baseOpt = TryParseUintptr(s_baseStr);
  const uintptr_t base = baseOpt.value_or(0);

  PacketCapture::LastIpcSnapshot lastIncoming{};
  PacketCapture::TryGetLastIncomingIpcSnapshot(lastIncoming);
  ImGui::Text("Last incoming IPC: %s", FormatIpc(lastIncoming).c_str());

  // Auto-find results UI
  {
    const bool running = s_findTask.valid() &&
                         s_findTask.wait_for(std::chrono::milliseconds(0)) !=
                             std::future_status::ready;
    if (running) {
      ImGui::Text("Auto-Find: %s", s_findStatus.c_str());
      ImGui::ProgressBar(
          (std::max)(0.0f, (std::min)(1.0f, s_findProgress.load(
                                                std::memory_order_relaxed))),
          ImVec2(-1, 0));
      if (ImGui::Button("Cancel scan")) {
        s_findCancel.store(true);
      }
    } else if (s_findTask.valid()) {
      // Finalize once
      try {
        s_candidates = s_findTask.get();
        s_findStatus = "Done";
      } catch (...) {
        s_candidates.clear();
        s_findStatus = "Failed";
      }
    }

    if (!s_candidates.empty()) {
      ImGui::Text("Auto-Find candidates (%zu)", s_candidates.size());
      if (ImGui::BeginTable("candidates", 6,
                            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Use", ImGuiTableColumnFlags_WidthFixed, 46.f);
        ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed,
                                140.f);
        ImGui::TableSetupColumn("Score", ImGuiTableColumnFlags_WidthFixed,
                                60.f);
        ImGui::TableSetupColumn("Jobs OK", ImGuiTableColumnFlags_WidthFixed,
                                70.f);
        ImGui::TableSetupColumn("Flags OK", ImGuiTableColumnFlags_WidthFixed,
                                70.f);
        ImGui::TableSetupColumn("Sample");
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < s_candidates.size(); ++i) {
          const auto &c = s_candidates[i];
          ImGui::TableNextRow();

          ImGui::TableSetColumnIndex(0);
          ImGui::PushID(static_cast<int>(i));
          if (ImGui::Button("Use")) {
            s_baseStr = ToHexPtr(c.base);
          }
          ImGui::PopID();

          ImGui::TableSetColumnIndex(1);
          ImGui::TextUnformatted(ToHexPtr(c.base).c_str());
          ImGui::TableSetColumnIndex(2);
          ImGui::Text("%d", c.score);
          ImGui::TableSetColumnIndex(3);
          ImGui::Text("%d", c.plausibleJobs);
          ImGui::TableSetColumnIndex(4);
          ImGui::Text("%d", c.plausibleFlags);
          ImGui::TableSetColumnIndex(5);
          if (c.plausibleFlags > 0) {
            ImGui::Text("job=%u flags=0x%08X",
                        static_cast<unsigned>(c.sampleJob), c.sampleFlags);
          } else {
            ImGui::TextDisabled("(no nonzero flags sampled)");
          }
        }

        ImGui::EndTable();
      }
    } else if (!s_findStatus.empty() && s_findStatus != "Scanning memory...") {
      ImGui::TextDisabled("Auto-Find: %s", s_findStatus.c_str());
    }
  }

  const bool baseValid = (base != 0) && IsValidMemoryAddress(base, kEntrySize);
  if (!baseValid) {
    ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1),
                       "Base address is not readable.");
  }

  auto doRefresh = [&]() {
    if (s_slotCount <= 0 || !baseValid)
      return;

    if (static_cast<int>(s_prev.size()) != s_slotCount) {
      s_prev.assign(static_cast<size_t>(s_slotCount), SlotSnapshot{});
    }

    for (int i = 0; i < s_slotCount; ++i) {
      const uintptr_t addr = base + static_cast<uintptr_t>(i) * kEntrySize;
      SlotSnapshot cur{};
      cur.valid = SafeReadBytes(addr, cur.bytes.data(), cur.bytes.size());

      const SlotSnapshot &prev = s_prev[static_cast<size_t>(i)];
      const bool hadPrev = prev.valid;

      if (cur.valid && hadPrev) {
        const uint8_t oldJob = ReadU8(prev.bytes.data(), kJobOffset);
        const uint8_t newJob = ReadU8(cur.bytes.data(), kJobOffset);
        const uint32_t oldFlags = ReadU32LE(prev.bytes.data(), kFlagsOffset);
        const uint32_t newFlags = ReadU32LE(cur.bytes.data(), kFlagsOffset);

        if (oldJob != newJob || oldFlags != newFlags) {
          ChangeEvent ev{};
          ev.ts = std::chrono::system_clock::now();
          ev.slotIndex = static_cast<uint32_t>(i);
          ev.oldJob = oldJob;
          ev.newJob = newJob;
          ev.oldFlags = oldFlags;
          ev.newFlags = newFlags;
          ev.lastIncoming = lastIncoming;

          s_history.push_front(ev);
          while (s_history.size() > 200)
            s_history.pop_back();

          if (s_logOnChange) {
            char msg[256]{};
            std::snprintf(msg, sizeof(msg),
                          "[RetainerCache] slot=%u job:%u->%u "
                          "flags:0x%08X->0x%08X last=%s",
                          ev.slotIndex, ev.oldJob, ev.newJob, ev.oldFlags,
                          ev.newFlags, FormatIpc(ev.lastIncoming).c_str());
            LogInfo(msg);
          }
        }
      }

      s_prev[static_cast<size_t>(i)] = cur;
    }
  };

  if (ImGui::Button("Refresh now")) {
    doRefresh();
  }

  if (s_autoRefresh) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= s_nextRefresh) {
      doRefresh();
      s_nextRefresh =
          now + std::chrono::milliseconds((std::max)(16, s_refreshMs));
    }
  }

  ImGui::Separator();

  if (ImGui::BeginTable("retainer_cache", 5,
                        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                            ImGuiTableFlags_ScrollY,
                        ImVec2(0, 240))) {
    ImGui::TableSetupColumn("Slot", ImGuiTableColumnFlags_WidthFixed, 48);
    ImGui::TableSetupColumn("Addr", ImGuiTableColumnFlags_WidthFixed, 120);
    ImGui::TableSetupColumn("Job(+0x39)", ImGuiTableColumnFlags_WidthFixed, 90);
    ImGui::TableSetupColumn("Flags(+0x3C)", ImGuiTableColumnFlags_WidthFixed,
                            120);
    ImGui::TableSetupColumn("Status");
    ImGui::TableHeadersRow();

    for (int i = 0; i < s_slotCount; ++i) {
      const uintptr_t addr = base + static_cast<uintptr_t>(i) * kEntrySize;

      SlotSnapshot cur{};
      cur.valid = SafeReadBytes(addr, cur.bytes.data(), cur.bytes.size());

      const uint8_t job = cur.valid ? ReadU8(cur.bytes.data(), kJobOffset) : 0;
      const uint32_t flags =
          cur.valid ? ReadU32LE(cur.bytes.data(), kFlagsOffset) : 0;

      ImGui::TableNextRow();
      ImGui::TableNextColumn();
      {
        const bool selected = (s_selectedSlot == static_cast<uint32_t>(i));
        char label[32]{};
        std::snprintf(label, sizeof(label), "%d", i);
        if (ImGui::Selectable(label, selected,
                              ImGuiSelectableFlags_SpanAllColumns)) {
          s_selectedSlot = static_cast<uint32_t>(i);
        }
      }

      ImGui::TableNextColumn();
      {
        char buf[32]{};
        std::snprintf(buf, sizeof(buf), "0x%p", reinterpret_cast<void *>(addr));
        ImGui::TextUnformatted(buf);
      }

      ImGui::TableNextColumn();
      if (cur.valid) {
        ImGui::Text("%u", static_cast<unsigned>(job));
      } else {
        ImGui::TextDisabled("-");
      }

      ImGui::TableNextColumn();
      if (cur.valid) {
        ImGui::Text("0x%08X", flags);
      } else {
        ImGui::TextDisabled("-");
      }

      ImGui::TableNextColumn();
      if (cur.valid) {
        ImGui::TextDisabled("OK");
      } else {
        ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1), "Unreadable");
      }
    }

    ImGui::EndTable();
  }

  ImGui::Separator();

  // Selected slot tail dump
  {
    const uintptr_t addr =
        base + static_cast<uintptr_t>(s_selectedSlot) * kEntrySize;
    std::array<uint8_t, kEntrySize> cur{};
    const bool ok = SafeReadBytes(addr, cur.data(), cur.size());

    ImGui::Text("Selected slot: %u", s_selectedSlot);
    if (ok) {
      ImGui::Text("job=%u flags=0x%08X",
                  static_cast<unsigned>(ReadU8(cur.data(), kJobOffset)),
                  ReadU32LE(cur.data(), kFlagsOffset));
      ImGui::TextDisabled("Tail [0x30..0x3F]:");

      ImGui::BeginChild("tail_dump", ImVec2(0, 90), true);
      for (size_t off = 0x30; off < 0x40; off += 0x10) {
        char line[128]{};
        std::snprintf(line, sizeof(line),
                      "%02zX: %02X %02X %02X %02X %02X %02X %02X %02X  %02X "
                      "%02X %02X %02X %02X %02X %02X %02X",
                      off, cur[off + 0], cur[off + 1], cur[off + 2],
                      cur[off + 3], cur[off + 4], cur[off + 5], cur[off + 6],
                      cur[off + 7], cur[off + 8], cur[off + 9], cur[off + 10],
                      cur[off + 11], cur[off + 12], cur[off + 13],
                      cur[off + 14], cur[off + 15]);
        ImGui::TextUnformatted(line);
      }
      ImGui::EndChild();
    } else {
      ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1),
                         "Selected slot memory unreadable.");
    }
  }

  ImGui::Separator();

  ImGui::Text("Recent changes");
  ImGui::BeginChild("history", ImVec2(0, 0), true);
  if (s_history.empty()) {
    ImGui::TextDisabled("(no changes yet)");
  } else {
    for (const auto &ev : s_history) {
      ImGui::Text("[%s] slot=%u job:%u->%u flags:0x%08X->0x%08X last=%s",
                  FormatTime(ev.ts).c_str(), ev.slotIndex,
                  static_cast<unsigned>(ev.oldJob),
                  static_cast<unsigned>(ev.newJob), ev.oldFlags, ev.newFlags,
                  FormatIpc(ev.lastIncoming).c_str());
    }
  }
  ImGui::EndChild();

  ImGui::End();
}

} // namespace SapphireHook
