#pragma once

#include "../UI/UIModule.h"

namespace SapphireHook {

class RetainerCacheInspectorModule final : public UIModule {
public:
  const char *GetName() const override { return "retainer_cache_inspector"; }
  const char *GetDisplayName() const override {
    return "Retainer Cache Inspector";
  }

  void RenderMenu() override;
  void RenderWindow() override;

  bool IsWindowOpen() const override { return m_windowOpen; }
  void SetWindowOpen(bool open) override { m_windowOpen = open; }

private:
  bool m_windowOpen = false;
};

} // namespace SapphireHook
