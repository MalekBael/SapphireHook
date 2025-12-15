# Doxygen (API Documentation)

SapphireHook is a native C++20 codebase, so the most common “API docs” approach is generating HTML from source comments.

This repo includes a starter Doxygen config at the repository root: `Doxyfile`.

## Prerequisites

- Install **Doxygen** (Windows).
  - If you use winget: `winget install doxygen.doxygen`

Optional:
- Install **Graphviz** if you want call graphs: `winget install graphviz.graphviz`

## Generate Docs

From the repo root:

- `doxygen Doxyfile`

Outputs (local-only):

- `docs/doxygen/html/index.html`

Generated output is intentionally ignored by git.

## Writing Doxygen Comments

Doxygen works best when functions/classes have `/** ... */` comments.

Example:

```cpp
/**
 * Reads the main module and returns the base address.
 * \return Base address if available.
 */
std::optional<uintptr_t> GetMainModuleBase();
```

## Scope / Exclusions

The default config documents `src/` (and uses `docs/README.md` as the main page) and excludes large dependency folders like `vendor/`.

If you later want vendor docs (e.g., `vendor/datReader`) included, we can narrow the `EXCLUDE` list or move datReader into `external/` and document it separately.
