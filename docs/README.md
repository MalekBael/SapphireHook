# SapphireHook Documentation

This folder contains long-lived documentation (how the codebase works).

## Start Here

- [Build, Run, Inject](BUILD_AND_RUN.md)
- [Architecture Overview](ARCHITECTURE.md)
- [Module & Class Reference](MODULE_REFERENCE.md)
- [Safety & Defensive Coding](SAFETY.md)
- [Doxygen API Docs](DOXYGEN.md)
- [Troubleshooting](TROUBLESHOOTING.md)

## Network / Protocol Work

- [Packet Migration Guide](../notes/PACKET_MIGRATION_GUIDE.md)
- [Struct/Opcode Verification](STRUCT_OPCODE_VERIFICATION.md)
- [Quest Opcode Status](../notes/QUEST_OPCODE_STATUS.md)

## Refactors & Planning

- [Backlog](../notes/BACKLOG.md)
- [Refactor Notes](../notes/REFACTOR.md)
- [Migration Progress](../notes/MIGRATION_PROGRESS.md)

## Research Notes (as-is)

The bulk of working notes have been moved to `notes/` to keep this folder clean.

These are working notes and may be incomplete/outdated:

- [Signature research](../notes/sig-research.txt)
- [Signature scan results](../notes/signature_scan_results.txt)
- [VTable analysis](../notes/vtable_analysis.txt)
- [Discovered vtables](../notes/discovered_vtables.json)
- [Camera research](../notes/camera-research.txt)
- [Console notes](../notes/console.txt)

## Contributing to Docs

- Prefer adding durable docs as `*.md` files with clear titles.
- Keep research/one-off notes in `*.txt` or clearly-labeled `*-research.*` files.
- When documenting a system, link the key entry points (source files + primary types) so future readers can jump straight into code.
