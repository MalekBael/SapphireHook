# Safety & Defensive Coding

SapphireHook runs inside a live game process. Defensive coding is not optional.

## Memory Access Rules

- Treat all in-process pointers as untrusted.
- Validate addresses and ranges before reading/writing.
- Prefer safe helpers in `SafeMemory` over ad-hoc checks.
- Avoid deprecated Win32 pointer probing (e.g., `IsBadReadPtr`).

### Use `SafeMemory`

Core helpers live in:

- `src/Core/SafeMemory.h`
- `src/Core/SafeMemory.cpp`

When reading memory:

- Validate the range (address + size) before touching it.
- Prefer `std::memcpy` into a local POD object rather than dereferencing potentially unaligned pointers.

## Buffer/Formatting Safety

- Avoid unbounded formatting functions (e.g., `sprintf`).
- Prefer bounded operations (`snprintf`-style) and explicit buffer sizes.

## Win32 Resource Ownership

If you touch Win32 handles (clipboard, events, threads, allocations):

- Check return values.
- Be explicit about ownership transfer semantics.
- Ensure every “acquire” has a corresponding “release”, even on early return.

## Threading & Concurrency

- Avoid doing heavy work on the render thread.
- If background threads are used:
  - make shutdown deterministic,
  - guard shared state,
  - prefer bounded queues/ring buffers.

## Hook Safety

- Hooks must be installed/uninstalled predictably.
- Avoid calling heavy/allocating code from hot hook paths.
- If a hook can re-enter, design for reentrancy or add guards.

## Data Validation

- Treat network packet lengths and offsets as hostile inputs.
- Always bounds-check before parsing.
- Avoid trusting “expected” struct sizes; verify `len >= sizeof(...)`.
