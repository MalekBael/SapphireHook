# Template Family Implementation Strategy

## Overview
Several FFXIV IPC packets use C++ template structs with variable-length arrays to handle different payload sizes efficiently. Instead of defining separate structs for each size variant, the protocol uses a single template definition with explicit instantiations.

## Template Families Identified

### 1. **MapMarkerN** (7 variants)
- **Template**: `template<int ArgCount> struct FFXIVIpcMapMarkerN`
- **Variants**: 2, 4, 8, 16, 32, 64, 128
- **Opcodes**: 0x026D - 0x0273
- **Purpose**: Map marker updates with variable icon/layout/handler ID arrays
- **Fields**:
  - `numOfMarkers` (uint8_t): Dynamic count field
  - `iconIds[ArgCount]` (uint32_t array)
  - `layoutIds[ArgCount]` (uint32_t array)
  - `handlerIds[ArgCount]` (uint32_t array)

### 2. **BattleTalkN** (3 variants)
- **Template**: `template<int ArgCount> struct FFXIVIpcBattleTalkN`
- **Variants**: 2, 4, 8
- **Opcodes**: 0x0263 - 0x0265 (0x0262 is header)
- **Purpose**: Battle dialogue with variable arguments
- **Fields**:
  - `numOfArgs` (uint8_t): Dynamic count field
  - `handlerId`, `talkerId`, `kind`, `nameId`, `battleTalkId`, `time`
  - `args[ArgCount]` (uint32_t array)

### 3. **EventLogMessageN** (5 variants)
- **Template**: `template<int ArgCount> struct FFXIVIpcEventLogMessageN`
- **Variants**: 2, 4, 8, 16, 32
- **Opcodes**: 0x0259 - 0x025D (0x0258 is header)
- **Purpose**: Event log messages with variable parameters
- **Fields**:
  - `numOfArgs` (uint8_t): Dynamic count field
  - `handlerId`, `messageId`
  - `args[ArgCount]` (uint32_t array)

### 4. **UpdateEventSceneN** (8 variants)
- **Template**: `template<int ArgCount> struct FFXIVIpcUpdateEventSceneN`
- **Variants**: 2, 4, 8, 16, 32, 64, 128, 255
- **Opcodes**: 0x01CF - 0x01D6 (0x01CE is header)
- **Purpose**: Event scene updates with variable arguments
- **Fields**:
  - `numOfArgs` (uint8_t): Dynamic count field
  - `handlerId`, `sceneId`
  - `args[ArgCount]` (uint32_t array)

### 5. **ResumeEventSceneN** (8 variants)
- **Template**: `template<int ArgCount> struct FFXIVIpcResumeEventSceneN`
- **Variants**: 2, 4, 8, 16, 32, 64, 128, 255
- **Opcodes**: 0x01D8 - 0x01DF (0x01D7 is header)
- **Purpose**: Event scene resumption with variable arguments
- **Fields**:
  - `numOfArgs` (uint8_t): Dynamic count field
  - `handlerId`, `sceneId`, `resumeId`
  - `args[ArgCount]` (uint32_t array)

### 6. **PlayEventSceneN** (Opcode Discovery Needed)
- **Template**: `template<int ArgCount> struct FFXIVIpcPlayEventSceneN`
- **Status**: Struct defined, DECLARE_PACKET_FIELDS exists for size 8, opcodes unknown
- **Fields**:
  - `paramCount` (uint8_t): Dynamic count field
  - `actorId`, `eventId`, `scene`, `sceneFlags`
  - `params[ArgCount]` (uint32_t array)

### 7. **NoticeN** (Opcode Discovery Needed)
- **Template**: `template<int Size> struct FFXIVIpcNoticeN`
- **Status**: Struct defined, opcodes unknown
- **Fields**:
  - `numOfArgs` (uint8_t): Dynamic count field
  - `handlerId`, `noticeId`
  - `args[Size]` (uint32_t array)

## Implementation Strategy

### Phase 1: Template Decoder Implementation
Create a single generic decoder template that:
1. Reads the dynamic count field (e.g., `numOfMarkers`, `numOfArgs`, `paramCount`)
2. Decodes fixed-size fields using `FieldBuilder`
3. Iterates over the variable-length array based on the count field
4. Uses `std::ostringstream` to format array elements as comma-separated values

### Phase 2: Explicit Template Instantiation
For each size variant:
1. Create explicit specialization of `MakeGenericDecoder<T>`
2. Use the generic template decoder implementation
3. Validate struct size matches expected opcode payload

### Phase 3: Opcode Registration
Register each instantiated decoder with its corresponding opcode:
- Use sequential opcodes (e.g., MapMarker2 at 0x026D, MapMarker4 at 0x026E, etc.)
- Skip "header" opcodes (e.g., 0x0262 BattleTalkHeader) - these don't use the template struct

## C++ Implementation Pattern

```cpp
// Generic template decoder for variable-length array families
template<int ArgCount>
DecoderFunc MakeGenericDecoder_MapMarkerN() {
    return [](const uint8_t* p, size_t l, RowEmitter emit) {
        if (l < sizeof(ServerZone::FFXIVIpcMapMarkerN<ArgCount>)) { 
            emit("error", "Packet too small"); 
            return; 
        }
        auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcMapMarkerN<ArgCount>*>(p);
        
        // Format arrays as comma-separated strings
        std::ostringstream iconIds, layoutIds, handlerIds;
        for (int i = 0; i < pkt->numOfMarkers && i < ArgCount; ++i) {
            if (i > 0) {
                iconIds << ", ";
                layoutIds << ", ";
                handlerIds << ", ";
            }
            iconIds << pkt->iconIds[i];
            layoutIds << pkt->layoutIds[i];
            handlerIds << pkt->handlerIds[i];
        }
        
        FieldBuilder(emit)
            .Field("numOfMarkers", (int)pkt->numOfMarkers)
            .Field("iconIds", iconIds.str())
            .Field("layoutIds", layoutIds.str())
            .Field("handlerIds", handlerIds.str());
    };
}

// Explicit specializations for each size variant
template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<2>>() {
    return MakeGenericDecoder_MapMarkerN<2>();
}

template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<4>>() {
    return MakeGenericDecoder_MapMarkerN<4>();
}
// ... continue for 8, 16, 32, 64, 128

// Registration
r.RegisterDecoder(1, false, 0x026D, MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<2>>());
r.RegisterDecoder(1, false, 0x026E, MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<4>>());
// ... continue for all variants
```

## Safety Considerations

1. **Bounds Checking**: Always validate `numOfArgs/numOfMarkers/paramCount` against `ArgCount` to prevent buffer overruns
2. **Size Validation**: Check packet size against `sizeof(template<ArgCount>)` before casting
3. **Dynamic Count**: Use `min(dynamicCount, ArgCount)` when iterating arrays
4. **Array Formatting**: Use `std::ostringstream` for clean comma-separated output without manual memory management

## Benefits of This Approach

1. **Code Reuse**: Single decoder implementation handles all size variants
2. **Type Safety**: C++ templates provide compile-time type checking
3. **Maintainability**: Changes to decoder logic automatically apply to all variants
4. **Performance**: No runtime overhead compared to manually duplicated code
5. **Clarity**: Clean separation between template logic and opcode registration

## Completion Roadmap

### Immediate (Opcodes Known)
1. **MapMarkerN**: 7 variants (0x026D - 0x0273)
2. **BattleTalkN**: 3 variants (0x0263 - 0x0265)
3. **EventLogMessageN**: 5 variants (0x0259 - 0x025D)
4. **UpdateEventSceneN**: 8 variants (0x01CF - 0x01D6)
5. **ResumeEventSceneN**: 8 variants (0x01D8 - 0x01DF)

### Future (Opcode Discovery Required)
6. **PlayEventSceneN**: Unknown variants/opcodes (struct defined, DECLARE_PACKET_FIELDS exists for size 8)
7. **NoticeN**: Unknown variants/opcodes

## Expected Impact
- **Decoders Added**: 31 new registrations (7+3+5+8+8)
- **Progress**: From 147/169 (87%) to 178/169 (105% - need to recount FFXIVIpc* structs excluding template instances)
- **Code Lines**: ~500 lines for all template families vs ~1500 if manually duplicated

## Notes on Script Counting
The `list_missing_decoders.py` script currently counts template structs (e.g., `FFXIVIpcMapMarkerN`) as single entries. After implementing size-specific registrations, we need to ensure each template *instantiation* is counted separately, or document that template families represent multiple logical packets.
