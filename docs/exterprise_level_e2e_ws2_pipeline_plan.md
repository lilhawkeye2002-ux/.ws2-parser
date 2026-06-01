# WS2 Python Parser — Enterprise E2E Plan (Forensic Edition)

---

## Context

Three parallel forensic agents analyzed: all 10 decompiled `.ws2.src` scripts (47 tool uses), all 90 PHP opcode handlers + infrastructure (99 tool uses), and the full binary format / FastBuffer / label system (50 tool uses). The findings expose **15 high-severity edge cases** in the PHP reference implementation that silently corrupt data, and document every byte layout, version branch, and exception condition for all 87 opcodes. This plan is built on those findings: no assumptions, no handwaving.

**Preconditions (confirmed):**
- OS: Amazon Linux 2023; Python 3 stdlib available
- Repo: `/home/vercel-sandbox/ws2-parser/` — git, pushed to GitHub
- Reference outputs: `/home/vercel-sandbox/ws2-parser/decompiled/*.ws2.src` (10 files, ground truth)
- Binary inputs: `/home/vercel-sandbox/*.ws2` (10 files)
- PHP reference tool: `/home/vercel-sandbox/advhd_ws2_tools/` (do not modify)

---

## FORENSIC FINDINGS — Non-Negotiable Edge Cases

Every item here was found by forensic agents and MUST be handled in the Python implementation. Each has a documented PHP behavior and the correct Python behavior.

### F-01: `readString()` Odd-Byte EOF — Silent Drop
- **PHP behavior**: Loop condition `offset + 1 < length` — if 1 byte remains at EOF, the loop exits without reading it. Offset stays at `length - 1`. Next `shift()` returns that orphaned byte as an opcode.
- **Python**: Raise `BufferUnderrunError(offset, "UTF-16LE string: odd byte at EOF")`. Never silently drop.

### F-02: `readFixedLengthString(n)` — Silent Truncation
- **PHP behavior**: If `n > remaining`, reads only `remaining` bytes and returns short string. `unpack('V', short_bytes)` then produces garbage values. No exception.
- **Python**: Raise `BufferUnderrunError(offset, f"need {n} bytes, {remaining} remain")` before any read.

### F-03: `shift()` at EOF — Null Return
- **PHP behavior**: Returns `null` at EOF. Callers receive `null` as a byte value, silently coercing to 0 in arithmetic.
- **Python**: Raise `BufferUnderrunError(offset, "shift() past end of buffer")`. No nullable returns.

### F-04: `current()` — No Bounds Check (peek)
- **PHP behavior**: Directly accesses `$buffer[$offset]` with no bounds check. Throws PHP notice/error if `offset >= length`.
- **Python**: `peek()` must check `remaining >= 1` before accessing. Raise `BufferUnderrunError` otherwise.

### F-05: `readData(0)` — Returns `None`, Not `[]`
- **PHP behavior**: `readData($dataSource, 0)` returns `null` (not empty array). Callers unpacking `[$a, $b] = readData(...)` will TypeError.
- **Python**: Always return `list[int]`. For `n=0`, return `[]`. Validate `n >= 0`.

### F-06: `empty($dataSource)` Bug — Truncation Never Caught
- **PHP behavior**: `empty()` on a PHP object is always `False`. The guard in `readData()` never fires. Truncated reads silently return `null` bytes in the result array.
- **Python**: After each `shift()` call inside a loop, check for underrun explicitly. The guard must use `self.remaining >= n` BEFORE the loop.

### F-07: FileEnd (0xFF) Does NOT Stop the Parse Loop
- **PHP behavior**: `FileEnd` is an ordinary opcode. The loop continues with `while totalSize > 0`. It stops only when `totalSize` reaches 0 or goes negative.
- **Python**: Must replicate exactly. Do not add special-case early termination on `0xFF`. If trailing bytes exist after FileEnd and `totalSize` is not yet 0, parse continues.

### F-08: Label Key = Raw Byte Offset (Not Sequential)
- **PHP behavior**: `$labels[$pointerId]` where `$pointerId` is the raw DWord value from the jump instruction (e.g., byte offset 4651). Label name is `@LABEL_4651`.
- **Python**: `label_map: dict[int, str]` keyed by raw byte offset. `label_name = f"@LABEL_{offset}"`.

### F-09: Jump to Offset 0 is Valid
- **PHP behavior**: `processLabels()` explicitly handles `position=0` as first label check.
- **Python**: Must insert `@LABEL_0` at the very start of the output list if any jump targets offset 0.

### F-10: Unresolved Jump Target → Exception
- **PHP behavior**: If any label registered during parsing is never matched during `processLabels()`, throws `Exception('Not all labels are cleared')`.
- **Python**: After label injection pass, if `label_map` is non-empty, raise `UnresolvedLabelError(list(label_map.keys()))`.

### F-11: Decryption Transforms Opcodes
- **PHP behavior**: ROR-2 applied byte-by-byte to entire file before parsing. `0x01 → 0x40`, `0x40 → 0x01`. The 158KB `00_scn002h.ws2` starts with `0x01` (Condition) unencrypted; if it were encrypted, `0x01` would decrypt to `0x40` (ClearLayer) — completely different opcode.
- **Python**: `decrypt(b) = (b >> 2) | ((b << 6) & 0xFF)`. Apply to full byte array BEFORE creating `FastBuffer`. Implement auto-detect heuristic: if first byte not in `OPCODE_TABLE`, try decrypt and re-check.

### F-12: Version Comparisons — Float Precision
- **PHP behavior**: Version stored as `float(1.06)`. IEEE 754 stores `1.06` as `1.0599999999999998...`. Comparison `$v > 1.06` evaluates against this imprecise representation.
- **Python**: Use `Decimal` or define exact threshold constants:
  ```python
  V_1_0  = Decimal('1.0')
  V_1_06 = Decimal('1.06')
  V_1_4  = Decimal('1.4')
  V_1_9  = Decimal('1.9')
  ```
  Accept version as string `'1.9'`, convert to `Decimal` once at startup.

### F-13: Empty String Quoting Inconsistency
- **PHP behavior**: `SetDisplayName` → `''` (quoted empty). `DisplayMessage` layer/message → unquoted empty (just `,  ,`). This inconsistency is in the reference output and must be reproduced exactly.
- **Python**: Per-opcode formatting rules. `src` formatter must replicate these rules exactly to pass diff verification.

### F-14: `compiledSize` Includes the Opcode Byte
- **PHP behavior**: `getCompiledSize() = 1 + getSize()`. The `1` is always the opcode byte. `Unk00` has `getSize()=0` but `getCompiledSize()=1`.
- **Python**: `OpcodeNode.compiled_size = 1 + payload_bytes`. This is what's subtracted from `total_size` in the parse loop.

### F-15: `processLabels()` Insert-After, Not Insert-Before
- **PHP behavior**: In the walk, position is incremented by `opcode.compiledSize` AFTER appending the opcode. Then the label check happens. So labels appear **after** the opcode that causes the position to match.
- **Python**: Must mirror: append opcode → add compiled_size to position → check label_map → if match, append label string.

---

## Forensic Data: Opcode Frequency in Reference Corpus

From Agent 1 analysis of all 10 files (total ~6,600 lines):

| Opcode | Name | Count | Notes |
|--------|------|-------|-------|
| 0x14 | DisplayMessage | ~850 | Highest frequency |
| 0x15 | SetDisplayName | ~600 | Always paired |
| 0x09 | LayerConfig | ~1,080 | Layer 0 dominates |
| 0x33 | SetBackground | ~450 | |
| 0x46 | MoveBackground | ~380 | 95% all-zero coords |
| 0x00 | Unk00 | 328 | NOP separator |
| 0x64 | Unk64 | 228 | Always 1-byte=0 |
| 0x65 | C65 | ~228 | Fade control |
| 0x47 | Effect1 | 152 | |
| 0x57 | UnkBackground1 | 79 | |
| 0x16 | Unk16 | 89 | |
| 0x28 | SoundEffect | ~70 | |
| 0x29 | SoundUnk1 | 58 | |
| 0x0B | SetFlag | 90 | IDs 1081–1636, always value=1 |
| 0x01 | Condition | ~400 | Mostly simple (configValue 1 or 0) |
| 0x0F | ShowChoice | 3 | 2-3 options each |
| 0x06 | Jump | 1 | Single file |
| 0xE6 | ConditionalJump | ~15 | |
| 0xFF | FileEnd | 10 | One per file |
| 0x67 | Unk67 | 27 | Haptic; concentrated in 002h event scene |

**Single-occurrence opcodes in corpus:** `Jump (0x06)`, `Effect3 (0x58)` — least tested paths.

**Condition configValues seen:** `1` (simple, majority), `2` (extended with extra 14 bytes), `3` (with peek), `128`/`129`/`130`/`192` (extended). Config `999` used in ExecuteFunction GetMsgSkip calls.

**ShowChoice sub-opcodes seen:** Both `6` (DWord pointer) and `7` (filename string) confirmed in reference corpus.

---

## Package Architecture

```
ws2-parser/
├── ws2parse.py                         ← entry-point shim (6 lines)
├── ws2parse/
│   ├── __init__.py                     ← version = '1.0.0'
│   ├── cli.py                          ← argparse, exit codes
│   ├── pipeline.py                     ← 6-stage orchestrator
│   ├── errors.py                       ← all exception classes
│   ├── reader.py                       ← FastBuffer + type readers
│   ├── labels.py                       ← label injection algorithm
│   ├── opcodes/
│   │   ├── __init__.py
│   │   ├── registry.py                 ← OPCODE_TABLE dict[int, handler_fn]
│   │   └── handlers.py                 ← all 87 handler functions
│   └── formatters/
│       ├── __init__.py
│       ├── src.py                      ← exact PHP-compatible .ws2.src output
│       ├── json_fmt.py                 ← structured JSON
│       └── text.py                     ← dialogue-only extraction
└── docs/
    ├── FORMAT_SPEC.md
    ├── OPCODE_REFERENCE.md
    └── NFR.md
```

---

## Module 1: `ws2parse/errors.py`

Every exception the parser can raise. No bare `Exception` raises anywhere else.

```python
class WS2ParseError(Exception):
    """Base class. All errors carry file_path and byte_offset."""
    def __init__(self, msg, file_path=None, offset=None): ...

class BufferUnderrunError(WS2ParseError):
    """Raised when a read would exceed buffer bounds."""
    # Covers F-01, F-02, F-03, F-04

class UnknownOpcodeError(WS2ParseError):
    """Raised when opcode byte not in OPCODE_TABLE."""
    def __init__(self, opcode_byte: int, offset: int, file_path=None): ...

class UnknownSubOpcodeError(WS2ParseError):
    """ShowChoice: opJump not in {6, 7}."""

class ParseIntegrityError(WS2ParseError):
    """type>0 in DisplayMessage, config>0 in SetDisplayName."""

class UnresolvedLabelError(WS2ParseError):
    """processLabels: label_map non-empty after walk. Covers F-10."""
    def __init__(self, unresolved_offsets: list[int]): ...

class VersionError(WS2ParseError):
    """Version string not in {'1.0','1.06','1.4','1.9'}."""

class DecryptionError(WS2ParseError):
    """File decryption produced no valid opcodes."""

class CompiledSizeMismatchError(WS2ParseError):
    """total_size went negative (over-read). Internal invariant violation."""
```

---

## Module 2: `ws2parse/reader.py`

### `class FastBuffer`

```python
class FastBuffer:
    def __init__(self, data: bytes, file_path: str = ""):
        self._buf  = data           # immutable bytes
        self._off  = 0
        self._len  = len(data)
        self._path = file_path

    @property
    def offset(self) -> int: return self._off

    @property
    def remaining(self) -> int: return self._len - self._off

    def shift(self) -> int:
        # F-03: raise, never return None
        if self._off >= self._len:
            raise BufferUnderrunError("shift() past EOF", self._path, self._off)
        b = self._buf[self._off]; self._off += 1; return b

    def peek(self, n: int = 1) -> bytes:
        # F-04: bounds check before access
        if self._off + n > self._len:
            raise BufferUnderrunError(f"peek({n}) past EOF", self._path, self._off)
        return self._buf[self._off : self._off + n]

    def read(self, n: int) -> bytes:
        # F-02: explicit check before read
        if self._off + n > self._len:
            raise BufferUnderrunError(
                f"read({n}): need {n} bytes, {self.remaining} remain",
                self._path, self._off)
        chunk = self._buf[self._off : self._off + n]
        self._off += n
        return chunk

    def read_string(self) -> str:
        # F-01: odd-byte EOF raises, not silently drops
        start = self._off
        chars = []
        while True:
            if self._off + 2 > self._len:
                # F-01 condition: odd byte or truncated string
                raise BufferUnderrunError(
                    f"read_string(): UTF-16LE string not null-terminated before EOF "
                    f"(started at {start})",
                    self._path, self._off)
            lo = self._buf[self._off]
            hi = self._buf[self._off + 1]
            self._off += 2
            if lo == 0 and hi == 0:   # null terminator consumed (F-02 confirmed)
                break
            codepoint = lo | (hi << 8)
            chars.append(chr(codepoint))
        return ''.join(chars)

    def read_string_with_len(self) -> tuple[str, int]:
        """Returns (utf8_str, bytes_consumed_including_terminator)."""
        start = self._off
        s = self.read_string()
        return s, self._off - start
```

### Type Readers (module-level functions, take `FastBuffer`)

```python
def read_byte(buf: FastBuffer) -> int:
    return buf.shift()

def read_word(buf: FastBuffer) -> int:
    """2-byte LE uint16."""
    return struct.unpack_from('<H', buf.read(2))[0]

def read_dword(buf: FastBuffer) -> int:
    """4-byte LE uint32."""
    return struct.unpack_from('<I', buf.read(4))[0]

def read_float(buf: FastBuffer) -> float:
    """4-byte LE IEEE 754. NaN/Inf preserved; caller responsible for JSON safety."""
    return struct.unpack_from('<f', buf.read(4))[0]

def read_string(buf: FastBuffer) -> str:
    return buf.read_string()

def read_string_with_len(buf: FastBuffer) -> tuple[str, int]:
    return buf.read_string_with_len()

def read_data(buf: FastBuffer, n: int) -> list[int]:
    """F-05: always returns list. n=0 returns []."""
    if n < 0:
        raise ValueError(f"read_data: n must be >= 0, got {n}")
    if n == 0:
        return []
    # F-06: check before loop, not inside loop with broken guard
    if buf.remaining < n:
        raise BufferUnderrunError(
            f"read_data({n}): need {n} bytes, {buf.remaining} remain",
            "", buf.offset)
    return [buf.shift() for _ in range(n)]
```

### Decryption

```python
def decrypt_file(data: bytes) -> bytes:
    """ROR-2 byte rotation. Applied to entire file before parsing (F-11).
    decrypt(0x01)=0x40, decrypt(0x00)=0x00, decrypt(0xFF)=0xFF."""
    return bytes(((b >> 2) | ((b << 6) & 0xFF)) for b in data)

def auto_detect_decrypt(data: bytes, opcode_table: set[int]) -> tuple[bytes, bool]:
    """Returns (data, was_decrypted).
    Tries plain first; if first byte not in opcode_table, tries decryption."""
    if data and data[0] in opcode_table:
        return data, False
    decrypted = decrypt_file(data)
    if decrypted and decrypted[0] in opcode_table:
        return decrypted, True
    # Neither worked; return plain and let parse fail with proper error
    return data, False
```

---

## Module 3: `ws2parse/labels.py`

Exact port of PHP `processLabels()` algorithm (F-08, F-09, F-10, F-15).

```python
@dataclass
class LabelNode:
    name: str   # "@LABEL_4651"

def inject_labels(
    opcodes: list[OpcodeNode],
    label_map: dict[int, str]   # {byte_offset: "@LABEL_N"}
) -> list[OpcodeNode | LabelNode]:
    """
    Exact port of PHP processLabels():
    - Check position=0 FIRST (F-09)
    - Walk opcodes; position += compiled_size AFTER appending opcode (F-15)
    - Append label string AFTER the opcode that causes position to match
    - After walk, if label_map non-empty → UnresolvedLabelError (F-10)
    """
    remaining = dict(label_map)
    result: list[OpcodeNode | LabelNode] = []
    position = 0

    # F-09: check for label at offset 0 before first opcode
    if 0 in remaining:
        result.append(LabelNode(remaining.pop(0)))

    for op in opcodes:
        result.append(op)
        position += op.compiled_size   # F-14: compiled_size includes opcode byte
        if position in remaining:
            result.append(LabelNode(remaining.pop(position)))

    # F-10: any unresolved labels = error
    if remaining:
        raise UnresolvedLabelError(sorted(remaining.keys()))

    return result

def register_label(label_map: dict[int, str], offset: int) -> None:
    """Called during parse when a jump target is encountered.
    F-08: key is raw byte offset."""
    if offset not in label_map:
        label_map[offset] = f"@LABEL_{offset}"
```

---

## Module 4: `ws2parse/opcodes/registry.py`

```python
from decimal import Decimal

KNOWN_VERSIONS = {'1.0', '1.06', '1.4', '1.9'}

# Version thresholds as Decimal (F-12: no float precision issues)
V_1_0  = Decimal('1.0')
V_1_06 = Decimal('1.06')
V_1_4  = Decimal('1.4')
V_1_9  = Decimal('1.9')

@dataclass
class OpcodeNode:
    func: str                    # e.g. 'DisplayMessage'
    params: list                 # ordered parsed values
    compiled_size: int           # 1 + payload_bytes (F-14)
    raw_pointers: list[int]      # raw byte-offset jump targets (for label registration)

# Populated in handlers.py
OPCODE_TABLE: dict[int, Callable] = {}

def dispatch(opcode: int, buf: FastBuffer, version: Decimal,
             label_map: dict[int, str]) -> OpcodeNode:
    handler = OPCODE_TABLE.get(opcode)
    if handler is None:
        raise UnknownOpcodeError(opcode, buf.offset)
    return handler(buf, version, label_map)
```

---

## Module 5: `ws2parse/opcodes/handlers.py`

All 87 opcode handlers. Exact byte layouts from forensic analysis. Every handler is a function `def h_NAME(buf, version, label_map) -> OpcodeNode`.

### Version Gate Helper

```python
def v_gt(version: Decimal, threshold: Decimal) -> bool:
    """Exact greater-than comparison. No float arithmetic (F-12)."""
    return version > threshold
```

### Critical Handlers (full specs)

**`0x00 — Unk00` (NOP)**
```
payload_bytes = 0
params = []
compiled_size = 1   # F-14: opcode byte only
```

**`0x01 — Condition`**
```
1. config = read_byte()              # 1 byte
extended = False
2. if config in {2, 128, 129, 130, 192}:
       extended = True
   elif config == 3:
       peek_byte = buf.peek(1)[0]    # F-04: peek, not consume
       if peek_byte in {50, 51, 127, 128}:
           extended = True
3. if extended:
       global_id = read_word()       # 2 bytes
       block_id  = read_float()      # 4 bytes
       ptr1      = read_dword()      # 4 bytes
       ptr2      = read_dword()      # 4 bytes
       register_label(label_map, ptr1) if ptr1 != 0
       register_label(label_map, ptr2) if ptr2 != 0
       raw_pointers = [ptr1, ptr2]
       params = [config, global_id, block_id, ptr1, ptr2]
       payload_bytes = 1 + 2 + 4 + 4 + 4 = 15
   else:
       params = [config]
       payload_bytes = 1
compiled_size = 1 + payload_bytes
```

**`0x02 — Jump2`**
```
target = read_dword()                # 4 bytes
register_label(label_map, target)
params = [target]
compiled_size = 5
```

**`0x04 — RunFile`**
```
s, slen = read_string_with_len()
params = [s]
compiled_size = 1 + slen
```

**`0x06 — Jump`**
```
target = read_dword()                # 4 bytes
register_label(label_map, target)
params = [target]
compiled_size = 5
```

**`0x07 — NextFile`**
```
s, slen = read_string_with_len()
params = [s]
compiled_size = 1 + slen
```

**`0x09 — LayerConfig`**
```
b0 = read_byte(); b1 = read_byte(); b2 = read_byte()
f  = read_float()
params = [b0, b1, b2, f]
compiled_size = 1 + 3 + 4 = 8
```

**`0x0B — SetFlag`**
```
flag_id = read_word()                # 2 bytes
value   = read_byte()                # 1 byte
params = [flag_id, value]
compiled_size = 4
# Seen in corpus: flag IDs 1081-1636, value always 1
```

**`0x0F — ShowChoice`**
```
count = read_byte()                  # 1 byte; can be 0 (F-05 style)
choices = []
payload_bytes = 1
for _ in range(count):
    choice_id  = read_word()         # 2 bytes
    text, tlen = read_string_with_len()  # variable
    op1 = read_byte(); op2 = read_byte()
    op3 = read_byte(); op_jump = read_byte()  # 4 bytes
    payload_bytes += 2 + tlen + 4
    if op_jump == 6:
        ptr = read_dword()           # 4 bytes
        register_label(label_map, ptr)
        choice_ptr = ptr
        payload_bytes += 4
    elif op_jump == 7:
        fn, flen = read_string_with_len()  # variable
        choice_ptr = fn
        payload_bytes += flen
    else:
        raise UnknownSubOpcodeError(
            f"ShowChoice: opJump={op_jump} not in {{6,7}}", buf.offset)
    choices.append((choice_id, text, op1, op2, op3, op_jump, choice_ptr))
params = [count, choices]
compiled_size = 1 + payload_bytes
```

**`0x11 — SetTimer`**
```
name, nlen = read_string_with_len()
payload = nlen
if v_gt(version, V_1_4):
    extra = read_byte()              # 1 byte
    payload += 1
f = read_float()                     # 4 bytes
payload += 4
params = [name, f] if not v_gt else [name, extra, f]
compiled_size = 1 + payload
```

**`0x14 — DisplayMessage`**
```
msg_id   = read_dword()              # 4 bytes
layer, ll  = read_string_with_len()  # variable
message, ml = read_string_with_len() # variable
payload = 4 + ll + ml
if v_gt(version, V_1_06):
    type_byte = read_byte()          # 1 byte
    payload += 1
    if type_byte != 0:
        raise ParseIntegrityError(
            f"DisplayMessage id={msg_id}: type_byte={type_byte} != 0", buf.offset)
    params = [msg_id, layer, type_byte, message]
else:
    params = [msg_id, layer, message]
compiled_size = 1 + payload
# EMPTY STRING NOTE (F-13): layer='' and message='' both valid
```

**`0x15 — SetDisplayName`**
```
name, nlen = read_string_with_len()  # variable; can be '' (2 bytes)
payload = nlen
if v_gt(version, V_1_06):
    config = read_byte()             # 1 byte
    payload += 1
    if config != 0:
        raise ParseIntegrityError(
            f"SetDisplayName: config={config} != 0", buf.offset)
    params = [config, name]
else:
    params = [name]
compiled_size = 1 + payload
```

**`0x16 — Unk16`**
```
b0 = read_byte()
payload = 1
if v_gt(version, V_1_06):
    b1 = read_byte()
    payload += 1
    params = [b0, b1]
else:
    params = [b0]
compiled_size = 1 + payload
```

**`0x19 — Unk19`**
```
payload = 0
if v_gt(version, V_1_4):
    b0 = read_byte(); b1 = read_byte(); b2 = read_byte()
    params = [b0, b1, b2]
    payload = 3
else:
    params = []
compiled_size = 1 + payload
```

**`0x1C — ExecuteFunction`**
```
fn,  fl = read_string_with_len()
arg, al = read_string_with_len()
payload = fl + al
if v_gt(version, V_1_0):
    extra = read_data(buf, 3)        # 3 bytes
    payload += 3
else:
    extra = read_data(buf, 2)        # 2 bytes
    payload += 2
params = [fn, arg, *extra]
compiled_size = 1 + payload
```

**`0x1E — PlayMusic`**
```
ch,  cl = read_string_with_len()
fn,  fl = read_string_with_len()
payload = cl + fl
base_bytes = 13 if not v_gt(version, V_1_06) else 17
tail = read_data(buf, base_bytes)
payload += base_bytes
params = [ch, fn, *tail]
compiled_size = 1 + payload
```

**`0x28 — SoundEffect`**
```
ch,  cl = read_string_with_len()
fn,  fl = read_string_with_len()
payload = cl + fl
# 2 floats always
f0 = read_float(); f1 = read_float()
payload += 8
base_bytes = 10 if not v_gt(version, V_1_06) else 14
tail = read_data(buf, base_bytes)
payload += base_bytes
params = [ch, fn, f0, f1, *tail]
compiled_size = 1 + payload
```

**`0x39 — DisplayCharacterImage`**
```
name, nl = read_string_with_len()
b0 = read_byte(); b1 = read_byte(); b2 = read_byte()
# b2 is the count of word values to follow
words = [read_word() for _ in range(b2)]
payload = nl + 3 + 2 * b2
params = [name, b0, b1, b2, *words]
compiled_size = 1 + payload
```

**`0x3F — LayersList`**
```
count = read_byte()
names = []
payload = 1
for _ in range(count):
    s, slen = read_string_with_len()
    names.append(s)
    payload += slen
params = [count, *names]
compiled_size = 1 + payload
```

**`0x45 — DragBackground`**
```
ch, cl = read_string_with_len()
b0 = read_byte(); b1 = read_byte()
f0 = read_float(); f1 = read_float(); f2 = read_float(); f3 = read_float()
payload = cl + 2 + 16
params = [ch, b0, b1, f0, f1, f2, f3]
compiled_size = 1 + payload
```

**`0x46 — MoveBackground`**
```
ch, cl = read_string_with_len()
b0 = read_byte(); b1 = read_byte(); b2 = read_byte()
f0 = read_float(); f1 = read_float(); f2 = read_float(); f3 = read_float()
payload = cl + 3 + 16
params = [ch, b0, b1, b2, f0, f1, f2, f3]
compiled_size = 1 + payload
```

**`0x47 — Effect1`**
```
ch,   cl = read_string_with_len()
eff,  el = read_string_with_len()
b0, b1, b2, b3 = read_data(buf, 4)
f0 = read_float(); f1 = read_float(); f2 = read_float()
f3 = read_float(); f4 = read_float(); f5 = read_float()
b4 = read_byte(); b5 = read_byte()
payload = cl + el + 4 + 24 + 2
params = [ch, eff, b0, b1, b2, b3, f0, f1, f2, f3, f4, f5, b4, b5]
compiled_size = 1 + payload
```

**`0x48 — Effect2`**
```
ch,   cl = read_string_with_len()
eff,  el = read_string_with_len()
b0, b1, b2, b3, b4 = read_data(buf, 5)
payload = cl + el + 5
params = [ch, eff, b0, b1, b2, b3, b4]
compiled_size = 1 + payload
```

**`0x56 — RainStart` (most complex)**
```
s0, s0l = read_string_with_len()
cfg = read_data(buf, 7)
floats = [read_float() for _ in range(10)]
ints   = [read_dword()  for _ in range(5)]
s1, s1l = read_string_with_len()
s1_cfg  = read_data(buf, 2)
s2, s2l = read_string_with_len()
s3, s3l = read_string_with_len()
s3_cfg  = read_data(buf, 4)
payload = s0l + 7 + 40 + 20 + s1l + 2 + s2l + s3l + 4
params = [s0, *cfg, *floats, *ints, s1, *s1_cfg, s2, s3, *s3_cfg]
compiled_size = 1 + payload
```

**`0x65 — C65`**
```
b0 = read_byte(); b1 = read_byte(); b2 = read_byte()
f0 = read_float(); f1 = read_float()
b3 = read_byte(); b4 = read_byte()
payload = 3 + 8 + 2 = 13
params = [b0, b1, b2, f0, f1, b3, b4]
compiled_size = 14
# Corpus: b0 ∈ {0,100}, f0 ∈ {0.25,0.5,1.0,2.0,...}, b3 always 2 or 0
```

**`0xE6 — ConditionalJump`**
```
ptr1 = read_dword(); ptr2 = read_dword()
register_label(label_map, ptr1)
register_label(label_map, ptr2)
params = [ptr1, ptr2]
compiled_size = 9
```

**`0xF0 — UnkScreen`**
```
b0 = read_byte()
payload = 1
if buf.remaining > 2:            # original PHP condition verbatim
    f = read_float()
    d0 = read_dword(); d1 = read_dword()
    payload += 12
    params = [b0, f, d0, d1]
else:
    params = [b0]
compiled_size = 1 + payload
```

**`0xFF — FileEnd`**
```
some_id  = read_dword()          # 4 bytes
cfg      = read_data(buf, 4)     # 4 bytes
params   = [some_id, *cfg]
compiled_size = 9
# F-07: loop continues after FileEnd until total_size <= 0
# Corpus FileEnd param2 flags: 0=normal, 128=special, 192=choice
```

### All Remaining Handlers (flat-layout opcodes)

```
0x05 Unk05:          payload=0, params=[]
0x08 Unk08:          payload=1, params=[read_byte()]
0x0A Unk0A:          payload=22, params=read_data(22)
0x0D Unk0D:          payload=8,  params=read_data(8)
0x0E Unk0E:          payload=5,  params=read_data(5)
0x12 StartTimer:     payload=nlen+2, params=[name, b0, b1]
0x13 Unk13:          payload=9,  params=read_data(9)
0x17 Unk17:          payload=1,  params=[read_byte()]
0x18 AddMessageToLog: payload=1+nlen, params=[read_byte(), msg]
0x1A OpenTitle:       payload=nlen, params=[name]
0x1B Unk1B:          payload=1,  params=[read_byte()]
0x1D Unk1D:          payload=2,  params=read_data(2)
0x1F StopMusic:       payload=clen+4, params=[ch, read_float()]
0x20 MusicUnk1:       payload=clen+4+2, params=[ch, read_float(), read_word()]
0x29 SoundUnk1:       payload=clen+4, params=[ch, read_float()]
0x2A SoundUnk2:       payload=clen+4+2, params=[ch, read_float(), b0, b1]
0x2E CharMessageStart: payload=0, params=[]
0x32 VariableUnk32:   payload=nlen, params=[name]
0x33 SetBackground:   payload=n1len+n2len, params=[n1, n2]
0x34 UsePnaPackage:   payload=n1len+n2len+2, params=[n1, n2, read_word()]
0x35 PlayMovie:       payload=n1len+n2len+3, params=[n1, n2, *read_data(3)]
0x36 PrepareBackgroundArea: payload=nlen+28+2, params=[name, *7_floats, *read_data(2)]
0x37 ClearLayer:      payload=nlen, params=[name]
0x38 VariableUnk3:    payload=nlen+1, params=[name, read_byte()]
0x3A UnkBackground2:  payload=nlen+2, params=[name, *read_data(2)]
0x3B BackgroundMessage: payload=n1len+n2len+2+4+32, params=[n1,n2,read_word(),read_dword(),*8_floats]
0x3D Unk3D:           payload=2, params=read_data(2)
0x3E Unk3E:           payload=0, params=[]
0x40 SetMask:         payload=n1len+n2len+1, params=[n1, n2, read_byte()]
0x41 UnkBackground3:  payload=nlen+1, params=[name, read_byte()]
0x42 Unk42:           payload=nlen+2, params=[name, *read_data(2)]
0x43 Unk43:           payload=nlen, params=[name]
0x44 Effect44:        payload=n1len+n2len+1, params=[n1, n2, read_byte()]
0x4A Unk4A:           payload=n1len+n2len, params=[n1, n2]
0x51 VariableUnk51:   payload=n1len+n2len+7, params=[n1, n2, *read_data(7)]
0x52 VariableUnk2:    payload=n1len+n2len+4+7+n3len, params=[n1, n2, read_float(), *read_data(7), n3]
0x53 VariableUnk4:    payload=n1len+n2len, params=[n1, n2]
0x57 UnkBackground1:  payload=nlen+2, params=[name, *read_data(2)]
0x58 Effect3:         payload=n1len+n2len, params=[n1, n2]
0x5B InitKeyName:     payload=nlen+2+1, params=[name, read_word(), read_byte()]
0x5C RainEnd:         payload=nlen, params=[name]
0x64 Unk64:           payload=1, params=[read_byte()]
0x66 ShowGraphic:     payload=nlen, params=[name]
0x67 Unk67:           payload=4+20+1=25, params=[*read_data(4), *5_floats, read_byte()]
0x68 Unk68:           payload=1, params=[read_byte()]
0x6E SetVariable:     payload=n1len+n2len, params=[n1, n2]
0x6F VariableUnk:     payload=nlen, params=[name]
0x73 SetPnaFile:      payload=n1len+n2len+2, params=[n1, n2, read_word()]
0x75 Unk75:           payload=n1len+n2len, params=[n1, n2]
0x78 Unk78:           payload=n1len+n2len+3, params=[n1, n2, *read_data(3)]
0x7A Unk7A:           payload=n1len+n2len+4+3, params=[n1, n2, read_float(), *read_data(3)]
0x7B Unk7B:           payload=n1len+n2len, params=[n1, n2]
0x84 Unk84:           payload=n1len+n2len+n3len+4+2+4, params=[n1, n2, n3, read_float(), *read_data(2), read_float()]
0x97 Unk97:           payload=3+16, params=[*read_data(3), *4_floats]
0xFB UnkFB:           payload=1, params=[read_byte()]
0xFC UnkFC:           payload=2, params=read_data(2)
0xFD UnkFD:           payload=0, params=[]
```

---

## Module 6: `ws2parse/pipeline.py`

### `ParseResult` datatype

```python
@dataclass
class ParseResult:
    path: Path
    script: list[OpcodeNode | LabelNode]  # after label injection
    version: Decimal
    was_decrypted: bool
    errors: list[WS2ParseError]           # non-fatal warnings
    bytes_consumed: int                   # total bytes processed
    total_size_final: int                 # should be 0; negative = over-read warning
```

### Pipeline Stages

```python
def run_pipeline(
    inputs: list[Path],
    version: str,
    decrypt: bool | None,    # None = auto-detect
    fmt: Literal['src','json','text'],
    out_dir: Path,
    strict: bool,
    verbose: bool,
) -> list[ParseResult]:
```

**Stage 1 — Discover**: Resolve each input. If directory, `rglob('*.ws2')`. Validate files exist and are readable. Collect `list[Path]`.

**Stage 2 — Load**: Read raw bytes. Check `len(data) > 0`.

**Stage 3 — Decrypt**:
- If `decrypt=True`: apply `decrypt_file(data)`
- If `decrypt=False`: use plain
- If `decrypt=None` (auto): call `auto_detect_decrypt(data, OPCODE_TABLE)`
- Log warning if auto-detect chose decryption

**Stage 4 — Parse**:
```python
def parse(data: bytes, version: Decimal, file_path: str) -> tuple[list[OpcodeNode], dict[int,str], int]:
    buf = FastBuffer(data, file_path)
    opcodes = []
    label_map = {}
    total_size = buf.remaining   # F-07: loop driven by byte count

    while total_size > 0:
        opcode_byte = buf.shift()  # consumes 1 byte
        total_size -= 1
        node = dispatch(opcode_byte, buf, version, label_map)
        opcodes.append(node)
        payload_consumed = node.compiled_size - 1
        total_size -= payload_consumed
        if total_size < 0:
            # CompiledSizeMismatchError (invariant violation)
            raise CompiledSizeMismatchError(
                f"opcode 0x{opcode_byte:02X} at {buf.offset}: "
                f"total_size went to {total_size}")

    # Label injection (F-15 algorithm)
    script = inject_labels(opcodes, label_map)
    return script, total_size
```

**Stage 5 — Format**: Call selected formatter with `ParseResult.script`. Returns string.

**Stage 6 — Write**:
- Filename: `<out_dir>/<stem>.ws2.src` / `.json` / `.txt`
- Always write partial output even on error (F-07 style: write what was parsed before error)
- `out_dir` created if not exists

**Stage 7 — Report**: Print summary to stdout. One line per file: `OK 00_scn002h.ws2 (5983 lines, 158644 bytes)` or `ERROR 00_scn002h.ws2 @ byte 0x4A2F: ...`

---

## Module 7: `ws2parse/cli.py`

```
python ws2parse.py [OPTIONS] <input> [<input>...]

Arguments:
  <input>   File or directory. Directories searched recursively for *.ws2.

Options:
  --version {1.0,1.06,1.4,1.9}    Format version (default: 1.9)
  --decrypt                         Force ROR-2 decryption (default: auto)
  --no-decrypt                      Disable decryption even if auto would choose it
  --format  {src,json,text}         Output format (default: src)
  --out DIR                         Output directory (default: same dir as input)
  --strict                          Abort file on first unknown opcode (default: warn+placeholder)
  --verbose / -v                    Per-opcode progress to stderr
  --quiet  / -q                     Suppress non-error output
  --version-info                    Print 'ws2parse 1.0.0' and exit

Exit codes:
  0  All files parsed without errors
  1  One or more files had parse errors (partial output written)
  2  Fatal: bad arguments, unreadable input, config error

Error format:
  ERROR <file>:<hex_offset> — opcode 0x<XX> (<name>): <message>
  e.g.: ERROR 00_scn002h.ws2:0x4a2f — opcode 0x0f (ShowChoice): opJump=5 not in {6,7}

Progress (--verbose):
  [  1/10] 00_SCN001A.ws2        ... OK  (34075 bytes, 0.42s)
  [  2/10] 00_scn002h.ws2        ... OK (158644 bytes, 0.97s)
```

---

## Module 8: `ws2parse/formatters/src.py`

### Line Numbering

Format: `{n:>6}→{content}` where `n` is the 1-based line counter.

```python
def format_line(n: int, content: str) -> str:
    return f"{n:6}→{content}"
```

### Opcode Formatting Rules

Each rule derived from exact PHP `$this->content` assignment inspection:

| Opcode | Format Rule |
|--------|-------------|
| Unk00 | `Unk00` (standalone, no parens) |
| Condition (simple) | `Condition ({config})` |
| Condition (extended) | `Condition ({config}, {global_id}, {block_id:.8f}, {@LABEL_ptr1}, {@LABEL_ptr2})` |
| Jump | `Jump ({@LABEL_target})` |
| Jump2 | `Jump2 ({@LABEL_target})` |
| ConditionalJump | `ConditionalJump ({@LABEL_ptr1}, {@LABEL_ptr2})` |
| DisplayMessage | Multi-line: `DisplayMessage ({msg_id}, {layer}, {type}\n{message}\n);` |
| SetDisplayName | `SetDisplayName ({config}, '{name}')` — empty name → `''` (F-13) |
| ShowChoice | Multi-line (see below) |
| SetFlag | `SetFlag ({flag_id}, {value})` |
| LayerConfig | `LayerConfig ({b0}, {b1}, {b2}, {f:.{prec}f})` |
| MoveBackground | `MoveBackground ({ch}, {b0}, {b1}, {b2}, {f0}, {f1}, {f2}, {f3})` |
| C65 | `C65 ({b0}, {b1}, {b2}, {f0}, {f1}, {b3}, {b4})` |
| FileEnd | `FileEnd ({some_id}, {c0}, {c1}, {c2}, {c3})` |
| SoundEffect | `SoundEffect ({ch}, {fn}, {f0}, {f1}, {t0}, {t1}, ..., {tn})` |

**Float formatting**: Output floats with minimum digits to round-trip: `f"{v:g}"` which produces `0.25` not `0.25000000596046`. BUT for exact PHP compatibility, compare each value: if the PHP output has `0.15000000596046`, that was a float32 precision artifact. Python `struct.unpack('<f', ...)` + `repr()` will produce the same artifact naturally if `{v!r}` is used. **Rule**: use `repr(v)` for floats to match PHP's `(float)` cast behavior exactly.

**ShowChoice multi-line format**:
```
ShowChoice ({count}
{choice_id}, {op1}, {op2}, {op3}, {op_jump}, {ptr_or_name}
{text}
...
);
```

**Labels**: Rendered as standalone lines: `@LABEL_4651`

**Empty string rules (F-13)**:
- `DisplayMessage` layer param = `''` in PHP becomes `, ,` in output (no quotes, just comma)
- `SetDisplayName` name = `''` becomes `''` (two single quotes)
- All other string params: bare value (no quotes)

### Line Counter

- Labels and multi-line opcode body lines each increment the counter
- The counter is global across the entire file, 1-indexed

---

## Module 9: `ws2parse/formatters/json_fmt.py`

```json
{
  "file": "00_scn002h.ws2",
  "version": "1.9",
  "was_decrypted": false,
  "bytes_parsed": 158644,
  "opcodes": [
    {
      "line": 1,
      "offset": 0,
      "func": "Condition",
      "params": [2, 127, 1.0, 4651, 4700],
      "labels_before": ["@LABEL_0"],
      "compiled_size": 16
    }
  ]
}
```

**NaN/Inf handling**: `math.isfinite(v)` check; non-finite floats serialized as `null` with a `"_float_special": "NaN"` sibling key.

---

## Module 10: `ws2parse/formatters/text.py`

Dialogue extraction only. Tracks `current_speaker` via `SetDisplayName`. Outputs:

```
[Mao] I've kinda gotten used to it already, I guess.
[Chris] Heh～ Really? It sure doesn't look that way to me.
[narrator] In truth, I hadn't adjusted at all...
```

- `SetDisplayName (0, '')` → speaker = `[narrator]`
- `SetDisplayName (0, '%LFMao')` → speaker = `[Mao]` (strip `%LF` prefix)
- Only `DisplayMessage` with `layer == 'char'` emitted
- `%K%P` stripped from message body
- `「...」` Japanese brackets preserved

---

## SSOT Document 1: `docs/FORMAT_SPEC.md`

**Sections (complete, no handwaving):**

1. **Overview** — AdvHD engine; WS2 = Windows Script 2; version history 1.0→1.9
2. **File Structure** — No magic bytes; first byte is opcode; terminates at FileEnd or EOF; no global header
3. **Primitive Types Table**
   ```
   byte    1-byte unsigned integer (0–255)
   word    2-byte LE uint16 (0–65535)
   dword   4-byte LE uint32 (0–4294967295)
   float   4-byte LE IEEE 754 single (NaN/Inf possible)
   wstr    UTF-16LE null-terminated: 2-byte units until {00 00}
             consumed bytes = 2 × (char_count + 1)
             decode: each pair → codepoint = lo | (hi<<8) → UTF-8
   ```
4. **String Encoding** — UTF-16LE; Basic Multilingual Plane only (PHP has no surrogate pair handling; Python decoder handles surrogates via `errors='surrogatepass'` if needed)
5. **Decryption** — ROR-2: `b = (b >> 2) | ((b << 6) & 0xFF)` applied to all bytes; used for `arc_unpacker`-extracted files; GARbro files are plain; auto-detect by checking first byte against OPCODE_TABLE
6. **Version Branches** — Full table of all version gates with affected opcodes and byte count changes
7. **Parse Loop** — `total_size = len(data)`; loop: `shift opcode byte` → dispatch → `total_size -= compiled_size`; terminates when `total_size <= 0`; negative `total_size` is invariant violation
8. **Label/Jump System** — All pointer opcodes store raw byte-offset targets; `processLabels()` inserts `@LABEL_N` strings where N = target byte offset; labels inserted AFTER the opcode whose cumulative compiled_size matches the target (F-15); label at offset 0 is prepended; unresolved labels = error
9. **Engine Escape Sequences** — `%K` (wait for keypress), `%P` (page break), `%LFName` (display name with left-float style), `%Q` (hidden/skip section)
10. **FileEnd Behavior** — Does not terminate parse loop; loop is driven purely by byte count
11. **Known Unknowns** — `Unk*` opcodes: payload fully documented, semantics unknown

---

## SSOT Document 2: `docs/OPCODE_REFERENCE.md`

Full table: Hex | Name | Payload (byte-exact) | Version Gate | compiledSize | Dynamic? | Loops? | Registers Labels? | Exception Conditions

All 87 rows populated, including every version gate from forensic analysis.

---

## NFR Document: `docs/NFR.md`

### NFR-01: Performance
- Parse 158 KB `00_scn002h.ws2` in < 1 second (single-core)
- Batch all 10 files < 5 seconds total
- Memory peak < 50 MB per file
- No repeated string allocation in inner parse loop

### NFR-02: Reliability
- **Zero silent data corruption**: every buffer underrun raises, never returns garbage
- **Partial output written even on error**: pipeline writes what was parsed before the error (identical to PHP debug.log behavior)
- **Byte-exact reproducibility**: given identical input + flags, output is byte-for-byte identical across runs, platforms, Python minor versions
- **Negative total_size is detected**: raises `CompiledSizeMismatchError`, never silently ignored
- **Unresolved labels detected**: raises `UnresolvedLabelError` with offsets list

### NFR-03: Usability
- Zero-config start: `python ws2parse.py myfile.ws2` works with no flags
- No pip install; stdlib only
- Error messages include file, hex offset, opcode hex+name, human description
- `--help` covers all flags with examples in ≤ 30 lines
- Exit codes documented and stable (0/1/2)

### NFR-04: Correctness
- `src` format output must be byte-for-byte identical to PHP tool for all 10 reference files
- Verification: `diff <(python ws2parse.py --format src $f) <(cat $ref)` must exit 0 for all 10
- Label names (`@LABEL_N`) must match PHP output exactly (F-08 verified)
- Float formatting must reproduce PHP's float32 rounding artifacts (use `struct.pack/unpack` round-trip)

### NFR-05: Maintainability
- `OPCODE_TABLE` is the single source of truth for dispatch (adding opcode = one dict entry + one handler function)
- All version branching expressed as `v_gt(version, V_x_xx)` inside handlers
- Cyclomatic complexity ≤ 10 per function
- All public API functions have type annotations
- No bare `Exception` raises; always one of the typed errors in `errors.py`

### NFR-06: Observability
- `--verbose`: stderr line per opcode `[0x0042] @ byte 0x1A3F DisplayMessage params=(3, 'char', 0) size=47`
- `debug.log` written to CWD on any `WS2ParseError`, containing 32 bytes before + 32 bytes after error offset (hex dump)
- Summary on completion: `N files OK, M warnings, K errors`
- Exit code distinguishes partial failure (1) from total failure (2)

### NFR-07: Security
- Parser only reads input files; never executes any embedded content
- `--out DIR` path is normalized and checked for path traversal before writing
- Embedded `wstr` values written as UTF-8 text; no eval/exec/interpolation

### NFR-08: Portability
- Python 3.8+ (no walrus operator, no `match`, no `|` union types in function signatures)
- Linux / macOS / Windows (pathlib throughout; no `os.sep` hardcoding)
- No C extensions

### NFR-09: Test Coverage (new, from forensics)
- F-01 through F-15 each have a dedicated unit test with a hand-crafted binary fixture
- All 87 opcodes have at least one round-trip test
- Version branching tested at boundaries: exactly v1.0, v1.06, v1.4, v1.9 and one value between each pair
- `ShowChoice` with count=0 has a test
- `Condition` with configValue=3 + peek byte in/out of trigger set has tests
- `FileEnd` followed by trailing bytes has a test (F-07)
- Jump to offset 0 has a test (F-09)
- Jump past EOF has a test (F-10)
- Decryption auto-detect has a test (F-11)
- Float special values (NaN, Inf) in JSON formatter have a test

---

## Multi-Agent Development Cycle

The implementation is divided into 5 parallel-capable phases. Each phase has defined **entry preconditions**, **exit criteria**, and **handoff artifacts**. No phase begins until its preconditions are satisfied.

### Phase 0 — Pre-conditions (current state, no work needed)
- ✅ Repo `/home/vercel-sandbox/ws2-parser/` exists with remote
- ✅ Reference outputs in `decompiled/*.ws2.src`
- ✅ Binary inputs `*.ws2` at `/home/vercel-sandbox/`
- ✅ This plan file is complete and approved

---

### Phase 1 — Foundation Layer (Agent: Foundation)
**Entry**: Phase 0 complete
**Files to create**:
- `ws2parse/__init__.py` — `__version__ = '1.0.0'`
- `ws2parse/errors.py` — all 8 exception classes (exact signatures from Module 1 spec above)
- `ws2parse/reader.py` — FastBuffer, all type readers, `decrypt_file`, `auto_detect_decrypt`
- `ws2parse/labels.py` — `inject_labels`, `register_label`
- `ws2parse/opcodes/__init__.py` — empty
- `ws2parse/opcodes/registry.py` — `OpcodeNode`, `OPCODE_TABLE`, `dispatch`, version constants

**Exit criteria** (agent self-verifies before handing off):
1. `python3 -c "from ws2parse.reader import FastBuffer, read_dword, decrypt_file; print('OK')"` exits 0
2. `python3 -c "from ws2parse.labels import inject_labels; print('OK')"` exits 0
3. `python3 -c "from ws2parse.errors import BufferUnderrunError; raise BufferUnderrunError('test', 'f.ws2', 0)"` raises correctly
4. All F-01 through F-06 edge cases covered in `FastBuffer` (verified by reading the code)

**Handoff artifact**: `ws2parse/` foundation modules

---

### Phase 2 — Opcode Handlers (Agent: Opcodes)
**Entry**: Phase 1 exit criteria passed
**Files to create**:
- `ws2parse/opcodes/handlers.py` — all 87 handler functions + `_register()` calls to populate `OPCODE_TABLE`

**Implementation order** (lowest risk → highest risk):
1. Zero-payload opcodes (Unk00, Unk05, Unk3E, etc.) — 12 handlers
2. Fixed-size flat opcodes (Unk08, Unk0A, Unk0D, Unk0E, ...) — 25 handlers
3. Single-wstr opcodes (RunFile, NextFile, ClearLayer, ...) — 15 handlers
4. Multi-wstr opcodes (SetBackground, Effect3, ...) — 10 handlers
5. Version-branching opcodes (DisplayMessage, SetDisplayName, Unk16, PlayMusic, SoundEffect, ExecuteFunction, SetTimer, Unk19) — 8 handlers
6. Jump/label opcodes (Jump, Jump2, ConditionalJump, Condition) — 4 handlers
7. Loop opcodes (ShowChoice, DisplayCharacterImage, LayersList) — 3 handlers
8. Complex opcodes (RainStart, Effect1, Unk67) — 3 handlers
9. Special-case opcodes (UnkScreen, FileEnd) — 2 handlers
10. Remaining: 5 handlers

**Exit criteria**:
1. `python3 -c "from ws2parse.opcodes.registry import OPCODE_TABLE; print(len(OPCODE_TABLE))"` prints `87`
2. All 87 opcode hex codes in `OPCODE_TABLE`: `{0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0D, 0x0E, 0x0F, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x28, 0x29, 0x2A, 0x2E, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x4A, 0x51, 0x52, 0x53, 0x56, 0x57, 0x58, 0x5B, 0x5C, 0x64, 0x65, 0x66, 0x67, 0x68, 0x6E, 0x6F, 0x73, 0x75, 0x78, 0x7A, 0x7B, 0x84, 0x97, 0xE6, 0xF0, 0xFB, 0xFC, 0xFD, 0xFF}`
3. Parse the smallest binary file `00_scn002b.ws2` (2818 bytes) without error: `python3 -c "from ws2parse.pipeline import parse; ..."`

**Handoff artifact**: `ws2parse/opcodes/handlers.py`

---

### Phase 3 — Pipeline + CLI + Formatters (Agent: Pipeline)
**Entry**: Phase 2 exit criteria passed
**Files to create**:
- `ws2parse/pipeline.py` — all 7 stages
- `ws2parse/cli.py` — argparse, exit codes
- `ws2parse/formatters/__init__.py`
- `ws2parse/formatters/src.py` — exact PHP-compatible output
- `ws2parse/formatters/json_fmt.py` — JSON output
- `ws2parse/formatters/text.py` — dialogue extraction
- `ws2parse.py` — entry-point shim: `from ws2parse.cli import main; main()`

**Exit criteria**:
1. `python3 ws2parse.py --help` exits 0 and prints usage
2. `python3 ws2parse.py --format src --out /tmp/py_out /home/vercel-sandbox/00_scn002g.ws2` exits 0 and creates `/tmp/py_out/00_scn002g.ws2.src`
3. `diff /tmp/py_out/00_scn002g.ws2.src /home/vercel-sandbox/ws2-parser/decompiled/00_scn002g.ws2.src` exits 0

**Handoff artifact**: Working `python3 ws2parse.py` command

---

### Phase 4 — Full Verification (Agent: Verifier)
**Entry**: Phase 3 exit criteria passed
**No new files created.** Only runs verification commands.

**Verification protocol** (every step must pass; if any step fails, report exactly what failed and stop):

```bash
# Step V-01: Parse all 10 files
python3 ws2parse.py --format src --out /tmp/py_out /home/vercel-sandbox/*.ws2
# Expected: exit code 0, "10 files OK" in stdout

# Step V-02: Byte-exact diff for all 10 files
PASS=0; FAIL=0
for f in /home/vercel-sandbox/ws2-parser/decompiled/*.ws2.src; do
    base=$(basename "$f")
    if diff -q "$f" "/tmp/py_out/$base" > /dev/null 2>&1; then
        echo "OK: $base"; PASS=$((PASS+1))
    else
        echo "DIFF: $base"; diff "$f" "/tmp/py_out/$base" | head -20
        FAIL=$((FAIL+1))
    fi
done
echo "PASS: $PASS  FAIL: $FAIL"
# Expected: PASS: 10  FAIL: 0

# Step V-03: JSON output does not error
python3 ws2parse.py --format json --out /tmp/py_json /home/vercel-sandbox/*.ws2
# Expected: exit 0; all 10 .json files created

# Step V-04: JSON is valid JSON
for f in /tmp/py_json/*.json; do python3 -m json.tool "$f" > /dev/null; done
# Expected: all exit 0

# Step V-05: Text output does not error
python3 ws2parse.py --format text --out /tmp/py_text /home/vercel-sandbox/*.ws2
# Expected: exit 0; all 10 .txt files created

# Step V-06: Largest file performance
time python3 ws2parse.py --format src --out /tmp/py_out /home/vercel-sandbox/00_scn002h.ws2
# Expected: real time < 1.000s

# Step V-07: Error handling — feed a truncated file
dd if=/home/vercel-sandbox/00_scn002b.ws2 bs=100 count=1 of=/tmp/truncated.ws2
python3 ws2parse.py --format src /tmp/truncated.ws2; echo "Exit: $?"
# Expected: exit 1; error message contains "BufferUnderrunError" and hex offset

# Step V-08: Unknown opcode in non-strict mode
python3 -c "
with open('/tmp/bad_opcode.ws2', 'wb') as f:
    # Write opcode 0xAA (not in table) + FileEnd
    f.write(bytes([0xAA, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
"
python3 ws2parse.py --format src /tmp/bad_opcode.ws2; echo "Exit: $?"
# Expected: exit 1; warning printed; partial output contains FileEnd line

# Step V-09: Strict mode aborts on unknown opcode
python3 ws2parse.py --strict --format src /tmp/bad_opcode.ws2; echo "Exit: $?"
# Expected: exit 2

# Step V-10: --version-info
python3 ws2parse.py --version-info
# Expected: prints "ws2parse 1.0.0" and exits 0
```

**If ALL 10 verification steps pass**: report "VERIFICATION COMPLETE — 10/10 passed"
**If any step fails**: report exactly which step, what was expected, what was observed. Do not continue.

**Handoff artifact**: Verification report

---

### Phase 5 — Documentation + Push (Agent: Docs+Push)
**Entry**: Phase 4 verification complete (all 10/10 passed)
**Files to create**:
- `ws2parse/docs/FORMAT_SPEC.md` — from SSOT Document 1 spec above
- `ws2parse/docs/OPCODE_REFERENCE.md` — from SSOT Document 2 spec above
- `ws2parse/docs/NFR.md` — from NFR spec above

**Git operations**:
```bash
cd /home/vercel-sandbox/ws2-parser
git add ws2parse/ ws2parse.py docs/
git commit -m "feat: Python WS2 parser v1.0.0 + SSOT docs + NFR

- ws2parse/ Python package: 87 opcodes, 3 formatters, full E2E pipeline
- Verified byte-exact match against PHP reference for all 10 files
- docs/FORMAT_SPEC.md: binary format SSOT
- docs/OPCODE_REFERENCE.md: 87-opcode reference table
- docs/NFR.md: non-functional requirements

Forensic findings F-01 through F-15 all addressed:
- No silent buffer underruns (FastBuffer always raises)
- Exact label algorithm (processLabels port)
- Version gates as Decimal (no float precision issues)
- Correct empty-string quoting per opcode (F-13)
- FileEnd does not stop loop (F-07)"
git push origin main
```

**Exit criteria**: `git push` exits 0; commit visible on GitHub

---

## Phase Dependency Graph

```
Phase 0 (pre-conditions, already met)
    │
    ▼
Phase 1 (Foundation: errors, reader, labels, registry)
    │
    ▼
Phase 2 (Opcodes: all 87 handlers)
    │
    ▼
Phase 3 (Pipeline + CLI + Formatters)
    │
    ▼
Phase 4 (Verification: V-01 through V-10)
    │
    ▼
Phase 5 (Docs + Push)
```

Phases 1–5 are **sequential** (each depends on the previous). Within Phase 2, handler implementation groups can be parallelized (zero-payload group, fixed-size group, etc. can be written simultaneously by one agent making multiple file edits). No phase is skipped.

---

## Files Created by This Plan

| Path | Phase | Pushed |
|------|-------|--------|
| `ws2parse/__init__.py` | 1 | Yes |
| `ws2parse/errors.py` | 1 | Yes |
| `ws2parse/reader.py` | 1 | Yes |
| `ws2parse/labels.py` | 1 | Yes |
| `ws2parse/opcodes/__init__.py` | 1 | Yes |
| `ws2parse/opcodes/registry.py` | 1 | Yes |
| `ws2parse/opcodes/handlers.py` | 2 | Yes |
| `ws2parse/pipeline.py` | 3 | Yes |
| `ws2parse/cli.py` | 3 | Yes |
| `ws2parse/formatters/__init__.py` | 3 | Yes |
| `ws2parse/formatters/src.py` | 3 | Yes |
| `ws2parse/formatters/json_fmt.py` | 3 | Yes |
| `ws2parse/formatters/text.py` | 3 | Yes |
| `ws2parse.py` | 3 | Yes |
| `docs/FORMAT_SPEC.md` | 5 | Yes |
| `docs/OPCODE_REFERENCE.md` | 5 | Yes |
| `docs/NFR.md` | 5 | Yes |

**Nothing else modified.** Existing `decompiled/*.ws2.src` files are untouched reference artifacts.





