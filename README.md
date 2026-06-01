# .ws2-parser

Decompiled AdvHD visual novel script files (.ws2 → .ws2.src pseudo-code).

## Source Files (10 binary .ws2 scripts)

| File | Size | Scene |
|------|------|-------|
| `00_SCN001A.ws2` | 34,075 bytes | Intro — Mao moves to new house, meets stepmother Mami and stepsister Miku |
| `00_scn002a.ws2` | 7,835 bytes | School Day 2 — name-selection choice branch (Sean / Marco / Chris) |
| `00_scn002b.ws2` | 2,818 bytes | Branch: classmate's name is Sean |
| `00_scn002c.ws2` | 2,684 bytes | Branch: classmate's name is Marco |
| `00_scn002d.ws2` | 2,155 bytes | Branch: classmate introduces himself as Saionji Chris |
| `00_scn002e.ws2` | 12,158 bytes | Merged scene — keychain returned, walk-home invitation |
| `00_scn002f.ws2` | 2,260 bytes | Sub-branch: "I've gotten used to it" |
| `00_scn002g.ws2` | 1,161 bytes | Sub-branch: "I still haven't gotten used to it" |
| `00_scn002h.ws2` | 158,644 bytes | Walking home main scene (largest file) |
| `00_scn002i.ws2` | 2,378 bytes | Walk home together — ending scene |

## Tool

Decompiled using [DarthFly/advhd_ws2_tools](https://github.com/DarthFly/advhd_ws2_tools)

```
php ws2_decompile.php /path/to/ws2/files 1.9
```

## Output

Decompiled pseudo-code files are in the `decompiled/` directory.
Each `.ws2.src` file contains human-readable commands:
- `DisplayMessage` — dialogue lines
- `SetDisplayName` — character name
- `ShowChoice` — branching choices
- `NextFile` — scene transitions
- `SetBackground`, `UsePnaPackage`, `DisplayCharacterImage` — visual layer control
