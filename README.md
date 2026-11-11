# NameFerry

**Audit a folder's names against the platform they are about to travel to.**

A filename that is perfectly legal where it was created can be
illegal, stripped, or silently overwritten where it lands: `a:b.txt`
is fine on Linux and unnameable on Windows; `Photo.jpg` and
`photo.jpg` coexist on Linux and destroy each other on a Windows or
macOS checkout; a name saved in decomposed Unicode form may not
match itself after a macOS round-trip. NameFerry reads a whole tree
and reports every name that will not survive the trip — before the
sync, the checkout, or the archive hand-off finds out the hard way.
One Python file, no dependencies, no network, read-only: nothing is
ever renamed.

```
$ nameferry check photos
profile: portable
roots: photos
entries: 5
finding: [error] reserved-name CON.txt: 'CON' is a reserved device name on Windows (suggestion: CON_.txt)
finding: [error] illegal-char a:b.txt: name contains characters illegal on Windows: : (U+003A) (suggestion: a-b.txt)
finding: [error] case-collision .: sibling names 'Photo.jpg', 'photo.jpg' are identical when case-folded; they overwrite each other on case-insensitive filesystems
nameferry: 5 entries, 3 errors, 0 warnings
```

The same tree checked against a Linux destination is clean — the
verdict follows the destination:

```
$ nameferry check photos --profile linux
profile: linux
roots: photos
entries: 5
nameferry: 5 entries, 0 errors, 0 warnings
```

(In a collision finding, the path is the directory holding the
siblings — `.` is the scan root.)

## Why it's different

- **Profiles, not one rulebook.** `portable` (the default) is the
  strict union of all three targets; `windows`, `macos`, and `linux`
  each apply only their own platform's published rules — reserved
  device names, illegal characters, trailing dots and spaces,
  component and path limits. A tree is audited for where it is
  *going*, not where it happens to be.
- **Collisions under transformation.** Sibling names are compared
  case-folded and under Unicode normalization (NFC and NFD), so the
  pairs that merge only after another filesystem rewrites them —
  different-case twins, composed-vs-decomposed twins — are
  first-class findings, reported once per directory with both names.
- **Check the name before it exists.** `nameferry name NAME...`
  applies the same profile to names you are about to use for new
  files, exports, or repositories — including component lengths your
  own filesystem would refuse to create, which a tree scan can never
  show you.
- **A gate, not a viewer.** Exit codes are the interface: 0 clean,
  1 error findings, 2 the audit could not run. `--json` output is
  byte-deterministic for a fixed tree, findings are counted exactly
  even when examples are capped, and every single-name finding
  carries a concrete suggested fix. Warnings never fail the gate.

## Install

Download `nameferry.py` and run it with Python 3.10 or newer.
That's the whole installation.

## Usage

```
nameferry check PATH [PATH...] [--profile PROFILE] [--json] [--max-examples N]
nameferry name NAME [NAME...] [--profile PROFILE] [--json] [--max-examples N]
nameferry --version
```

- `check` audits directories recursively, or individual files.
  Symlinks are listed as entries and never followed, so a symlink
  loop cannot hang the audit. The scan root's own name is not
  audited; everything under it is, including directory names.
- `name` audits single names (no `/` allowed) and also reports
  collisions among the names given.
- `--profile` is one of `portable` (default), `windows`, `macos`,
  `linux`.
- `--max-examples N` caps the findings printed per finding code
  (default 10); totals in the summary and in `--json` counts are
  always exact, and `--json` reports how many were suppressed.

### What is checked

| Finding | Profiles | Severity |
|---|---|---|
| `reserved-name` — stem is CON, PRN, AUX, NUL, COM1–9, LPT1–9 | windows, portable | error |
| `illegal-char` — `<>:"\|?*` or backslash (windows set), `:` (macos), control characters | all | error (control-only on linux: warning) |
| `non-utf8-name` — name bytes are not valid UTF-8 | all | error |
| `trailing-dot-or-space` — Windows silently strips these | windows, portable | error |
| `component-too-long` — over 255 characters and/or 255 UTF-8 bytes, per profile | all | error |
| `path-too-long` — relative path over 260 chars (windows/portable), 1024 chars (macos), 4096 bytes (linux) | all | error |
| `case-collision` — siblings equal when case-folded | portable, windows, macos | error |
| `normalization-collision` — siblings equal under NFC/NFD | portable, macos (error); windows (warning) | error/warning |
| `non-nfc-name` — name not in Unicode NFC form | portable, windows, macos | warning |
| `leading-dash` — name starts with `-` | all | warning |

Path lengths are measured relative to the scan root as given, so a
`path-too-long` verdict is a lower bound: the destination's absolute
path will be longer.

### Suggestions

Single-name findings (except collisions, path length, and
non-UTF-8 names) carry a suggestion built by fixed rules: illegal
characters become `-`, trailing dots/spaces are stripped, a reserved
stem gains a `_` (`CON.txt` → `CON_.txt`), a decomposed name is
recomposed to NFC, a leading dash gains a `_` prefix. Suggestions
are advice printed in the report — NameFerry never renames anything.

## Limitations, honestly

- The rule sets are the documented platform rules (Microsoft's
  cross-platform compatibility reference, Apple's and the Linux
  kernel's filesystem limits) reduced to a portable core. They do
  not model every filesystem quirk: APFS and NTFS each accept some
  names the strict `portable` profile rejects, and cloud drives add
  rules of their own (some sync services also reject names like
  `.lock` or temporary Office names) that are out of scope.
- A component longer than 255 bytes cannot exist on most
  filesystems, so `component-too-long` is mainly reachable through
  the `name` subcommand and through names arriving from archives or
  other systems — by design.
- Collision detection compares names within one directory, exactly
  where filesystems collide them. It does not compare a file against
  a directory in a *different* directory, and it cannot see names
  that will only be created later at the destination.
- Non-UTF-8 names are reported with escaped display forms; the
  audit does not guess an encoding for them.

## License

MIT — see `LICENSE`. Copyright (c) 2026 Dimon Global Group.
