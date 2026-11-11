#!/usr/bin/env python3
"""NameFerry - audit filenames against the platform they travel to.

Single-file, stdlib-only, read-only. See README.md.
"""
import argparse
import json
import os
import sys
import unicodedata
from collections import Counter, OrderedDict

VERSION = "1.0.0"

RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
WIN_ILLEGAL = set('<>:"|?*\\')

PROFILES = {
    "portable": {
        "reserved": True, "illegal": "windows", "trailing": True,
        "comp_chars": 255, "comp_bytes": 255,
        "path_chars": 260, "path_bytes": None,
        "non_nfc": "warning", "control": "error",
        "case_collision": "error", "norm_collision": "error",
    },
    "windows": {
        "reserved": True, "illegal": "windows", "trailing": True,
        "comp_chars": 255, "comp_bytes": 255,
        "path_chars": 260, "path_bytes": None,
        "non_nfc": "warning", "control": "error",
        "case_collision": "error", "norm_collision": "warning",
    },
    "macos": {
        "reserved": False, "illegal": "macos", "trailing": False,
        "comp_chars": 255, "comp_bytes": None,
        "path_chars": 1024, "path_bytes": None,
        "non_nfc": "warning", "control": "error",
        "case_collision": "error", "norm_collision": "error",
    },
    "linux": {
        "reserved": False, "illegal": "linux", "trailing": False,
        "comp_chars": None, "comp_bytes": 255,
        "path_chars": None, "path_bytes": 4096,
        "non_nfc": None, "control": "warning",
        "case_collision": None, "norm_collision": None,
    },
}


def is_control(ch):
    return ord(ch) < 0x20 or ord(ch) == 0x7F


def is_non_utf8(name):
    try:
        os.fsencode(name).decode("utf-8")
        return False
    except (UnicodeDecodeError, UnicodeEncodeError):
        return True


def display(name):
    """A printable form of a name, escaping non-UTF-8 bytes."""
    if is_non_utf8(name):
        return os.fsencode(name).decode("utf-8", "backslashreplace")
    return name


def illegal_chars(name, profile):
    kind = PROFILES[profile]["illegal"]
    out = []
    for ch in name:
        bad = False
        if is_control(ch):
            bad = True
        elif kind == "windows" and ch in WIN_ILLEGAL:
            bad = True
        elif kind == "macos" and ch == ":":
            bad = True
        if bad and ch not in out:
            out.append(ch)
    return out


def char_token(ch):
    if is_control(ch):
        return f"U+{ord(ch):04X}"
    return f"{ch} (U+{ord(ch):04X})"


def sanitize(name, profile):
    s = name
    stem = s.split(".", 1)[0]
    if PROFILES[profile]["reserved"] and stem.upper() in RESERVED:
        if "." in s:
            idx = s.index(".")
            s = s[:idx] + "_" + s[idx:]
        else:
            s = s + "_"
    bad = set(illegal_chars(s, profile))
    if bad:
        s = "".join("-" if ch in bad else ch for ch in s)
    if PROFILES[profile]["trailing"]:
        s = s.rstrip(". ")
        if not s:
            s = "_"
    s = unicodedata.normalize("NFC", s)
    if s.startswith("-"):
        s = "_" + s
    return s


def check_component(name, profile):
    """Per-name findings for one component. Returns list of dicts."""
    cfg = PROFILES[profile]
    findings = []

    def add(code, severity, message):
        f = {"code": code, "severity": severity, "message": message}
        if code != "non-utf8-name":
            sug = sanitize(name, profile)
            if sug != name:
                f["suggestion"] = display(sug)
        findings.append(f)

    if is_non_utf8(name):
        findings.append({
            "code": "non-utf8-name", "severity": "error",
            "message": "name bytes are not valid UTF-8; many platforms and tools cannot represent it",
        })
        return findings

    stem = name.split(".", 1)[0]
    if cfg["reserved"] and stem.upper() in RESERVED:
        add("reserved-name", "error",
            f"'{stem.upper()}' is a reserved device name on Windows")

    bad = illegal_chars(name, profile)
    if bad:
        controls_only = all(is_control(c) for c in bad)
        if profile == "linux":
            add("illegal-char", cfg["control"],
                "name contains a control character: " + ", ".join(char_token(c) for c in sorted(bad, key=ord)))
        elif controls_only:
            add("illegal-char", cfg["control"],
                "name contains a control character: " + ", ".join(char_token(c) for c in sorted(bad, key=ord)))
        else:
            target = "Windows" if cfg["illegal"] == "windows" else "macOS"
            add("illegal-char", "error",
                f"name contains characters illegal on {target}: "
                + ", ".join(char_token(c) for c in sorted(bad, key=ord)))

    if cfg["trailing"] and (name.endswith(".") or name.endswith(" ")):
        add("trailing-dot-or-space", "error",
            "name ends with a dot or a space, which Windows silently strips")

    n_chars = len(name)
    n_bytes = len(name.encode("utf-8"))
    too_long = False
    if cfg["comp_chars"] is not None and n_chars > cfg["comp_chars"]:
        too_long = True
    if cfg["comp_bytes"] is not None and n_bytes > cfg["comp_bytes"]:
        too_long = True
    if too_long:
        limits = []
        if cfg["comp_chars"] is not None:
            limits.append(f"{cfg['comp_chars']} characters")
        if cfg["comp_bytes"] is not None:
            limits.append(f"{cfg['comp_bytes']} bytes")
        add("component-too-long", "error",
            f"name is {n_chars} characters ({n_bytes} UTF-8 bytes); the {profile} limit is "
            + " and ".join(limits))

    if cfg["non_nfc"] and unicodedata.normalize("NFC", name) != name:
        add("non-nfc-name", cfg["non_nfc"],
            "name is not in Unicode NFC form; it can fail to match its NFC twin after a round-trip")

    if name.startswith("-"):
        add("leading-dash", "warning",
            "name starts with '-', which many command-line tools read as an option")

    return findings


def check_path_length(rel, profile):
    cfg = PROFILES[profile]
    n_chars = len(rel)
    n_bytes = len(os.fsencode(rel))
    if cfg["path_chars"] is not None and n_chars > cfg["path_chars"]:
        return (f"relative path is {n_chars} characters; the {profile} limit is "
                f"{cfg['path_chars']} characters")
    if cfg["path_bytes"] is not None and n_bytes > cfg["path_bytes"]:
        return (f"relative path is {n_bytes} bytes; the {profile} limit is "
                f"{cfg['path_bytes']} bytes")
    return None


def collision_findings(names, profile, path_label):
    """names: raw sibling names in one directory (or one argument list)."""
    cfg = PROFILES[profile]
    out = []
    case_groups = OrderedDict()
    if cfg["case_collision"]:
        for n in names:
            case_groups.setdefault(n.casefold(), set()).add(n)
    reported_case_sets = []
    for key in sorted(case_groups):
        group = case_groups[key]
        if len(group) > 1:
            reported_case_sets.append(set(group))
            members = ", ".join(f"'{display(m)}'" for m in sorted(group))
            out.append({
                "code": "case-collision", "severity": cfg["case_collision"],
                "path": path_label,
                "message": f"sibling names {members} are identical when case-folded; "
                           "they overwrite each other on case-insensitive filesystems",
            })
    if cfg["norm_collision"]:
        norm_groups = OrderedDict()
        for n in names:
            norm_groups.setdefault(unicodedata.normalize("NFC", n), set()).add(n)
        for key in sorted(norm_groups):
            group = norm_groups[key]
            if len(group) > 1 and set(group) not in reported_case_sets:
                members = ", ".join(f"'{display(m)}'" for m in sorted(group))
                out.append({
                    "code": "normalization-collision", "severity": cfg["norm_collision"],
                    "path": path_label,
                    "message": f"sibling names {members} are identical under Unicode "
                               "normalization (NFC/NFD); they merge on normalizing filesystems",
                })
    return out


def scan_root(root, profile):
    """Returns (entries, per_name_findings, collision_findings_list)."""
    entries = 0
    findings = []
    collisions = []

    def audit_entry(name, rel):
        nonlocal entries
        entries += 1
        for f in check_component(name, profile):
            f2 = dict(f)
            f2["path"] = display(rel)
            # order keys deterministically when serialized by caller
            findings.append(f2)
        msg = check_path_length(rel, profile)
        if msg:
            findings.append({"code": "path-too-long", "severity": "error",
                             "path": display(rel), "message": msg})

    if not os.path.isdir(root) or os.path.islink(root):
        base = os.path.basename(os.path.normpath(root))
        audit_entry(base, base)
        return entries, findings, collisions

    def onerror(err):
        raise err

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=onerror, followlinks=False):
        dirnames.sort()
        filenames.sort()
        siblings = list(dirnames) + list(filenames)
        rel_dir = os.path.relpath(dirpath, root)
        label = "." if rel_dir == "." else display(rel_dir)
        for name in sorted(siblings):
            rel = name if rel_dir == "." else os.path.join(rel_dir, name)
            audit_entry(name, rel)
        collisions.extend(collision_findings(siblings, profile, label))
    return entries, findings, collisions


def cap_findings(findings, max_examples):
    counts = Counter(f["code"] for f in findings)
    seen = Counter()
    kept = []
    for f in findings:
        if seen[f["code"]] < max_examples:
            kept.append(f)
        seen[f["code"]] += 1
    suppressed = {code: counts[code] - min(counts[code], max_examples)
                  for code in counts if counts[code] > max_examples}
    return kept, counts, suppressed


def ordered(f):
    out = OrderedDict()
    out["code"] = f["code"]
    out["severity"] = f["severity"]
    out["path"] = f["path"]
    out["message"] = f["message"]
    if "suggestion" in f:
        out["suggestion"] = f["suggestion"]
    return out


def emit(findings_all, profile, max_examples, as_json, header_lines, summary_word, summary_count):
    kept, counts, suppressed = cap_findings(findings_all, max_examples)
    errors = sum(1 for f in findings_all if f["severity"] == "error")
    warnings = sum(1 for f in findings_all if f["severity"] == "warning")
    code_counts = {}
    for f in findings_all:
        key = f"{f['severity']}:{f['code']}"
        code_counts[key] = code_counts.get(key, 0) + 1
    if as_json:
        doc = OrderedDict()
        doc["tool"] = "nameferry"
        doc["version"] = VERSION
        doc["profile"] = profile
        for k, v in header_lines:
            doc[k] = v
        doc["counts"] = {k: code_counts[k] for k in sorted(code_counts)}
        doc["errors"] = errors
        doc["warnings"] = warnings
        doc["findings"] = [ordered(f) for f in kept]
        if suppressed:
            doc["suppressed"] = {k: suppressed[k] for k in sorted(suppressed)}
        print(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=False))
    else:
        for k, v in header_lines:
            if isinstance(v, list):
                print(f"{k}: {', '.join(v)}")
            else:
                print(f"{k}: {v}")
        for f in kept:
            line = f"finding: [{f['severity']}] {f['code']} {f['path']}: {f['message']}"
            if "suggestion" in f:
                line += f" (suggestion: {f['suggestion']})"
            print(line)
        for code in sorted(suppressed):
            print(f"note: {suppressed[code]} more {code} findings not shown (example cap {max_examples})")
        print(f"nameferry: {summary_count} {summary_word}, {errors} errors, {warnings} warnings")
    return 1 if errors else 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="nameferry", description=__doc__)
    parser.add_argument("--version", action="version", version=f"nameferry {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="audit a directory tree (or files) against a profile")
    p_check.add_argument("paths", nargs="+")
    p_check.add_argument("--profile", choices=sorted(PROFILES), default="portable")
    p_check.add_argument("--max-examples", type=int, default=10)
    p_check.add_argument("--json", action="store_true")

    p_name = sub.add_parser("name", help="check individual names before you create them")
    p_name.add_argument("names", nargs="+")
    p_name.add_argument("--profile", choices=sorted(PROFILES), default="portable")
    p_name.add_argument("--max-examples", type=int, default=10)
    p_name.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    if args.max_examples < 0:
        parser.error("--max-examples must be >= 0")

    if args.command == "check":
        all_findings = []
        all_collisions = []
        total_entries = 0
        for root in args.paths:
            if not os.path.lexists(root):
                print(f"nameferry: error: no such path: {root}", file=sys.stderr)
                return 2
            try:
                entries, findings, collisions = scan_root(root, args.profile)
            except OSError as exc:
                print(f"nameferry: error: cannot scan {root}: {exc}", file=sys.stderr)
                return 2
            total_entries += entries
            all_findings.extend(findings)
            all_collisions.extend(collisions)
        header = [("profile", args.profile), ("roots", list(args.paths)), ("entries", total_entries)]
        return emit(all_findings + all_collisions, args.profile, args.max_examples,
                    args.json, header, "entries", total_entries)

    # name subcommand
    for n in args.names:
        if "/" in n or n in ("", ".", ".."):
            print(f"nameferry: error: not a single name: {n!r}", file=sys.stderr)
            return 2
    findings = []
    for n in args.names:
        for f in check_component(n, args.profile):
            f2 = dict(f)
            f2["path"] = display(n)
            findings.append(f2)
    collisions = collision_findings(list(args.names), args.profile, "(names)")
    header = [("profile", args.profile), ("names_checked", len(args.names))]
    return emit(findings + collisions, args.profile, args.max_examples,
                args.json, header, "names", len(args.names))


if __name__ == "__main__":
    sys.exit(main())
