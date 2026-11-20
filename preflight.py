#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布前体检：在把本地目录推上公开仓库之前，先检查「不能上去的东西」。

这个工具是被真实事故逼出来的：每次发新仓库/更新仓库，都要人工确认一遍
「有没有把录音、密钥、本机路径、缓存带上去」。人工确认靠记性，迟早会漏；
所以把它变成一条命令 + 一个退出码，并且给发布脚本当闸门。

检查分两级：

    阻断（exit 2）  个人音频、密钥/证书、.env、.git 目录 —— 这些东西上去就撤不回来
    提醒（exit 1）  本机绝对路径、太大的文件、缓存/日志、带 EXIF 的图片 —— 通常不该发，
                   但有些是故意的，看一眼再决定

用法：
    python preflight.py <目录>                      # 体检，给人看
    python preflight.py <目录> --json out.json      # 机器可读
    python preflight.py <目录> --allow-audio 采样.wav # 明确允许某个音频（可重复）
    python preflight.py --selftest                  # 跑自带用例（验证规则本身没坏）

目录里的 `.preflight-allow` 可以写多行 glob（相对路径），作为长期允许清单，例如：
    tests/data/tts_zh.wav     # 单测用的 TTS 合成样本，不是真人录音
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------- 规则表
AUDIO_EXT = {".wav", ".mp3", ".m4a", ".aac", ".flac", ".ogg", ".opus", ".webm",
             ".wma", ".amr", ".aiff", ".aif", ".caf"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".heic"}

SECRET_FILES = {
    ".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials.json", "secrets.json", "credentials.yaml", "credentials.yml",
}
SECRET_SUFFIX = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
ALLOWED_SECRET_FILES = {".env.example", ".env.sample", ".env.template"}

JUNK_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
             "node_modules", ".venv", "venv", ".idea", ".vscode", ".git"}
JUNK_SUFFIX = {".pyc", ".pyo", ".log", ".tmp", ".swp", ".bak~"}
JUNK_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("GitHub fine-grained token", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("百炼/OpenAI 风格 key", re.compile(r"\bsk-(?:sp-)?[A-Za-z0-9_\-]{20,}")),
    ("私钥", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
SECRET_HINT = re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{24,})[\"']")

HOME_PATH = re.compile(
    r"(?:[A-Za-z]:\\Users\\[^\\\s\"'<>|\[\]()^$*+?{}]+|/Users/[^/\s\"'<>|\[\]()^$*+?{}]+|"
    r"/home/[^/\s\"'<>|\[\]()^$*+?{}]+)")
WORK_PATH = re.compile(r"[A-Za-z]:\\DSH_[A-Za-z]+")

TEXT_EXT = {".md", ".txt", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
            ".json", ".jsonc", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf",
            ".ps1", ".sh", ".bat", ".cmd", ".html", ".htm", ".css", ".csv", ".tsv",
            ".gitignore", ".gitattributes"}

SKIP_READ_OVER = 2 * 1024 * 1024  # 超过 2MB 的文本不扫内容（多半是数据）


@dataclass
class Finding:
    level: str        # blocker / warn
    code: str
    path: str
    message: str
    line: int | None = None

    def as_dict(self) -> dict:
        d = {"level": self.level, "code": self.code, "path": self.path, "message": self.message}
        if self.line:
            d["line"] = self.line
        return d


# ---------------------------------------------------------------- .gitignore
def load_gitignore(root: Path) -> list[str]:
    p = root / ".gitignore"
    if not p.exists():
        return []
    pats = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            pats.append(line.rstrip("/"))
    return pats


def _match(rel: str, pat: str) -> bool:
    parts = rel.split("/")
    if pat.startswith("*."):
        return rel.endswith(pat[1:])
    if pat.startswith("**/"):
        return fnmatch.fnmatch(rel, pat)
    return rel == pat or rel.startswith(pat + "/") or pat in parts[:-1]


def is_ignored(rel: str, pats: list[str]) -> bool:
    ignored = False
    for pat in pats:
        neg = pat.startswith("!")
        p = pat[1:] if neg else pat
        if p and _match(rel, p):
            ignored = not neg
    return ignored


def load_allow(root: Path, extra: list[str]) -> list[str]:
    allow = []
    f = root / ".preflight-allow"
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                allow.append(line)
    for e in extra:
        if e:
            allow.append(e.replace("\\", "/"))
    return allow


def is_allowed(rel: str, allow: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pat) or rel == pat for pat in allow)


# ---------------------------------------------------------------- 单文件检查
def _exif_personal(path: Path) -> str | None:
    """图片里有没有 GPS / 相机型号这类个人信息（没有 Pillow 就跳过）。"""
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover
        return None
    try:
        with Image.open(path) as im:
            exif = im.getexif()
            if not exif:
                return None
            gps = exif.get(34853)
            make, model = exif.get(271), exif.get(272)
            if gps:
                return "带 GPS 信息"
            if make or model:
                return f"带相机信息（{str(make or '')} {str(model or '')}）".strip()
    except Exception:  # noqa: BLE001
        return None
    return None


def scan_file(root: Path, path: Path, rel: str, allow: list[str],
              max_mb: float) -> list[Finding]:
    out: list[Finding] = []
    name = path.name
    suffix = path.suffix.lower()

    # 1) 个人音频（最大红线）
    if suffix in AUDIO_EXT:
        if not is_allowed(rel, allow):
            out.append(Finding("blocker", "AUDIO", rel,
                               "音频文件默认视为个人录音；确认不是就写进 .preflight-allow"))
        return out  # 音频不扫内容

    # 2) 密钥文件
    if name in SECRET_FILES and name not in ALLOWED_SECRET_FILES:
        out.append(Finding("blocker", "SECRET_FILE", rel, "疑似密钥/凭据文件，不能发布"))
    if suffix in SECRET_SUFFIX:
        out.append(Finding("blocker", "SECRET_FILE", rel, f"证书/私钥文件（{suffix}），不能发布"))

    # 3) 垃圾文件
    parts = rel.split("/")
    if any(p in JUNK_DIRS for p in parts[:-1]) or name in JUNK_FILES or suffix in JUNK_SUFFIX:
        out.append(Finding("warn", "JUNK", rel, "缓存/日志/临时文件，通常不该提交"))

    # 4) 体积
    try:
        size_mb = path.stat().st_size / 1024 / 1024
        if size_mb > max_mb:
            out.append(Finding("warn", "LARGE", rel, f"{size_mb:.1f}MB，超过 {max_mb:g}MB 阈值"))
    except OSError:
        pass

    # 5) 图片 EXIF
    if suffix in IMAGE_EXT:
        why = _exif_personal(path)
        if why:
            out.append(Finding("warn", "IMAGE_META", rel, f"图片{why}，发布前确认"))

    # 6) 文本内容：密钥 + 本机路径
    if suffix in TEXT_EXT or name.startswith(".git") or name in ("LICENSE", "Makefile"):
        try:
            if path.stat().st_size <= SKIP_READ_OVER:
                text = path.read_text(encoding="utf-8", errors="ignore")
            else:
                text = ""
        except OSError:
            text = ""
        for i, line in enumerate(text.splitlines(), 1):
            for label, pat in SECRET_PATTERNS:
                m = pat.search(line)
                if m and "EXAMPLE" not in line and "xxx" not in line.lower():
                    out.append(Finding("blocker", "SECRET", rel,
                                       f"疑似{label}：{m.group(0)[:12]}…", i))
                    break
            else:
                hint = SECRET_HINT.search(line)
                if hint:
                    out.append(Finding("warn", "SECRET_HINT", rel,
                                       f"像{group_if_any(hint)}赋值，确认不是真密钥", i))
            # 占位符（C:\Users\<你>、E:\DSH_…）不算泄露
            def placeholder(s: str) -> bool:
                return any(t in s for t in ("…", "...", "<", ">", "%", "$", "{"))

            m = HOME_PATH.search(line)
            if m and not placeholder(m.group(0)):
                out.append(Finding("warn", "LOCAL_PATH", rel,
                                   f"出现本机用户路径：{m.group(0)}", i))
            else:
                m = WORK_PATH.search(line)
                if m and not placeholder(m.group(0)):
                    out.append(Finding("warn", "LOCAL_PATH", rel,
                                       f"出现本机工作区路径：{m.group(0)}", i))
    return out


def group_if_any(m) -> str:
    try:
        return m.group(1) or "敏感字段"
    except IndexError:  # pragma: no cover
        return "敏感字段"


# ---------------------------------------------------------------- 目录扫描
def scan(root: Path, allow_extra: list[str] | None = None,
         max_mb: float = 8.0) -> tuple[list[Finding], dict]:
    root = root.resolve()
    if not root.is_dir():
        raise SystemExit(f"目录不存在：{root}")
    ignores = load_gitignore(root)
    allow = load_allow(root, allow_extra or [])
    findings: list[Finding] = []
    stats = {"scanned": 0, "ignored": 0, "dirs": 0}

    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        rel_dir = here.relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        # 忽略目录：.git 等；gitignore 里忽略的目录直接剪枝
        dirnames[:] = [
            d for d in dirnames
            if d not in (".git",) and not is_ignored(f"{rel_dir}/{d}".lstrip("/"), ignores)
        ]
        stats["dirs"] += 1
        for fn in filenames:
            p = here / fn
            rel = p.relative_to(root).as_posix()
            if is_ignored(rel, ignores):
                stats["ignored"] += 1
                continue
            stats["scanned"] += 1
            findings.extend(scan_file(root, p, rel, allow, max_mb))

    # .git 目录单独提示（如果真存在）
    if (root / ".git").exists():
        findings.insert(0, Finding("blocker", "GIT_DIR", ".git/",
                                   "这是 git 仓库目录；发布用 API 建树即可，别把 .git 传上去"))
    return findings, stats


# ---------------------------------------------------------------- 报告
def report(findings: list[Finding], stats: dict, root: Path) -> str:
    blockers = [f for f in findings if f.level == "blocker"]
    warns = [f for f in findings if f.level == "warn"]
    lines = [f"发布前体检 · {root}"]
    lines.append(f"  检查 {stats['scanned']} 个文件（按 .gitignore 跳过 {stats['ignored']} 个）"
                 f" · 阻断 {len(blockers)} · 提醒 {len(warns)}")
    lines.append("")
    for f in blockers:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        lines.append(f"  [阻断] {f.code:12} {loc}  — {f.message}")
    for f in warns:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        lines.append(f"  [提醒] {f.code:12} {loc}  — {f.message}")
    if not findings:
        lines.append("  干净：可以发布。")
    return "\n".join(lines)


def selftest() -> int:
    """用临时目录造一批「该拦的」和「该放的」，验证规则本身没坏。"""
    import tempfile
    import wave

    ok = True
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / ".gitignore").write_text("ignored/\n*.log\n", encoding="utf-8")
        (root / ".preflight-allow").write_text("allowed/clip.wav  # 合成的\n", encoding="utf-8")
        (root / "src").mkdir()
        (root / "src" / "ok.py").write_text("print('hello')\n", encoding="utf-8")

        def wav(p: Path):
            p.parent.mkdir(parents=True, exist_ok=True)
            with wave.open(str(p), "wb") as w:
                w.setnchannels(1)
                w.setsampwidth(2)
                w.setframerate(16000)
                w.writeframes(b"\x00\x00" * 1600)

        wav(root / "personal" / "rec.wav")           # 该拦
        wav(root / "allowed" / "clip.wav")           # 白名单放行
        wav(root / "ignored" / "x.wav")              # gitignore 跳过（目录被剪枝）
        (root / "debug.log").write_text("x\n", encoding="utf-8")  # gitignore 跳过（文件）
        (root / ".env").write_text("TOKEN=abc\n", encoding="utf-8")
        (root / "key.pem").write_text("x\n", encoding="utf-8")
        fake_key = "sk-" + "abcdefghijklmnopqrstuvwxyz012345"  # 拼出来，避免体检自己扫到自己
        (root / "note.md").write_text(
            f"key: {fake_key}\n"
            "path: C:\\Users\\someone\\secret\\a.txt\n", encoding="utf-8")
        (root / "big.bin").write_bytes(b"0" * (9 * 1024 * 1024))
        (root / "__pycache__").mkdir()
        (root / "__pycache__" / "x.pyc").write_bytes(b"x")

        findings, stats = scan(root)
        codes = [(f.level, f.code) for f in findings]
        paths = {f.path: f for f in findings}

        checks = [
            ("个人录音被拦", ("blocker", "AUDIO") in codes and "personal/rec.wav" in paths),
            ("白名单音频放行", "allowed/clip.wav" not in paths),
            ("gitignore 音频跳过", "ignored/x.wav" not in paths and stats["ignored"] >= 1),
            (".env 被拦", paths.get(".env") is not None and paths[".env"].level == "blocker"),
            ("私钥被拦", paths.get("key.pem") is not None),
            ("文本里的 key 被拦", any(f.code == "SECRET" and f.path == "note.md" for f in findings)),
            ("本机路径被提醒", any(f.code == "LOCAL_PATH" for f in findings)),
            ("大文件被提醒", any(f.code == "LARGE" for f in findings)),
            ("缓存被提醒", any(f.code == "JUNK" for f in findings)),
        ]
        print("preflight 自检")
        for name, passed in checks:
            print(f"  {name:18} {'✓' if passed else '✗'}")
            ok = ok and passed
        if not ok:
            for f in findings:
                print("   ·", f.level, f.code, f.path, f.message)
    print("\n结果:", "通过" if ok else "失败")
    return 0 if ok else 1


# ---------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="发布前体检：音频/密钥/本机路径检查")
    ap.add_argument("target", nargs="?", help="要检查的目录")
    ap.add_argument("--allow-audio", action="append", default=[],
                    help="允许的音频（相对路径或 glob，可重复）")
    ap.add_argument("--max-mb", type=float, default=8.0, help="大文件阈值（MB）")
    ap.add_argument("--json", help="结果写成 JSON")
    ap.add_argument("--selftest", action="store_true", help="跑自带用例")
    ap.add_argument("--quiet", action="store_true", help="只在有阻断时输出")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.target:
        ap.error("需要目录（或 --selftest）")
    root = Path(args.target)
    findings, stats = scan(root, args.allow_audio, args.max_mb)
    blockers = [f for f in findings if f.level == "blocker"]
    if not (args.quiet and not blockers):
        print(report(findings, stats, root.resolve()))
    if args.json:
        Path(args.json).write_text(json.dumps(
            {"findings": [f.as_dict() for f in findings], "stats": stats},
            ensure_ascii=False, indent=1), encoding="utf-8")
    if blockers:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())