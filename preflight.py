#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布前体检：在把本地目录推上公开仓库之前，先检查「不能上去的东西」。

这个工具是被真实事故逼出来的：每次发新仓库/更新仓库，都要人工确认一遍
「有没有把录音、密钥、本机路径、缓存带上去」。人工确认靠记性，迟早会漏；
所以把它变成一条命令 + 一个退出码，并且给发布脚本当闸门。

检查分三级：

    阻断（exit 2）  个人音频、密钥/证书、.env 系列、文本里的真 key、.git 目录
    提醒（exit 1）  本机绝对路径、太大的文件、缓存/日志、带 EXIF 的图片、像密钥的赋值
    信息（不影响退出码）体检自身的覆盖范围：哪个文件太大没扫完、哪项检查因为缺依赖没跑

「文本」按**内容**判断（前 8KB 没有 NUL 字节），不按扩展名白名单 —— 否则
`main.go`、`Main.java`、`Dockerfile` 里的密钥会被整份放过。

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
from functools import lru_cache
from pathlib import Path

# ---------------------------------------------------------------- 规则表
AUDIO_EXT = {".wav", ".mp3", ".m4a", ".aac", ".flac", ".ogg", ".opus", ".webm",
             ".wma", ".amr", ".aiff", ".aif", ".caf"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".heic"}

SECRET_FILES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa.pub",
    "credentials.json", "secrets.json", "credentials.yaml", "credentials.yml",
    ".git-credentials", ".netrc", "_netrc",
}
SECRET_SUFFIX = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".kdbx"}
ALLOWED_SECRET_FILES = {".env.example", ".env.sample", ".env.template"}

JUNK_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
             "node_modules", ".venv", "venv", ".idea", ".vscode", ".git"}
JUNK_SUFFIX = {".pyc", ".pyo", ".log", ".tmp", ".swp", ".bak~"}
JUNK_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}

# 扩展名命中就一定不是文本，省掉读文件的开头（音频/图片在更早的分支已返回）
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".heic",
    ".zip", ".gz", ".bz2", ".xz", ".zst", ".7z", ".rar", ".tar", ".tgz",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".pyd", ".class", ".jar", ".wasm",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".mkv", ".avi", ".mov", ".m4v", ".flv",
    ".db", ".sqlite", ".sqlite3", ".parquet", ".npy", ".npz", ".pt", ".pth", ".onnx",
    ".pkl", ".pickle", ".joblib", ".h5", ".hdf5", ".iso", ".dmg", ".msi", ".apk", ".ipa",
}

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("GitHub fine-grained token", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Slack Webhook", re.compile(
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("百炼/OpenAI 风格 key", re.compile(r"\bsk-(?:sp-)?[A-Za-z0-9_\-]{20,}")),
    ("Stripe live key", re.compile(r"sk_live_[0-9A-Za-z]{20,}")),
    ("阿里云 AccessKey", re.compile(r"LTAI[A-Za-z0-9]{12,}")),
    ("npm 认证 token", re.compile(r"//[^\s/]+/:_authToken=\S+")),
    ("私钥", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
# 只可能出现在真 token 里的东西：提醒，不阻断（文档里的示例 JWT 不算事故）
SOFT_PATTERNS = [
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
]
SECRET_HINT = re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{24,})[\"']")

HOME_PATH = re.compile(
    r"(?:[A-Za-z]:[\\/]Users[\\/][^\\/\s\"'<>|\[\]()^$*+?{}]+"
    r"|/Users/[^/\s\"'<>|\[\]()^$*+?{}]+"
    r"|/home/[^/\s\"'<>|\[\]()^$*+?{}]+"
    r"|\\\\[^\\\s]+\\Users\\[^\\\s\"'<>|\[\]()^$*+?{}]+)")
WORK_PATH = re.compile(r"[A-Za-z]:\\DSH_[A-Za-z]+")

SAMPLE_BYTES = 8 * 1024            # 判断文本/二进制看开头这么多字节
SCAN_TEXT_MAX = 64 * 1024 * 1024   # 单个文本文件最多扫这么多内容


@dataclass
class Finding:
    level: str        # blocker / warn / info
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
            pats.append(line)
    return pats


@lru_cache(maxsize=4096)
def _gitignore_regex(pattern: str) -> re.Pattern[str]:
    """把一条 .gitignore 模式翻译成正则（git 的常见语义，不是完整实现）。

    支持：`dir/`（目录及内容）、`*.ext`（任意深度）、`a/b`（锚定根）、
    `**/x`、`x/**`、`a/**/b`、`?`、`[...]`。带 `/` 的模式锚定在根，
    不带 `/` 的模式匹配任意深度的一级名字。
    """
    p = pattern
    dir_only = p.endswith("/")
    if dir_only:
        p = p[:-1].rstrip("/")
    anchored = p.startswith("/")
    if anchored:
        p = p[1:]
    if "/" in p:
        anchored = True

    out: list[str] = []
    i = 0
    while i < len(p):
        c = p[i]
        if c == "*":
            if p.startswith("**", i):
                j = i + 2
                if j < len(p) and p[j] == "/":
                    out.append("(?:.*/)?")   # `**/` 可以匹配零层
                    i = j + 1
                    continue
                out.append(".*")
                i = j
                continue
            out.append("[^/]*")
            i += 1
            continue
        if c == "?":
            out.append("[^/]")
            i += 1
            continue
        if c == "[":
            end = p.find("]", i + 1)
            if end == -1:
                out.append(re.escape(c))
                i += 1
                continue
            cls = p[i + 1:end]
            if cls.startswith("!"):
                cls = "^" + cls[1:]
            out.append("[" + cls.replace("\\", "\\\\") + "]")
            i = end + 1
            continue
        out.append(re.escape(c))
        i += 1

    body = "".join(out)
    prefix = "^" if anchored else r"^(?:.*/)?"
    # 末尾允许再跟子路径：命中一个目录时，目录里的东西也一起忽略（git 的行为）
    suffix = r"(?:/.*)?$"
    if dir_only:
        return re.compile(prefix + body + suffix)
    return re.compile(prefix + body + suffix)


def _match(rel: str, pat: str) -> bool:
    try:
        return bool(_gitignore_regex(pat).match(rel))
    except re.error:   # pragma: no cover - 正则坏掉时退回旧行为
        return rel == pat or rel.startswith(pat + "/")


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
    for pat in allow:
        pat = pat.replace("\\", "/").lstrip("./")
        if not pat:
            continue
        if pat.endswith("/") and rel.startswith(pat):
            return True
        if fnmatch.fnmatch(rel, pat) or rel == pat:
            return True
        # `assets/**` 这种写法：fnmatch 的 `*` 本来就能跨 `/`，这里再兜一层目录前缀
        if pat.endswith("/**") and rel.startswith(pat[:-3] + "/"):
            return True
    return False


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


def _pil_available() -> bool:
    try:
        import PIL  # noqa: F401
    except ImportError:
        return False
    return True


def _secret_name_reason(name: str) -> str | None:
    """文件名本身就是凭据（.env 全家族、id_rsa、.git-credentials…）。"""
    low = name.lower()
    if low in ALLOWED_SECRET_FILES:
        return None
    if low == ".env" or low.startswith(".env."):
        return "环境变量文件，几乎一定含密钥"
    if low in SECRET_FILES:
        return "疑似密钥/凭据文件，不能发布"
    return None


def _looks_text(path: Path) -> bool:
    """按内容判断是不是文本：没有 NUL 字节就当文本扫。"""
    if path.suffix.lower() in BINARY_EXT:
        return False
    try:
        with path.open("rb") as fh:
            chunk = fh.read(SAMPLE_BYTES)
    except OSError:
        return False
    return bool(chunk) and b"\x00" not in chunk


def group_if_any(m) -> str:
    try:
        return m.group(1) or "敏感字段"
    except IndexError:  # pragma: no cover
        return "敏感字段"


def _placeholder(s: str) -> bool:
    """占位符（C:\\Users\\<你>、E:\\DSH_…）不算泄露。"""
    return any(t in s for t in ("…", "...", "<", ">", "%", "$", "{"))


def _check_line(line: str, rel: str, lineno: int, out: list[Finding]) -> None:
    for label, pat in SECRET_PATTERNS:
        m = pat.search(line)
        if m and "EXAMPLE" not in line and "xxx" not in line.lower():
            out.append(Finding("blocker", "SECRET", rel,
                               f"疑似{label}：{m.group(0)[:12]}…", lineno))
            return
    for label, pat in SOFT_PATTERNS:
        m = pat.search(line)
        if m and "EXAMPLE" not in line and "xxx" not in line.lower():
            out.append(Finding("warn", "SECRET_HINT", rel,
                               f"出现{label}，确认不是真 token", lineno))
            return
    hint = SECRET_HINT.search(line)
    if hint:
        out.append(Finding("warn", "SECRET_HINT", rel,
                           f"像{group_if_any(hint)}赋值，确认不是真密钥", lineno))
        return
    m = HOME_PATH.search(line)
    if m and not _placeholder(m.group(0)):
        out.append(Finding("warn", "LOCAL_PATH", rel,
                           f"出现本机用户路径：{m.group(0)}", lineno))
        return
    m = WORK_PATH.search(line)
    if m and not _placeholder(m.group(0)):
        out.append(Finding("warn", "LOCAL_PATH", rel,
                           f"出现本机工作区路径：{m.group(0)}", lineno))


def _scan_text(path: Path, rel: str, out: list[Finding]) -> None:
    """逐行扫文本；超大的文件只扫前 SCAN_TEXT_MAX，并明说没扫完。"""
    try:
        fh = path.open("r", encoding="utf-8", errors="ignore")
    except OSError:
        return
    budget = SCAN_TEXT_MAX
    with fh:
        for lineno, line in enumerate(fh, 1):
            budget -= len(line)
            if budget < 0:
                out.append(Finding("info", "SCAN_TRUNCATED", rel,
                                   f"文件超过 {SCAN_TEXT_MAX // 1024 // 1024}MB，"
                                   f"只扫了前 {SCAN_TEXT_MAX // 1024 // 1024}MB"))
                return
            _check_line(line, rel, lineno, out)


def scan_file(root: Path, path: Path, rel: str, allow: list[str],
              max_mb: float, pil: bool = True) -> list[Finding]:
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
    why = _secret_name_reason(name)
    if why:
        out.append(Finding("blocker", "SECRET_FILE", rel, why))
    if suffix in SECRET_SUFFIX:
        out.append(Finding("blocker", "SECRET_FILE", rel, f"证书/私钥文件（{suffix}），不能发布"))

    # 3) 垃圾文件（这些目录里的内容不值得读，报一次就走）
    parts = rel.split("/")
    if any(p in JUNK_DIRS for p in parts[:-1]) or name in JUNK_FILES or suffix in JUNK_SUFFIX:
        out.append(Finding("warn", "JUNK", rel, "缓存/日志/临时文件，通常不该提交"))
        return out

    # 4) 体积
    try:
        size_mb = path.stat().st_size / 1024 / 1024
        if size_mb > max_mb:
            out.append(Finding("warn", "LARGE", rel, f"{size_mb:.1f}MB，超过 {max_mb:g}MB 阈值"))
    except OSError:
        pass

    # 5) 图片 EXIF
    if suffix in IMAGE_EXT:
        if not pil:
            out.append(Finding("info", "EXIF_SKIPPED", rel,
                               "没装 Pillow，这张图的 GPS/相机信息没检查"))
        else:
            why = _exif_personal(path)
            if why:
                out.append(Finding("warn", "IMAGE_META", rel, f"图片{why}，发布前确认"))

    # 6) 文本内容：密钥 + 本机路径（按内容判断，不按扩展名白名单）
    if _looks_text(path):
        _scan_text(path, rel, out)
    return out


# ---------------------------------------------------------------- 目录扫描
def scan(root: Path, allow_extra: list[str] | None = None,
         max_mb: float = 8.0) -> tuple[list[Finding], dict]:
    root = root.resolve()
    if not root.is_dir():
        raise SystemExit(f"目录不存在：{root}")
    ignores = load_gitignore(root)
    allow = load_allow(root, allow_extra or [])
    pil = _pil_available()
    findings: list[Finding] = []
    stats = {"scanned": 0, "ignored": 0, "dirs": 0}

    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        rel_dir = here.relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        # 忽略目录：.git 等；gitignore 里忽略的目录直接剪枝（和 git 一致：剪掉就找不回来）
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
            findings.extend(scan_file(root, p, rel, allow, max_mb, pil))

    # .git 目录单独提示（如果真存在）
    if (root / ".git").exists():
        findings.insert(0, Finding("blocker", "GIT_DIR", ".git/",
                                   "这是 git 仓库目录；发布用 API 建树即可，别把 .git 传上去"))
    return findings, stats


# ---------------------------------------------------------------- 报告
LEVEL_TAG = {"blocker": "阻断", "warn": "提醒", "info": "信息"}


def report(findings: list[Finding], stats: dict, root: Path) -> str:
    blockers = [f for f in findings if f.level == "blocker"]
    warns = [f for f in findings if f.level == "warn"]
    infos = [f for f in findings if f.level == "info"]
    lines = [f"发布前体检 · {root}"]
    summary = (f"  检查 {stats['scanned']} 个文件（按 .gitignore 跳过 {stats['ignored']} 个）"
               f" · 阻断 {len(blockers)} · 提醒 {len(warns)}")
    if infos:
        summary += f" · 信息 {len(infos)}"
    lines.append(summary)
    lines.append("")
    for f in blockers + warns + infos:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        lines.append(f"  [{LEVEL_TAG.get(f.level, f.level)}] {f.code:12} {loc}  — {f.message}")
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
        (root / ".gitignore").write_text(
            "ignored/\n*.log\nbuild/**\n**/cache/\n/root-only.txt\n!keep.log\n",
            encoding="utf-8")
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
        (root / "debug.log").write_text("x\n", encoding="utf-8")      # gitignore 跳过（文件）
        (root / "keep.log").write_text("x\n", encoding="utf-8")       # ! 例外，应被扫到
        (root / "build" / "out.js").parent.mkdir(parents=True, exist_ok=True)
        (root / "build" / "out.js").write_text("x\n", encoding="utf-8")   # build/** 跳过
        (root / "a" / "b" / "cache").mkdir(parents=True, exist_ok=True)
        (root / "a" / "b" / "cache" / "x.txt").write_text("x\n", encoding="utf-8")  # **/cache/ 跳过
        (root / "root-only.txt").write_text("x\n", encoding="utf-8")  # 锚定根，跳过
        (root / "sub").mkdir()
        (root / "sub" / "root-only.txt").write_text("x\n", encoding="utf-8")  # 不锚根，保留

        (root / ".env").write_text("TOKEN=abc\n", encoding="utf-8")
        (root / ".env.local").write_text("TOKEN=abc\n", encoding="utf-8")
        (root / "key.pem").write_text("x\n", encoding="utf-8")
        fake_key = "sk-" + "abcdefghijklmnopqrstuvwxyz012345"
        (root / "note.md").write_text(
            f"key: {fake_key}\n"
            "path: C:\\Users\\someone\\secret\\a.txt\n", encoding="utf-8")
        # 没有扩展名白名单里的文件：必须也扫
        (root / "main.go").write_text('const k = "AKIA' + 'ABCDEFGHIJKLMNOP"\n', encoding="utf-8")
        (root / "Dockerfile").write_text('ENV K="AKIA' + 'QQQQQQQQQQQQQQQQ"\n', encoding="utf-8")
        # 二进制文件里的私钥头不该当成文本扫（也不该漏掉文件名规则）；拼接写，免得自己扫自己
        (root / "blob.dat").write_bytes(b"\x00\x00-----BEGIN " + b"RSA PRIVATE KEY-----")
        # 超过旧阈值 2MB 的文本里藏 key
        (root / "huge.txt").write_text("x" * (3 * 1024 * 1024) + "\nAKIA" + "ZZZZZZZZZZZZZZZZ\n",
                                       encoding="utf-8")
        (root / "big.bin").write_bytes(b"0" * (9 * 1024 * 1024))
        (root / "__pycache__").mkdir()
        (root / "__pycache__" / "x.pyc").write_bytes(b"x")

        findings, stats = scan(root)
        codes = [(f.level, f.code) for f in findings]
        paths = {f.path: f for f in findings}
        ign = load_gitignore(root)
        ign_expect = {
            "root-only.txt": True,           # `/root-only.txt` 锚定根
            "sub/root-only.txt": False,      # 同上：子目录里的同名文件不忽略
            "keep.log": False,               # `!keep.log` 例外
            "debug.log": True,               # `*.log`
            "build/out.js": True,            # `build/**`
            "a/b/cache/x.txt": True,         # `**/cache/`
            "ignored/x.wav": True,           # `ignored/`
        }
        ign_bad = [k for k, want in ign_expect.items() if is_ignored(k, ign) != want]

        checks = [
            ("个人录音被拦", ("blocker", "AUDIO") in codes and "personal/rec.wav" in paths),
            ("白名单音频放行", "allowed/clip.wav" not in paths),
            ("gitignore 目录剪枝", "ignored/x.wav" not in paths),
            ("gitignore 语义", not ign_bad),
            (".env 被拦", paths.get(".env") is not None and paths[".env"].level == "blocker"),
            (".env.local 被拦", paths.get(".env.local") is not None),
            ("私钥被拦", paths.get("key.pem") is not None),
            ("文本里的 key 被拦", any(f.code == "SECRET" and f.path == "note.md" for f in findings)),
            ("无扩展名清单之外的文本也扫", any(f.code == "SECRET" and f.path == "main.go" for f in findings)
             and any(f.code == "SECRET" and f.path == "Dockerfile" for f in findings)),
            ("大文本不漏扫", any(f.code == "SECRET" and f.path == "huge.txt" for f in findings)),
            ("二进制不当文本", not any(f.path == "blob.dat" and f.code == "SECRET" for f in findings)),
            ("本机路径被提醒", any(f.code == "LOCAL_PATH" for f in findings)),
            ("大文件被提醒", any(f.code == "LARGE" for f in findings)),
            ("缓存被提醒", any(f.code == "JUNK" for f in findings)),
        ]
        print("preflight 自检")
        for name, passed in checks:
            print(f"  {name:18} {'✓' if passed else '✗'}")
            ok = ok and passed
        if ign_bad:
            print("   · .gitignore 判断不对：", ", ".join(ign_bad))
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
    ap.add_argument("--version", action="version", version="repo-preflight 0.2")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.target:
        ap.error("需要目录（或 --selftest）")
    root = Path(args.target)
    findings, stats = scan(root, args.allow_audio, args.max_mb)
    blockers = [f for f in findings if f.level == "blocker"]
    warns = [f for f in findings if f.level == "warn"]
    if not (args.quiet and not blockers):
        print(report(findings, stats, root.resolve()))
    if args.json:
        Path(args.json).write_text(json.dumps(
            {"findings": [f.as_dict() for f in findings], "stats": stats},
            ensure_ascii=False, indent=1), encoding="utf-8")
    if blockers:
        return 2
    return 1 if warns else 0


if __name__ == "__main__":
    sys.exit(main())
