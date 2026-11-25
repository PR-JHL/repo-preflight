# -*- coding: utf-8 -*-
"""repo-preflight 的回归测试（标准库 unittest，无第三方依赖）。

跑法：
    python -m unittest discover -s tests -v
或：
    python tests/test_preflight.py

这里刻意不用 pytest：这个工具承诺「无依赖」，测试也不该先要人装东西。
假 key 一律用拼接生成 —— 否则体检工具扫自己仓库时会把测试样本当成真泄漏。
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import preflight as pf  # noqa: E402

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GHP = "ghp_" + "a" * 36
SK = "sk-" + "abcdefghijklmnopqrstuvwxyz012345"
PRIVATE_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----"


def write(root: Path, rel: str, text: str = "x\n") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


class TestGitignore(unittest.TestCase):
    """`.gitignore` 的常见写法必须真的生效 —— 它同时是「别把录音扫进来」的闸门。"""

    TABLE = [
        # (模式, 路径, 期望被忽略)
        ("build/", "build/out.js", True),
        ("build/", "src/build/out.js", True),        # 不带 / 的模式任意深度
        ("build/", "build.py", False),               # 目录模式不误伤同名文件
        ("*.log", "debug.log", True),
        ("*.log", "deep/nested/trace.log", True),
        ("*.log", "src/logs.py", False),
        ("dist/**", "dist/app/main.js", True),
        ("dist/**", "dist", False),
        ("**/cache/", "a/b/cache/x.txt", True),
        ("**/cache/", "cache/x.txt", True),
        ("/root-only.txt", "root-only.txt", True),
        ("/root-only.txt", "sub/root-only.txt", False),
        ("docs/*.tmp", "docs/note.tmp", True),
        ("docs/*.tmp", "docs/deep/note.tmp", False),
        ("temp*", "tempfile.txt", True),
        ("sub/**/*.bak", "sub/x.bak", True),
        ("sub/**/*.bak", "sub/a/b/x.bak", True),
        ("bench-modes-*/", "bench-modes-1/rec.wav", True),
        ("*.wav", "tests/data/tts_zh.wav", True),
        ("data[0-9].bin", "data7.bin", True),
    ]

    def test_table(self):
        for pat, rel, want in self.TABLE:
            with self.subTest(pattern=pat, path=rel):
                self.assertIs(pf.is_ignored(rel, [pat]), want)

    def test_negation_last_wins(self):
        pats = ["*.wav", "!tests/data/tts_zh.wav"]
        self.assertTrue(pf.is_ignored("bench/rec.wav", pats))
        self.assertFalse(pf.is_ignored("tests/data/tts_zh.wav", pats))

    def test_negation_inside_excluded_dir_does_not_resurrect(self):
        """`bench/` + `!bench/keep.wav`：git 也不会把已排除目录里的文件找回来。"""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".gitignore").write_text("bench/\n!bench/keep.wav\n", encoding="utf-8")
            (root / "bench").mkdir()
            (root / "bench" / "keep.wav").write_bytes(b"RIFF....WAVE")
            findings, _ = pf.scan(root)
            self.assertFalse([f for f in findings if f.path.startswith("bench/")])

    def test_load_gitignore_skips_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".gitignore").write_text("# 注释\n\n*.log\n", encoding="utf-8")
            self.assertEqual(pf.load_gitignore(root), ["*.log"])


class TestAllowList(unittest.TestCase):
    def test_exact_and_glob(self):
        allow = ["tests/data/tts_zh.wav", "assets/*.wav"]
        self.assertTrue(pf.is_allowed("tests/data/tts_zh.wav", allow))
        self.assertTrue(pf.is_allowed("assets/clip.wav", allow))
        self.assertFalse(pf.is_allowed("bench/rec.wav", allow))

    def test_double_star(self):
        self.assertTrue(pf.is_allowed("assets/a/b/clip.wav", ["assets/**"]))
        self.assertTrue(pf.is_allowed("assets/a/b/clip.wav", ["assets/"]))
        self.assertFalse(pf.is_allowed("other/clip.wav", ["assets/**"]))

    def test_backslashes_normalized(self):
        self.assertTrue(pf.is_allowed("assets/clip.wav", ["assets\\clip.wav"]))


class TestSecretFiles(unittest.TestCase):
    def test_env_family(self):
        self.assertEqual(pf._secret_name_reason(".env"), "环境变量文件，几乎一定含密钥")
        self.assertIsNotNone(pf._secret_name_reason(".env.local"))
        self.assertIsNotNone(pf._secret_name_reason(".env.production"))
        self.assertIsNone(pf._secret_name_reason(".env.example"))
        self.assertIsNone(pf._secret_name_reason(".env.template"))

    def test_known_secret_names(self):
        for name in ("id_rsa", "id_ed25519", ".git-credentials", ".netrc", "credentials.json"):
            with self.subTest(name=name):
                self.assertIsNotNone(pf._secret_name_reason(name))

    def test_ordinary_names_pass(self):
        for name in ("README.md", "main.py", ".gitignore", ".preflight-allow", ".npmrc"):
            with self.subTest(name=name):
                self.assertIsNone(pf._secret_name_reason(name))


class TestTextDetection(unittest.TestCase):
    def test_code_files_without_known_extension_are_scanned(self):
        for rel, body in [
            ("main.go", f'const k = "{AWS}"\n'),
            ("Main.java", f'String k = "{SK}";\n'),
            ("lib.rs", f'let k = "{GHP}";\n'),
            ("Dockerfile", f'ENV K="{AWS}"\n'),
            ("misc/notes.weird", f'token: {SK}\n'),
        ]:
            with self.subTest(path=rel), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                write(root, rel, body)
                findings, _ = pf.scan(root)
                self.assertTrue(
                    any(f.code == "SECRET" and f.level == "blocker" and f.path == rel
                        for f in findings), f"{rel} 里的密钥没被拦住")

    def test_binary_file_is_not_read_as_text(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "blob.dat").write_bytes(b"\x00\x01" + PRIVATE_KEY.encode())
            findings, _ = pf.scan(root)
            self.assertFalse([f for f in findings if f.code == "SECRET"])

    def test_large_text_is_scanned_past_old_2mb_limit(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "logs/huge.txt", "x" * (3 * 1024 * 1024) + f"\n{AWS}\n")
            findings, _ = pf.scan(root)
            self.assertTrue(any(f.code == "SECRET" and f.path == "logs/huge.txt" for f in findings))

    def test_truncation_is_reported_as_info(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "big.txt", "line\n" * 10)
            old = pf.SCAN_TEXT_MAX
            pf.SCAN_TEXT_MAX = 10          # 只允许扫 10 字节
            try:
                findings, _ = pf.scan(root)
            finally:
                pf.SCAN_TEXT_MAX = old
            self.assertTrue(any(f.level == "info" and f.code == "SCAN_TRUNCATED" for f in findings))

    def test_soft_patterns_warn_not_block(self):
        jwt = ".".join(["eyJ" + "a" * 12, "b" * 12, "c" * 12])
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "doc.md", f"token: {jwt}\n")
            findings, _ = pf.scan(root)
            self.assertTrue(all(f.level != "blocker" for f in findings))
            self.assertTrue(any(f.code == "SECRET_HINT" for f in findings))


class TestImageExif(unittest.TestCase):
    def test_missing_pillow_is_reported_not_silent(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "shot.png").write_bytes(
                b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
            findings = pf.scan_file(root, root / "shot.png", "shot.png", [], 8.0, pil=False)
            self.assertTrue(any(f.code == "EXIF_SKIPPED" and f.level == "info" for f in findings))


class TestCli(unittest.TestCase):
    def run_main(self, argv) -> tuple[int, str]:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = pf.main(argv)
        return code, buf.getvalue()

    def test_exit_codes_and_json(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "src/ok.py", "print('hi')\n")
            code, _ = self.run_main([str(root)])
            self.assertEqual(code, 0)

            write(root, "note.md", "path: " + "C:" + "\\Users\\someone\\a.txt\n")
            code, _ = self.run_main([str(root)])
            self.assertEqual(code, 1)

            write(root, ".env", "TOKEN=abc\n")
            out_json = root / "out.json"
            code, out = self.run_main([str(root), "--json", str(out_json)])
            self.assertEqual(code, 2)
            self.assertIn("阻断", out)
            data = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertTrue(any(f["level"] == "blocker" for f in data["findings"]))

    def test_quiet_prints_nothing_when_clean(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            write(root, "src/ok.py", "print('hi')\n")
            code, out = self.run_main([str(root), "--quiet"])
            self.assertEqual(code, 0)
            self.assertEqual(out.strip(), "")

    def test_selftest_passes(self):
        code, out = self.run_main(["--selftest"])
        self.assertEqual(code, 0, out)
        self.assertIn("结果: 通过", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
