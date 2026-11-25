# repo-preflight · 发布前体检

把「发布前人工确认一遍有没有把不能发的东西带上去」变成一条命令 + 一个退出码，
并给 `tools/publish_repo.py` 当闸门。

## 为什么

公开仓库发出去就撤不回来。真实场景里最常出事的三类东西：

1. **个人录音**（`bench/`、`bench-modes-*/` 这种语音项目特有）；
2. **密钥**（`.env`、私钥、写在代码里的 `sk-...`）；
3. **本机路径/个人信息**（`C:\Users\<你>\...`、带 GPS 的照片）。

靠记性检查，第一次能记住，第十次一定漏。这个工具把规则写成代码，发布脚本只在体检
通过时才继续。

## 检查什么

| 级别 | 内容 |
|---|---|
| **阻断**（exit 2） | 音频文件（`.wav/.mp3/.m4a/.aac/.flac/.ogg/.opus/.webm/...`，白名单除外）、密钥类文件（`.env` 及其 `.env.local/.env.production` 等变体、`id_rsa*`、`.git-credentials`、`.netrc`、`*.pem/*.key/*.p12/*.ppk/...`）、文本里的真 key（`AKIA…`、`ghp_…`、`github_pat_…`、`xox…`、Slack Webhook、`sk-…`、`sk_live_…`、`AIza…`、`LTAI…`、npm `_authToken`、私钥头）、`.git` 目录 |
| **提醒**（exit 1） | 本机用户路径（`C:\Users\…`、`C:/Users/…`、`/Users/…`、`/home/…`）、本机工作区路径、>8MB 文件、缓存/日志/临时文件、图片 EXIF 里的 GPS/相机信息、像 JWT 或 `password = "…"` 的赋值 |
| **信息**（不影响退出码） | 体检自身覆盖到哪：某个文件太大只扫了一部分、没装 Pillow 所以图片 EXIF 没检查 |

**「文本」按内容判断，不按扩展名**：前 8KB 没有 NUL 字节就当文本扫。这样 `main.go`、
`Main.java`、`lib.rs`、`Dockerfile`、没有扩展名的配置文件里的密钥也会被扫到 ——
按扩展名白名单的做法会整份放过它们（v0.1 的漏洞，v0.2 修掉）。
单个文本文件最多扫 64MB，超了会在报告里明说「只扫了前 64MB」，不会假装扫过。

规则是启发式的：它能拦住「结构上不该发」的东西，不能替你看内容（比如一张没有 EXIF 的截图、
base64 之后再拼起来的密钥）。

## 用法

```bash
# 体检（人看）
python preflight.py <目录>

# 机器可读
python preflight.py <目录> --json out.json

# 明确允许某个音频（可重复；也支持 glob）
python preflight.py <目录> --allow-audio tests/data/tts_zh.wav

# 跑自带用例（验证规则本身没坏）
python preflight.py --selftest

# 回归测试（19 个用例：gitignore 语义、白名单、文本判断、退出码、信息级）
python -m unittest discover -s tests -v
```

退出码：`0` 干净 / `1` 只有提醒 / `2` 有阻断。按 `.gitignore` 跳过。

## `.gitignore` 支持到什么程度

按 git 的常见语义实现（不是完整实现）：`dir/`、`*.ext`（任意深度）、`a/b`（锚定根）、
`**/x`、`x/**`、`a/**/b`、`?`、`[...]`，以及 `!` 例外（后面的规则覆盖前面的）。

和 git 一致的两条：目录被排除后不再进去找（里面的 `!` 例外救不回来）；
**不读**子目录里的 `.gitignore`（只读根目录那一份）。

## 长期允许清单

在要发布的目录里放一个 `.preflight-allow`，每行一个相对路径或 glob（`#` 注释）：

```text
# 单测用的 TTS 合成样本，不是真人录音
tests/data/tts_zh.wav
```

## 接进发布脚本

`tools/publish_repo.py` 已经接好：发布前先跑体检，**有阻断就拒绝发布**并打印报告；
放行方式只有两种——写进 `.preflight-allow`，或者命令行 `--allow-audio`。
不建议用 `--skip-preflight`。

「要不要发」和「发了什么」用的是同一份 `.gitignore` 实现：发布脚本的文件清单
直接调体检模块的 `is_ignored`，避免「体检跳过的文件被悄悄发出去」。

```bash
python tools/publish_repo.py <目录> --dry-run     # 体检 + 文件清单，不碰网络
```

## 自检输出

```
preflight 自检
  个人录音被拦             ✓
  白名单音频放行            ✓
  gitignore 目录剪枝     ✓
  gitignore 语义         ✓
  .env 被拦            ✓
  .env.local 被拦      ✓
  私钥被拦               ✓
  文本里的 key 被拦          ✓
  无扩展名清单之外的文本也扫      ✓
  大文本不漏扫             ✓
  二进制不当文本            ✓
  本机路径被提醒            ✓
  大文件被提醒             ✓
  缓存被提醒              ✓
结果: 通过
```

## 局限（自己先说）

- 二进制文件不做内容扫描：`.dat/.pkl/.zip` 里塞一坨密钥查不出来（这类东西本来就该用文件名规则）；
- UTF-16 文本（开头有 NUL）会被当成二进制；
- 只读根目录的 `.gitignore`，子目录里的忽略规则和 `.git/info/exclude` 不看；
- 阈值是经验值：8MB 大文件、64MB 扫描上限，太大/太小的仓库可能需要 `--max-mb` 调。
