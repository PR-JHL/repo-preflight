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
| **阻断**（exit 2） | 音频文件（`.wav/.mp3/.m4a/.aac/.flac/.ogg/.opus/.webm/...`，白名单除外）、密钥类文件（`.env`、`id_rsa`、`*.pem`、`*.key`、`credentials*`）、文本里的真 key（`AKIA…`、`ghp_…`、`github_pat_…`、`xox…`、`sk-…`、`AIza…`、私钥头）、`.git` 目录 |
| **提醒**（exit 1） | 本机用户路径（`C:\Users\…`、`/Users/…`、`/home/…`）、本机工作区路径、>8MB 文件、缓存/日志/临时文件、图片 EXIF 里的 GPS/相机信息 |

规则是启发式的：它能拦住「结构上不该发」的东西，不能替你看内容（比如一张没有 EXIF 的截图）。

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
```

退出码：`0` 干净 / `1` 只有提醒 / `2` 有阻断。按 `.gitignore` 跳过（支持 `!` 例外）。

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

```bash
python tools/publish_repo.py <目录> --dry-run     # 体检 + 文件清单，不碰网络
```

## 自检输出

```
preflight 自检
  个人录音被拦             ✓
  白名单音频放行            ✓
  gitignore 音频跳过     ✓
  .env 被拦            ✓
  私钥被拦               ✓
  文本里的 key 被拦          ✓
  本机路径被提醒            ✓
  大文件被提醒            ✓
  缓存被提醒              ✓
结果: 通过
```