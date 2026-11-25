# AGENTS.md

本仓库协作智能体约定：议题去向、领域文档，以及「怎么构建 / 怎么验证 / 怎么连目标板」。

## Agent skills

### Issue tracker

本仓库的 issue 记在 GitHub Issues（`guoyulong1/firmware_secure_download`），用 `gh` CLI 操作。见 `docs/agents/issue-tracker.md`。

### Domain docs

单上下文：根目录 `GLOSSARY.md` + `docs/adr/`。见 `docs/agents/domain.md`。

## 目标与约束

- 目标板：地平线X3（ARM64 Linux）。
- 本项目依赖 POSIX 与 Linux 工具链（g++/make/perl、`flock`/`fsync`/`pthread`/`dl`），**不要在 Windows 上直接构建/运行**。Windows 只做编辑与 git 调度；构建/运行放到 WSL2（x86_64 快速自检）或直接板载。

## 构建与验证

### 一键本地验证（Linux 侧，WSL2 或板载）

```bash
./scripts/verify.sh
```

等价于：`./3rdparty/fetch.sh`（首次，拉取并校验 curl/OpenSSL/googletest 源码）→ `cmake -S . -B build` → `cmake --build build` → `./build/firmware_secure_download --self-test` → `ctest --test-dir build --output-on-failure`。

**验证标准**：`--self-test` 退出码 0 是底线；GoogleTest 单元测试（ctest）全绿。失败即视为改动有问题。改动涉及网络/TLS/IO/下载编排时，还需在真机跑一次真实下载验证。

### 真机验证（板载）

```bash
./scripts/board-verify.sh
```

把改动同步到板子并在其上构建 + 自检。首次使用前需在板子上克隆本仓库一次（见下）。

### 目标板（地平线X3）访问

- SSH：`root@192.168.31.35:22`
- 免密私钥：`.ssh/id_ed25519`（已 gitignore）；公钥见 `.ssh/pubkey.txt`
- 非交互登录（脚本/智能体用）：

```bash
ssh -i .ssh/id_ed25519 \
    -o UserKnownHostsFile=.ssh/known_hosts \
    -o StrictHostKeyChecking=accept-new \
    root@192.168.31.35 "uname -a"
```

> 本机 `~/.ssh/known_hosts` 在沙箱工作区之外，写入会被拦；务必用工作区内的 `-o UserKnownHostsFile=.ssh/known_hosts`。

首次在板子上准备仓库（板子能访问 GitHub 时）：

```bash
ssh root@192.168.31.35 "git clone https://github.com/guoyulong1/firmware_secure_download.git /home/root/workspace/firmware_secure_download"
```

## 仓库约定

- 分支：`main` 保持可构建；功能走 feature 分支 + PR；CI（`.github/workflows/ci.yml`）跑 ARM64 构建 + `--self-test`，merge 前必须绿。
- 设计文档：`doc/OTA.md` 是 OTA 端到端设计基线；代码行为与其冲突时，先对齐文档再改。
