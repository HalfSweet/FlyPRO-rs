# FlyPRO-rs

FlyPRO-rs 是对 FlyPRO 系列 Flash 编程器上位机能力的 Rust 重构。项目以
FlyPRO II V1.61（2026-07-14）的静态分析事实源为当前兼容基线。

本仓库采用 Cargo workspace，包含两个部分：

- `flypro-core`：不依赖界面的资产解析、协议编解码、传输抽象与会话状态机。
- `flypro-cli`：面向用户和诊断流程的命令行程序。

设计与实现范围见 [架构说明](docs/architecture.md)。

## 安全边界

当前证据只完整确认了算法验证、算法分块下发和器件参数下发三条应用层命令：
`0x0008`、`0x0087`、`0x008A`。读取、擦除、编程、OTP、保护位和固件升级等命令
尚未由真机抓包闭环，本项目不会根据调用顺序猜测或发送这些未知命令。

仓库不会提交官方安装包、固件、器件数据库或算法二进制。使用者应从有权使用的
FlyPRO II 发布快照中取得资产，并通过 CLI 做完整性检查。

## 当前 CLI

```bash
# 批量验证算法资产
cargo run -p flypro-cli -- algorithm verify-dir /path/to/ALG20

# 检查并查询器件数据库
cargo run -p flypro-cli -- device-db inspect /path/to/SP20.dev
cargo run -p flypro-cli -- device-db find /path/to/SP20.dev W25Q128

# 预览一个算法会产生的已确认命令块（不发送 USB 数据）
cargo run -p flypro-cli -- algorithm frames /path/to/w25q128.alg

# 检查配置资产
cargo run -p flypro-cli -- configuration inspect /path/to/w25q128s.cfg
```

CLI 目前只执行离线诊断。WinUSB 设备发现、描述符导出和真机传输将在取得 Windows
实机证据后接入 `flypro-core::transport::Transport`。

## 开发约定

- 所有变更使用 Conventional Commits。
- 一个提交只包含一个可独立解释和验证的修改。
- 兼容性代码和测试引用事实 ID；未知字段保留原始字节，不做有损命名。
- 破坏性操作在超时或未知执行状态后不得自动重试。
