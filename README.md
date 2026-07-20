# FlyPRO-rs

FlyPRO-rs 是对 FlyPRO 系列 Flash 编程器上位机能力的 Rust 重构。项目以
FlyPRO II V1.61（2026-07-14）的静态分析事实源为当前兼容基线。

本仓库采用 Cargo workspace，包含两个部分：

- `flypro-core`：不依赖界面的资产解析、协议编解码、传输抽象与会话状态机。
- `flypro-cli`：面向用户和诊断流程的命令行程序。

设计与实现范围见 [架构说明](docs/architecture.md)，真机取证步骤见
[USB 抓包计划](docs/usb-capture-plan.md)。

## 安全边界

当前证据只完整确认了算法验证、算法分块下发和器件参数下发三条应用层命令：
`0x0008`、`0x0087`、`0x008A`。读取、擦除、编程、OTP、保护位和固件升级等命令
尚未由真机抓包闭环，本项目不会根据调用顺序猜测或发送这些未知命令。

仓库在 `flypro-core` 中内嵌当前兼容基线的 92 个 `.alg` 文件，供器件记录按算法 stem
直接查询。官方安装包、固件、器件数据库和配置文件仍不提交；使用者应从有权使用的
FlyPRO II 发布快照中取得这些外部资产，并通过 CLI 做完整性检查。

## 内嵌算法

`flypro_core::assets::embedded_algorithms` 提供稳定顺序的全量遍历和不区分 ASCII 大小写
的 stem 查询。返回值包含完整原始 `.alg` 字节，并可通过现有严格解析器校验和解析：

```rust
use flypro_core::assets::embedded_algorithms::embedded_algorithm;

let asset = embedded_algorithm("W25Q128").expect("algorithm is bundled");
let algorithm = asset.parse()?;
assert_eq!(asset.file_name(), "w25q128.alg");
```

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

# 列出 VID:PID 为 5346:5109 的已连接编程器
cargo run -p flypro-cli -- usb list

# 只读导出系统缓存的 USB 描述符；不会 claim 接口或发端点传输
cargo run -p flypro-cli -- usb inspect --index 0 --json
```

USB 发现和描述符检查基于 `nusb`，由 Windows 的 WinUSB、macOS 的 IOKit 和 Linux 的
usbfs 原生后端完成。真实业务传输尚未接入 `flypro-core::transport::Transport`；在取得
真机描述符和单变量抓包前，CLI 不会 claim USB 接口或发送编程命令。

## 开发约定

- 所有变更使用 Conventional Commits。
- 一个提交只包含一个可独立解释和验证的修改。
- 兼容性代码和测试引用事实 ID；未知字段保留原始字节，不做有损命名。
- 破坏性操作在超时或未知执行状态后不得自动重试。
