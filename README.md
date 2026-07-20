# FlyPRO-rs

FlyPRO-rs 是对 FlyPRO 系列 Flash 编程器上位机能力的 Rust 重构。项目以
FlyPRO II V1.61（2026-07-14）的静态分析事实源为当前兼容基线。

本仓库采用 Cargo workspace，包含两个部分：

- `flypro-core`：不依赖界面的资产解析、协议编解码、传输抽象与会话状态机。
- `flypro-cli`：面向用户和诊断流程的命令行程序。

设计与实现范围见 [架构说明](docs/architecture.md)，后续真机验证步骤见
[USB 验证计划](docs/usb-capture-plan.md)。

## 安全边界

当前实现以静态闭环事实 `F-PROTO-022`～`033` 为依据，已经编码算法准备、`SPRJ`
参数镜像、查空、读取、校验、编程、配置读写、擦除和进度事件状态机。这些真实设备命令
尚未经过物理硬件验证，CLI 因而要求显式传入 `--accept-static-protocol`；编程、擦除和配置
写入还要求 `--yes`。超时、短传输或取消后不会自动重试，USB 会话也不会继续复用。

OTP、保护位、固件升级、脱机烧录以及擦除 `path_selector` 各位的业务名称仍未闭环，项目
不会把这些未知字段猜测成稳定 API。

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

# 真实设备只读操作：会 claim 接口、准备内嵌算法并下发匹配的 SPRJ
cargo run -p flypro-cli -- device read \
  --algorithm w25q128 \
  --parameters /path/to/w25q128.sprj \
  --accept-static-protocol \
  --region 0 --length 0x100 --output read.bin

# 破坏性操作额外要求 --yes
cargo run -p flypro-cli -- device program \
  --algorithm w25q128 \
  --parameters /path/to/w25q128.sprj \
  --accept-static-protocol --yes \
  --region 0 --input image.bin
```

USB 发现和描述符检查基于 `nusb`，由 Windows 的 WinUSB、macOS 的 IOKit 和 Linux 的
usbfs 原生后端完成。真实业务传输会在运行时从描述符选择 Bulk 或 Interrupt 端点，不对
尚未取得的端点类型和最大包长做硬编码。

当前 CLI 要求调用者提供严格 2048 字节的 `SPRJ` 文件。文件在打开 USB 前会检查 magic、
版本、整体 CRC，并核对其算法名称、时间戳、负载长度和负载 CRC 与所选内嵌算法完全匹配。
`flypro-core::parameters` 已提供确定性的 `SPRJ` 构造器；但从 `SP20.dev`/`.cfg` 自动组装
`0xA28` 运行时 profile 的规则尚未完整命名，因此 CLI 不会用补零 profile 生成可疑参数。

## 开发约定

- 所有变更使用 Conventional Commits。
- 一个提交只包含一个可独立解释和验证的修改。
- 兼容性代码和测试引用事实 ID；未知字段保留原始字节，不做有损命名。
- 破坏性操作在超时或未知执行状态后不得自动重试。
