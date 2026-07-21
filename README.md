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

仓库在 `flypro-core` 中内嵌当前兼容基线的 `SP20.dev`、封装映射、92 个 `.alg` 和 389 个
`.cfg` 文件。默认器件库包含 4576 条记录，且所有封装、非空 CFG 外键都经过测试；CLI
只在调试其他发布快照时才需要外部资产。

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

# 检查并查询内嵌器件数据库；需要时用 --database 覆盖
cargo run -p flypro-cli -- device-db inspect
cargo run -p flypro-cli -- device-db find W25Q128
cargo run -p flypro-cli -- device-db inspect --database /path/to/SP20.dev

# 预览一个算法会产生的已确认命令块（不发送 USB 数据）
cargo run -p flypro-cli -- algorithm frames /path/to/w25q128.alg

# 检查配置资产
cargo run -p flypro-cli -- configuration inspect /path/to/w25q128s.cfg

# 列出 VID:PID 为 5346:5109 的已连接编程器
cargo run -p flypro-cli -- usb list

# 只读导出系统缓存的 USB 描述符；不会 claim 接口或发端点传输
cargo run -p flypro-cli -- usb inspect --index 0 --json

# 真实设备只读操作：封装 key 来自 device-db find 的 packages 字段
cargo run -p flypro-cli -- device read \
  --chip W25Q128BV \
  --package-key 150 \
  --accept-static-protocol \
  --output read.bin

# 破坏性操作额外要求 --yes
cargo run -p flypro-cli -- device program \
  --chip W25Q128BV \
  --package-key 150 \
  --accept-static-protocol --yes \
  --input image.bin

# 配置写入默认使用该器件 CFG 的 block 0 和 block 1
cargo run -p flypro-cli -- device config-write \
  --chip W25Q128BV \
  --package-key 150 \
  --accept-static-protocol --yes
```

USB 发现和描述符检查基于 `nusb`，由 Windows 的 WinUSB、macOS 的 IOKit 和 Linux 的
usbfs 原生后端完成。真实业务传输会在运行时从描述符选择 Bulk 或 Interrupt 端点，不对
尚未取得的端点类型和最大包长做硬编码。

自动参数模式要求 `--chip`、器件记录允许的 `--package-key` 和风险确认参数。CLI 不会猜测
SOIC、WSON 或 ISP 接线；它会按封装映射填充 `SPRJ` 的封装类型与路由标志，再按器件记录
自动选择算法和 CFG。输入工程按 `0x800` 边界以 `0xff` 对齐，同一范围同时用于 `SPRJ`
元数据和实际编程/校验传输。`read` 与 `blank-check` 未传 `--length` 时使用所选区域容量；
配置写入/校验未传 `--data` 或 `--mask` 时使用 CFG 的两个默认块。传入外部 `--parameters`
时可以省略 `--package-key`，因为封装上下文已经包含在该 SPRJ 中。

高级诊断仍可用 `--vendor` 消除同名器件歧义，并用 `--device-database`、`--configuration`、
`--algorithm` 或 `--parameters` 覆盖自动选择结果。外部 `SPRJ` 仍会执行严格校验；自动构造
只填充静态分析已确认的转换字段和新工程默认值，尚未命名的字段保持零值，真机逐字节对照
仍属于验证计划。

## 开发约定

- 所有变更使用 Conventional Commits。
- 一个提交只包含一个可独立解释和验证的修改。
- 兼容性代码和测试引用事实 ID；未知字段保留原始字节，不做有损命名。
- 破坏性操作在超时或未知执行状态后不得自动重试。
