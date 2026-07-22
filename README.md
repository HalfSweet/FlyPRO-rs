# FlyPRO-rs

FlyPRO-rs 是一个面向硕飞 SP10/SP20 烧录器的跨平台 Rust 命令行工具，用于读取 USB
信息、查询器件资料，并执行实验性的芯片读写操作。

> [!IMPORTANT]
> **SP10 和 SP20 是硕飞烧录器的产品系列；FlyPro 是配套上位机软件的名称。**
> FlyPRO-rs 是本项目的名称，不代表存在名为“FlyPRO”的烧录器系列。

当前协议实现来自对 FlyPro II V1.61（2026-07-14）的静态分析，尚未完成所有型号、固件和
芯片的实机验证。读取、查空等操作也必须显式接受这一风险；编程、擦除和配置写入会修改
芯片内容，并要求二次确认。

## 功能概览

- 枚举 SP10/SP20 烧录器并导出 USB 描述符；
- 使用原版 `M25ID` 流程自动识别部分 25 系列 SPI Flash，并列出所有匹配候选；
- 查询内置器件数据库、算法和配置资产；
- 准备算法及器件参数；
- 查空、读取、校验、编程和擦除芯片；
- 读取、校验和写入配置区；
- 校验外部 `.alg`、`.cfg` 和 `SP20.dev` 资产。

## 编译

### 环境要求

- Rust 1.85 或更高版本（推荐通过 [rustup](https://rustup.rs/) 安装）；
- 一个支持 Rust 2024 edition 的 Cargo；
- 如需连接烧录器，系统必须允许当前用户访问对应 USB 设备。

克隆仓库并进入项目目录：

```bash
git clone https://github.com/HalfSweet/FlyPRO-rs.git
cd FlyPRO-rs
```

然后执行发布构建：

```bash
cargo build --release
```

编译产物位于：

- Linux/macOS：`target/release/flypro`
- Windows：`target\release\flypro.exe`

也可以安装到 Cargo 的可执行文件目录：

```bash
cargo install --path flypro-cli --locked
```

编译本身不需要接入烧录器。提交修改前建议运行完整检查：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### USB 权限

- Windows 使用 WinUSB 后端。修改设备驱动前请确认不会影响官方 FlyPro 软件。
- macOS 使用 IOKit，通常不需要额外驱动。
- Linux 使用 usbfs；如果普通用户没有权限，可按发行版规则为 `5346:5109` 添加 udev 规则，
  或先以有权限的账户验证。不要长期使用宽泛的 USB 授权规则。

## 使用

以下示例假设 `flypro` 已通过 `cargo install` 安装。若只执行了本地编译，请将命令替换为
`./target/release/flypro`；开发时也可以使用 `cargo run -p flypro-cli --` 作为前缀。

### 1. 确认烧录器连接

```bash
flypro usb list
flypro usb inspect --index 0 --json
```

这两条命令只读取系统缓存的 USB 信息，不会占用设备接口，也不会向端点发送数据。

### 2. 自动识别 SPI Flash

将支持的 25 系列 SPI Flash 放入锁紧座后，可按 3.3 V（默认）执行非破坏性识别：

```bash
flypro device identify --accept-static-protocol
```

识别会下载专用 `M25ID` 算法并读取原始 8 字节结果，但不会发送器件参数、擦除或写入芯片。
同一 ID 可能对应多个具体型号或封装，因此命令会列出全部候选，不会自动选中第一项。使用者仍须
根据芯片丝印和实物封装确认后，再把对应 `--chip` 与 `--package-key` 传给读写命令。

1.8 V 器件必须使用正确的转接和供电条件，并显式指定电压：

```bash
flypro device identify --voltage 1.8 --accept-static-protocol
```

添加 `--json` 可保留原始回包、未知字节、状态值和完整候选列表。

### 3. 手动查找芯片和封装参数

```bash
flypro device-db find W25Q128
```

从输出中确认完整芯片型号和 `packages` 字段中的封装 key。工具不会根据 SOIC、WSON、ISP
等文字自行猜测封装或接线方式。

### 4. 读取芯片

以下命令使用索引为 `0` 的烧录器读取所选区域，并写入 `read.bin`：

```bash
flypro device read \
  --chip W25Q128BV \
  --package-key 150 \
  --accept-static-protocol \
  --output read.bin
```

没有传入 `--length` 时，默认读取所选区域的完整容量。若同名芯片对应多个厂商，可增加
`--vendor`；可用 `--programmer-index` 选择其他烧录器。

### 5. 校验或写入芯片

校验文件不会修改芯片：

```bash
flypro device verify \
  --chip W25Q128BV \
  --package-key 150 \
  --accept-static-protocol \
  --input image.bin
```

编程属于破坏性操作，必须额外传入 `--yes`：

```bash
flypro device program \
  --chip W25Q128BV \
  --package-key 150 \
  --accept-static-protocol \
  --yes \
  --input image.bin
```

输入数据按 `0x800` 字节边界以 `0xff` 对齐。超时、短传输、取消或拔线后，工具不会自动
重试，也不会继续复用当前 USB 会话；请先人工确认芯片状态。

### 其他常用命令

```bash
# 检查内置器件数据库
flypro device-db inspect

# 校验目录中的算法或配置资产
flypro algorithm verify-dir /path/to/ALG20
flypro configuration verify-dir /path/to/CFG

# 查看算法对应的已确认命令块（不发送 USB 数据）
flypro algorithm frames /path/to/w25q128.alg

# 查看某个子命令的全部参数
flypro device erase --help
flypro device config-write --help
```

外部器件数据库、算法、配置和 `SPRJ` 参数镜像可通过高级选项覆盖。覆盖文件仍会经过格式、
名称和 CRC 校验；具体参数以 `flypro <COMMAND> --help` 为准。

## 项目结构与文档

- `flypro-cli`：命令行入口和面向用户的操作流程；
- `flypro-core`：资产解析、协议、参数、会话状态机和 USB 传输；
- [架构设计](docs/architecture.md)：模块边界、依赖方向和数据流；
- [实现细节](docs/implementation.md)：资产格式、协议阶段、状态机和已知限制；
- [USB 实机验证计划](docs/usb-validation.md)：抓包、对照实验和证据闭环标准；
- [贡献规范](CONTRIBUTING.md)：开发风格、提交规范和检查要求。

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 授权。
