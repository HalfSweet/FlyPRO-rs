# 实现细节

本文记录当前兼容基线、数据约束和协议状态机。高层模块关系见 [架构设计](architecture.md)。

## 事实与兼容基线

当前实现以 FlyPro II V1.61（2026-07-14）的静态分析结果为兼容基线。证据按以下规则进入
代码：

1. `CONFIRMED` 可实现为严格解析、类型和 golden test；
2. `INFERRED` 只能位于可替换边界后，API 和日志必须保留不确定性；
3. `UNKNOWN` 不得硬编码为协议语义，相关能力保持不可用或要求额外证据；
4. `PROPOSAL` 只描述本项目设计，不能反向视为 FlyPro 软件的既有事实。

真实设备命令仍属于实验路径，必须显式传入 `--accept-static-protocol`。编程、擦除和配置
写入还要求 `--yes`。

## 内置资产

`flypro-core` 在编译时包含当前基线的：

- `SP20.dev` 器件数据库，共 4576 条记录；
- `PkgID20.ini` 封装映射；
- 92 个 `.alg` 算法文件；
- 389 个 `.cfg` 配置文件。

所有封装外键和非空 CFG 外键均经过测试。`.alg`、`.cfg` 和 `SP20.dev` 的外部覆盖也使用
相同的严格解析路径。

关键约束如下：

- `.alg` 的 `0x4000` 字节负载在主机端保持不透明，不解释或改写；
- `SP20.dev` 中未命名的字段保留在原始 144 字节记录中；
- `SPRJ` 的 2048 字节器件参数镜像是独立强类型对象；
- 外部 `SPRJ` 必须通过结构、CRC 和算法身份校验；
- 自动参数构造只写入已确认的 DEV 映射、CFG 默认块、操作码、区域掩码、工程范围和新工程
  默认值，其余未命名字节保持为零。

`flypro_core::assets::embedded_algorithms` 支持稳定顺序的全量遍历，以及不区分 ASCII 大小写
的 stem 查询：

```rust
use flypro_core::assets::embedded_algorithms::embedded_algorithm;

let asset = embedded_algorithm("W25Q128").expect("algorithm is bundled");
let algorithm = asset.parse()?;
assert_eq!(asset.file_name(), "w25q128.alg");
```

## 算法准备状态机

算法准备按以下顺序执行：

1. 加载并严格校验算法文件；
2. 如果当前主机会话标记 ready，使用 `0x0008` 校验设备端算法名称和哨兵值；
3. 新会话或校验不匹配时，以 `0x0087` 按最多 `0x800` 字节逐块下发；
4. 每块依次完成 command OUT、payload OUT 和 completion IN；
5. 全部块完成后等待 100 ms，再用 `0x0008` 复验；
6. 无论复用还是重新下载，都通过 `0x008A` 下发独立的 2048 字节器件参数；
7. 所有阶段成功后才返回 `AlgorithmReady`。

## 操作状态机

准备完成后，`OperationSession` 串行执行以下事务：

| 操作 | 命令或阶段 |
|---|---|
| 查空 | `0x0015 -> 0x0014* -> 0x0016` |
| 编程 | `0x0019 -> (0x0098 + payload)* -> 0x001A` |
| 读取/校验 | `0x001B -> 0x001D -> data* -> 0x001E` |
| 配置写入 | `0x00A3` |
| 配置读取 | `0x0025` |
| 擦除 | `0x0013`，携带原始路径选择值和明确模式 |
| 事件流 | `0x003A -> 0x85* -> 0x82` |

输入工程按 `0x800` 边界以 `0xff` 对齐，同一有效范围用于参数镜像元数据和实际编程或校验
传输。`read` 与 `blank-check` 未指定 `--length` 时使用所选区域容量。配置写入或校验没有
指定 `--data`、`--mask` 时，默认使用 CFG 的 block 0 和 block 1。

`0x82` 仅实现已确认的接受谓词，不对各个位赋予未经验证的业务名称；原始状态会完整保留。

## USB 后端

设备发现和传输使用 `nusb` 的原生平台后端：Windows 使用 WinUSB，macOS 使用 IOKit，
Linux 使用 usbfs。

- 当前发现条件为 VID:PID `5346:5109`；
- 描述符检查不会 claim 接口或进行端点传输；
- 真实操作会独占 claim 包含已知 Pipe 的接口；
- Bulk 或 Interrupt 类型及最大包长均从运行时描述符读取，不硬编码；
- 传输接口要求精确长度，短传输视为失败；
- 超时或取消后不复用该 USB 会话。

## 尚未闭环的能力

以下内容仍需真机抓包或对照实验，不能视为稳定 API：

- 自动参数镜像与官方 FlyPro 软件输出的逐字节一致性；
- 各 SP10/SP20 型号及固件的端点、状态和诊断兼容性；
- 擦除 `path_selector` 各位的业务含义；
- OTP、保护位、固件升级和脱机烧录；
- bootloader 模式、通用诊断和 ATE 电气规格。

验证顺序与证据要求见 [USB 实机验证计划](usb-validation.md)。
