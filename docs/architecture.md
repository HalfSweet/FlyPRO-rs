# 架构与实现边界

## 1. 事实基线

当前基线来自 `/Users/halfsweet/Documents/sp/FlyPROII_重构事实源`。实现采用以下证据规则：

1. `CONFIRMED` 可转成严格解析、类型和 golden test。
2. `INFERRED` 只能位于可替换边界后，API 和日志必须保留其不确定性。
3. `UNKNOWN` 不得硬编码为协议语义；相关能力保持不可用或要求外部证据策略。
4. `PROPOSAL` 只用于本项目架构，不能反向声称为旧软件事实。

关键事实到首轮模块的映射如下：

| Rust 模块 | 职责 | 事实依据 |
|---|---|---|
| `assets::algorithm` | 严格校验 `.alg` 布局、名称、负载边界和 CRC32 | `F-ALG-010`～`020` |
| `assets::embedded_algorithms` | 编译期内嵌并按 stem 查询全部 92 个基线算法 | `F-ALG-001`～`020` |
| `assets::device_db` | 无损解析 `SP20.dev`、厂商/器件索引和算法/cfg 外键 | `F-DEV-001`～`015` |
| `assets::defaults` | 内嵌、缓存并校验默认 `SP20.dev`（4576 条器件记录） | `F-DEV-001`～`015` |
| `assets::embedded_configurations` | 构建期注册并按 stem 查询全部 389 个 CFG | `F-CFG-001`～`009` |
| `protocol` | 编码算法、业务命令、状态谓词与诊断块 | `F-PROTO-001`～`033` |
| `parameters` | 从显式 profile 构造 `SPRJ`，或由器件/算法/CFG/操作自动推导 | `F-PROTO-022`～`023` |
| `transport` | 用精确长度、Pipe、超时和取消表达分阶段传输 | `F-USB-010`～`019` |
| `session` | 验证复用、按需下载、复验、下发器件参数 | `F-ALG-021`～`026` |
| `operations` | 查空、编程、读取、校验、配置、擦除与事件流状态机 | `F-PROTO-024`～`033` |
| `usb` | 跨平台只读设备发现、描述符导出和 Pipe 集合核对 | `F-USB-001`～`019` |
| `usb_transport` | 动态打开 Bulk/Interrupt 端点并实现精确 I/O、超时和取消恢复 | `F-USB-010`～`019`、`F-PROTO-030` |
| CLI | 资产诊断、USB 诊断和显式选择的实验性真实设备操作 | `T-ALG-*`、`T-DEV-*`、`T-PROTO-*` |

## 2. Workspace 边界

```text
flypro-cli
    └── flypro-core
            ├── assets
            │   ├── defaults
            │   ├── embedded_algorithms
            │   └── embedded_configurations
            ├── protocol
            ├── parameters
            ├── session
            ├── operations
            ├── transport
            ├── usb
            └── usb_transport
```

`flypro-core` 是唯一允许表达设备协议和资产格式的 crate。CLI 只调用领域 API，不得拼接
端点号或裸命令块。设备发现和真实传输通过 `nusb` 使用 Windows WinUSB、macOS IOKit 和
Linux usbfs；平台句柄不会进入公共领域模型。只读描述符路径不 claim 接口，真实设备路径
则独占 claim 含六个已知 Pipe 的接口，并从描述符动态选择 Bulk 或 Interrupt 传输。

首轮只使用两个 workspace 成员，避免在证据尚少时把每个概念拆成大量稳定性不足的 crate。
当 USB 传输后端、生产审计或多机调度形成独立发布边界后，再按依赖方向拆分，而不是预先拆包。

## 3. 类型化数据流

```text
内嵌或显式覆盖的发布资产
  -> 严格导入器
  -> Algorithm / DeviceDatabase / Configuration
  -> 操作与区域默认推导
  -> DeviceParameterImage
  -> AlgorithmSession
  -> OperationSession
  -> 已确认的命令块、负载与响应
  -> Transport trait
  -> nusb 跨平台 USB 后端
```

几个重要约束：

- `.alg` 的 `0x4000` 字节负载始终是不透明字节，不在主机端解释或改写。
- `SP20.dev` 未命名字段以原始 144 字节记录保留。
- `0x008A` 的 2048 字节参数是独立强类型对象；外部 `SPRJ` 必须通过结构、CRC 和算法身份校验。
- 低层构造器继续接受显式 `0xA28` profile；高层构造器只映射已静态确认的 DEV 转换字段、
  CFG 默认块、新工程初始化值、操作码、区域掩码和工程范围，其他 profile 字节保持零值。
- 默认数据库、算法和配置均在 `flypro-core`；CLI 覆盖路径不会绕过格式、名称和 CRC 校验。
- 每条事务显式声明 command OUT、payload OUT、response IN 或 completion IN 阶段。
- `0x82` 使用静态确认的接受谓词；不为各个位擅自命名业务语义，并完整保留原始状态。
- 任何 I/O 失败、短传输、超时或取消都会使当前 USB 传输对象不可继续使用。

## 4. 操作状态机

已确认的算法准备流程为：

1. 加载并严格校验算法文件。
2. 若当前主机会话标记 ready，使用 `0x0008` 验证设备端算法名称和哨兵值。
3. 新会话或验证不匹配时，以 `0x0087` 按最多 `0x800` 字节逐块下发；每块都完成
   command OUT、payload OUT、completion IN。
4. 全部块完成后等待 100 ms，再用 `0x0008` 复验。
5. 无论复用还是重新下载，都必须用 `0x008A` 下发独立的 2048 字节器件参数。
6. 只有上述阶段全部完成才返回 `AlgorithmReady`。

准备完成后，`OperationSession` 可以串行执行：

- 查空：`0x0015 -> 0x0014* -> 0x0016`；
- 编程：`0x0019 -> (0x0098 + payload)* -> 0x001A`；
- 读取/校验：`0x001B -> 0x001D -> data* -> 0x001E`；
- 配置写入/读取：`0x00A3` 与 `0x0025`；
- 擦除：带原始路径选择值和明确模式的 `0x0013`；
- 事件流：`0x003A -> 0x85* -> 0x82`。

仍未关闭的边界包括：自动 profile 与官方软件的逐字节真机对照、真实端点描述符、状态/诊断
在不同固件上的兼容性、bootloader、OTP/保护位、脱机镜像和 ATE 电气规格。真实设备 API
因而仍标记为静态协议实验路径，不能视为生产验证完成。

## 5. 后续垂直切片

1. 在可牺牲样片上对比官方软件和 Rust 的无故障查空、读取与校验事务。
2. 固定 profile、时钟和工程数据，生成 `SPRJ` golden image 并逐字节对照。
3. 再验证擦除、编程和配置写入，任何未知执行状态都由人工恢复，不自动重放。
4. 在 Windows、Linux、macOS 上核对真实端点描述符和相同只读结果。
5. 补齐 `0x84` 通用诊断与 `0x85` 阶段值字典，验证 SP10/SP20 固件差异。
6. 脱机、固件升级、OTP/保护位和 ATE 最后实现，并要求独立恢复方案与审批。
