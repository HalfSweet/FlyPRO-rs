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
| `protocol` | 只编码已确认的 `0x0008/0x0087/0x008A` | `F-PROTO-001`～`018` |
| `transport` | 用精确长度、Pipe、超时和取消表达分阶段传输 | `F-USB-010`～`019` |
| `session` | 验证复用、按需下载、复验、下发器件参数 | `F-ALG-021`～`026` |
| `usb` | 跨平台只读设备发现、描述符导出和 Pipe 集合核对 | `F-USB-001`～`019`、`Q-USB-001` |
| CLI | 资产诊断、目录查询、确认帧预览和 USB 描述符诊断 | `T-ALG-*`、`T-DEV-*`、`T-PROTO-*` |

## 2. Workspace 边界

```text
flypro-cli
    └── flypro-core
            ├── assets
            │   └── embedded_algorithms
            ├── protocol
            ├── session
            ├── transport
            └── usb
```

`flypro-core` 是唯一允许表达设备协议和资产格式的 crate。CLI 只调用领域 API，不得拼接
端点号或裸命令块。设备发现通过 `nusb` 使用 Windows WinUSB、macOS IOKit 和 Linux usbfs；
平台句柄不会进入公共领域模型。当前只读描述符路径不会 claim 接口或提交端点传输，真实传输
将在真机证据闭环后接入 core trait。

首轮只使用两个 workspace 成员，避免在证据尚少时把每个概念拆成大量稳定性不足的 crate。
当 USB 传输后端、生产审计或多机调度形成独立发布边界后，再按依赖方向拆分，而不是预先拆包。

## 3. 类型化数据流

```text
原始发布资产
  -> 严格导入器
  -> Algorithm / DeviceCatalog / DeviceParameterImage
  -> AlgorithmSession
  -> 已确认的 ProtocolFrame
  -> Transport trait
  -> 平台原生 USB 后端（发现已实现，传输后续接入）
```

几个重要约束：

- `.alg` 的 `0x4000` 字节负载始终是不透明字节，不在主机端解释或改写。
- `SP20.dev` 未命名字段以原始 144 字节记录保留。
- `0x008A` 的 2048 字节参数是独立强类型对象，不能由 `.alg` 负载或 DEV 记录补零得到。
- 每条事务显式声明 command OUT、payload OUT、response IN 或 completion IN 阶段。
- `0x82` 状态位语义尚未知；会话执行必须由经过真机证据验证的状态策略判定，库不提供猜测默认值。

## 4. 操作状态机

已确认的算法准备流程为：

1. 加载并严格校验算法文件。
2. 若当前主机会话标记 ready，使用 `0x0008` 验证设备端算法名称和哨兵值。
3. 新会话或验证不匹配时，以 `0x0087` 按最多 `0x800` 字节逐块下发；每块都完成
   command OUT、payload OUT、completion IN。
4. 全部块完成后等待 100 ms，再用 `0x0008` 复验。
5. 无论复用还是重新下载，都必须用 `0x008A` 下发独立的 2048 字节器件参数。
6. 只有上述阶段全部完成才返回 `AlgorithmReady`。

流程在这里结束。业务操作命令、器件参数构造器、`0x82/0x84/0x85` 状态含义、USB 描述符、
bootloader、脱机镜像和 ATE 电气规格仍分别被 `Q-PROTO-*`、`Q-USB-*`、`Q-FW-*`、
`Q-OFF-*`、`Q-ATE-*` 阻塞。

## 5. 后续垂直切片

1. 完成算法、DEV、CFG 离线导入和基线全量测试。
2. 完成三条已确认命令的编解码与纯内存会话测试。
3. 在三平台实现只读发现和描述符导出，并以 Windows 官方软件作为协议取证基线。
4. 用 USBPcap 单变量抓包关闭设备身份、读 ID 和只读数据路径的未知项。
5. 只有在命令、字段、状态和错误都闭环后，才逐项开放查空、擦除、编程和校验。
6. 脱机、固件升级和 ATE 最后实现，并要求独立恢复方案与审批。
