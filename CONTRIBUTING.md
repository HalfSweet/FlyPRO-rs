# 贡献规范

感谢参与 FlyPRO-rs。提交代码或文档前，请先确认变更没有混淆产品名称：SP10/SP20 是硕飞
烧录器系列，FlyPro 是配套上位机软件名称。

## 开发环境

项目要求 Rust 1.85 或更高版本。推荐通过 rustup 安装工具链，并添加格式化和 Clippy 组件：

```bash
rustup component add rustfmt clippy
cargo build --workspace
```

## 开发原则

- `flypro-core` 负责资产、协议、参数、会话和 USB 传输，不能依赖 CLI；
- `flypro-cli` 负责输入、输出和风险确认，不直接构造裸协议帧；
- 已确认的兼容性行为应包含测试，并在适用时引用事实 ID；
- 未知字段保留原始字节，不使用推测性的名字或有损转换；
- 破坏性命令在超时、取消或状态未知后不得自动重试；
- 优先修改现有边界，避免为尚未验证的能力提前创建抽象。

架构和协议背景分别见 [架构设计](docs/architecture.md)与 [实现细节](docs/implementation.md)。

## 代码风格

- 使用 `cargo fmt` 的默认格式；
- 遵循 workspace 中启用的 Rust 和 Clippy lint；
- 公共 API 应提供说明用途、约束或风险的 rustdoc；
- 错误信息应包含可操作的上下文，但不得把未知状态描述为已确认事实；
- 测试名称应表达场景和期望结果，协议字节优先使用可审查的 golden fixture。

## 提交前检查

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

若修改真实设备路径，还应检查对应 CLI 帮助，并说明是否完成 SP10/SP20 实机验证。没有硬件
验证时，必须保留实验性和静态协议风险提示。

## 提交与合并请求

- 使用 [Conventional Commits](https://www.conventionalcommits.org/)；
- 一个提交只包含一个可独立解释和验证的修改；
- 合并请求应说明动机、行为变化、验证命令和剩余风险；
- 涉及 USB 或写操作时，附上设备型号、固件、目标芯片和是否为可牺牲样片；
- 不要提交芯片备份、序列号、抓包中的敏感标识或来源不明的二进制资产。

## 许可证

提交贡献即表示你有权提供该贡献，并同意其按照本项目的
[Apache License 2.0](LICENSE) 授权。
