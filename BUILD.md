# 构建与发布

源码构建需要 JDK 17+ 和 Maven 3.9。额外验证及发布打包使用 Python 3.8+。首次构建会从 Maven Central 获取依赖。

## Windows、Linux 和 macOS

在项目根目录运行：

```text
mvn clean verify
```

构建和集成测试使用同一个 Maven 产物。Maven 将原始签名 BC JAR 嵌入 `META-INF/lib/bcprov.jar`，并过滤外层模块描述符和旧签名元数据。依赖的许可证与声明收录在 JAR 的 `META-INF/uce-third-party/`。

额外校验最终 JAR 的结构、依赖和密码服务：

```text
python scripts/verify_distribution.py --crypto-classpath target/test-classes
```

Linux 和 macOS 可以用 `python3`，也可以直接运行 `./build.sh` 或 `make build` 执行构建及额外校验。Windows 可使用 PowerShell 或命令提示符运行以上 Maven 和 Python 命令。

仓库的 [跨平台工作流](.github/workflows/build.yml) 在 Windows、Linux 和 macOS 上以 Java 17、21 运行构建、密码检查及独立 JAR 规则重放。Burp 界面和编辑器还需在实际 Burp 中验收。

## 产物与版本核对

加载 `target/universal-crypto-extension-1.0.0.jar`。插件兼容版本仍为 1.0.0；精确构建通过 Manifest 的 UCE-Revision、Response-Editor-Phase、Crypto-Provider-Layout 和 JAR SHA-256 识别。启动输出会显示 revision，避免仅凭相同文件名判断已更新。

```bash
make verify
./status.sh
```

`make verify` 校验 SPI、必需类、嵌套 BC 原始 SHA-256、能力标记及最终 JAR 的密码服务；任何失败均返回非零退出码。status 仅检查本地产物，不能证明 Burp 已加载它，也不会切换 SPI 到已经移除的精简扩展。

## 文档与 Skill 同步

修改源码或 Skill 后运行：

```bash
python3 scripts/sync_skill.py
python3 scripts/sync_skill.py --check
```

同步源码快照、仓库中的文档镜像和 ZIP。`--install` 额外同步本机 ~/.codex Skill，未指定时不修改安装目录。发布前可运行 Skill 自身的规则验证器；示例、执行阶段和源代码必须对应同一构建。

## 发布与安装

```bash
make release
```

发布包包含经过验证的 JAR、Skill 和维护文档，位于 target。仅验证规则时可使用发布 JAR，无需工程源码或 Maven：

```bash
python3 skills/universal-crypto-rules/scripts/check_rule.py --jar /path/to/plugin.jar --rules rules.json --fixtures fixtures.json
```

在 Burp 的 Extensions → Installed → Add 中选择 Java 和 JAR 路径。`make install` 只显示经过校验的加载路径，复制到猜测的目录并不会注册 Burp 扩展。

常用开发命令：`make test`、`make compile`、`make clean`、`make deps`。最终交付请使用经过 build.sh 或 verify_distribution 校验的产物，不把“编译成功”视为密码服务或 Burp 实机验证通过。

`make verify`、`status.sh`、最终构建和发布打包同时核对工程的 uce.revision，拒绝具有旧 revision 的 JAR；不能仅因为旧包仍带能力标记就把它当作本轮构建。

预设库规则与 fixtures 位于 src/main/resources/com/universal/crypto/presets，与 Skill 的 assets/examples 保持逐字节一致。编辑样例后同步这些资源；sync_skill --check 会拒绝模板漂移，发布 JAR 会携带规则和离线 fixtures。

单元测试将 Java 用户目录、APPDATA 和 XDG_CONFIG_HOME 指向 target/test-home 下的隔离位置。合成响应链规则随 src/test/resources/protocol 提供。发布校验要求全部 20 个预设/fixtures 资源存在，并在工程内比较 JAR 与源资源内容。
