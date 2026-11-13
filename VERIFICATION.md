# 功能验证与验收

验证应记录实际结果，本文不是“已经在 Burp 加载成功”的证明。当前隐藏交互修复见 [UI 保存与交互记录](docs/UI隐藏交互缺陷与优化_2026-10-14.md)；场景/预设修复见 [更新记录](docs/场景向导与预设库更新_2026-10-14.md)；UI 修复见 [UI 检查记录](docs/UI检查与优化_2026-10-14.md)；处理链统一修复记录见 [历史遗漏与统一优化](docs/历史遗漏与统一优化_2026-10-13.md)；实时流量修复记录见 [实时流量修复说明](docs/实时流量展示修复_2026-10-13.md)，整体维护记录见 [整体检查记录](docs/整体检查与优化_2026-10-13.md)；历史实验见 [规则验证记录](skills/universal-crypto-rules/references/validation.md)。

## 离线验证

1. `./build.sh`：单元测试、独立 JVM 打包测试、最终 JAR 的 18 项密码服务检查。
2. `make verify`：重新校验实际 JAR 及嵌套 BC 完整性，失败必须非零退出。
3. `python3 scripts/sync_skill.py --check --install`：核对维护中的源码快照、Schema、链接、文档/安装镜像和 ZIP。
4. 用 Skill 的 check_rule.py 验证固定样例，分别选择 source/packaged；独立 JAR 可用 `--jar`。

预置规则默认禁用。导入规则也默认禁用，核对匹配范围、协议参数和执行阶段后再启用；不要以规则/处理器数量、一次启动日志或固定耗时作为成功标准。步骤预览使用真实内置/脚本处理器；外部服务及密钥查询明确未验证，不模拟加密成功。

## Burp 实机验收

使用本地测试服务或已授权目标，保留原始与实际发送报文字节。

| 场景 | 验收结果 |
|---|---|
| 请求只展示 | display 解密成功，未编辑时原密文保持不变 |
| Repeater 编辑请求 | 显式 encrypt/body-or-field/editor-send 动作匹配后开放编辑；修改明文后 editor-send 重加密，服务端解密得到修改值；重复取值不重复加密 |
| 规则更新 | 有用户编辑时使旧准备密文失效，按新规则重加密；禁用/移除加密动作后保留原密文 |
| 不执行加密 | 无动作、noChange、未改变正文时保留原密文，不把明文写回 |
| 外部服务不可用 | 明确失败，不退回模拟加密；内置 AES/HMAC 等继续独立运行 |
| 取消编辑 | 撤销回基线后发送原请求，不因 Pretty 格式化改变签名原文 |
| 响应只展示 | response-display 显示明文，客户端收到原密文及原头 |
| Intercept 编辑响应 | 明确配置 encrypt/body-or-field/response-editor-send；Forward 后客户端收到可解密的新密文 |
| 只读 / 缺加密规则 | 不允许编辑响应，未编辑时返回原对象 |
| 原请求 AAD | 响应 getOriginalHeader 取关联请求头，getHeader 和 headers 条件仍只针对响应头 |
| 失败 | 格式错误、加密失败、缺规则时保留原密文并显示错误；不是自动阻止 Forward |
| 重载与展示 | 键入、删除、撤销、切换头部和 Pretty/Raw 正常；字体跟随 Burp 编辑器设置 |
| 实时流量 | 仅展示解密时转发快照保持密文；明文预览显示解密正文且不改客户端数据；无展示动作/错误 AAD/外部服务明确失败或未验证 |
| 实时流量布局 | 首次进入详情占约一半；可拖动分隔；排序/新记录/切换语言保留当前选择 |
| 非目标流量 | 不命中且字节不变 |

响应自动线上修改另用 response-send；不要为了只看明文而选择该阶段。二进制流量优先验证真实 HTTP 链的 bodyBytes，不把文本编辑器往返视为二进制正确性证明。

本次未操作运行中的 Burp、未发送实际网络请求。真实客户端、HTTP/2 元数据及各平台加载效果要在对应环境单独记录。

UI 验收另需验证：语言切换保留当前页签与未保存的测试输入；排序后批量操作对应所选规则；设置导入后取消可恢复；慢任务运行时界面仍响应；取消流量选择清空详情；步骤中间快照不重复运行整个解密链。

本轮表单与筛选验收：已有高级配置自动展开；折叠后保存值不变；URL 特殊字符按字面搜索；失败不计为未修改；筛选和重置保留数据；隐藏/淘汰选择清空详情；语言刷新保留筛选和排序；表单在 480/840 像素宽容器内不强制横向滚动。规则编辑器与测试台的脚本帮助应一致，英文说明不混入中文说明段落。

整体复核新增验收：未修改的重复头不得重写；脚本数组密文 `[0,128,255,65]` 以原字节提交，非 UTF-8 输出不经字符串往返；保存失败不发布候选或改变 revision；含逗号的已有路径在无操作保存后仍保持原匹配。当前配置测试应保留父编辑窗口和完整参数，并正确使用输入源、方向和阶段。测试不应依赖用户 用户目录 文件或因缺私有规则而跳过。

## 发布版本的离线验证

构建后，可用发布 JAR 验证示例规则，无需启动 Burp 或访问目标服务。

```bash
python3 skills/universal-crypto-rules/scripts/check_rule.py \
  --jar target/universal-crypto-extension-1.0.0.jar \
  --rules skills/universal-crypto-rules/assets/examples/01-text-base64.rules.json \
  --fixtures skills/universal-crypto-rules/assets/examples/01-text-base64.fixtures.json
```

预设库的标准规则和对应 fixtures 位于 `skills/universal-crypto-rules/assets/examples/`。测试向量使用公开演示数据。SM2 的独立固定向量位于 `src/test/resources/crypto/`，可通过 `scripts/generate-sm2-vector.py` 重新生成。
