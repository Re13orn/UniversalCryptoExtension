# BC 签名打包与 SM2 密钥加载修复

旧扩展把 BC 1.70 类直接合并进 fat JAR 并移除签名，Oracle JDK 21 的 JCE 无法认证该 provider。影响受 javax.crypto 门控的 BC Cipher、Mac、SecretKeyFactory 服务，包括 AES、SM4、DESede、HMAC、PBKDF2；示例 06 的内置 HMAC 因此无法生成 X-Signature。SM2 密钥加载还调用了 BC 1.70 未注册的 SM2 KeyFactory 别名，是独立故障。

当前构建仍交付一个可直接加载的扩展 JAR。Maven 在 generate-resources 阶段完整复制原始签名 BC JAR 至 META-INF/lib/bcprov.jar，Shade 排除所有 BC 类；build.sh 对外层规范化，不解包或改变嵌入 JAR。BC 官方要求使用原始签名 provider JAR，见 [BC Java 文档](https://www.bouncycastle.org/documentation/documentation-java/)。

BouncyCastleSupport 将嵌入 JAR 复制到保留私有权限的临时文件，通过以 platform classloader 为父级的 URLClassLoader 加载，校验证书并实际调用 Mac 触发 JCE 认证。所有内置 Cipher、Mac、MessageDigest、Signature、KeyFactory 都接收同一个 Provider 对象；不向 Burp 全局 Security provider 列表注册 BC，也不复用其他扩展的 BC。扩展加载时检查 provider 并记录日志，卸载时关闭加载器及删除临时 JAR；临时目录不可写、资源缺失或签名被破坏时明确失败。脚本 Crypto helper 保持默认 JCE provider 路径。

SM2 公私钥加载改为 EC KeyFactory，密钥曲线为 sm2p256v1，公钥为 X.509 SPKI，私钥为 PKCS#8，均支持 PEM/Base64。现有 algorithm=sm2、rsaPublicKey/rsaPrivateKey 配置无需修改。测试生成密钥使用 EC generator + ECGenParameterSpec("sm2p256v1")。没有修改 BC 本身或添加 SM2 工厂别名。当前 Cipher("SM2") 默认为 raw C1C2C3；OpenSSL ASN.1 或 C1C3C2 密文需按真实协议转换。

## 构建和识别

```bash
./build.sh
# 或验证 Maven 原始交付路径：
mvn verify
```

加载 target/universal-crypto-extension-1.0.0.jar 即可，不需要另行安装 BC JAR。新包 Manifest 包含 Crypto-Provider-Layout: signed-bc-nested-v1，包内有 META-INF/lib/bcprov.jar 且外层无 org/bouncycastle/ 类，启动日志包含 Signed BC provider loaded。规则 schemaVersion/engineBuild 和扩展版本号保持兼容，单看版本号不能区分旧包。

## 验证结果

BC/SM2 修复阶段，本机 Oracle JDK 21.0.10：

- 274 项单元测试与 2 项独立 JVM 打包集成测试通过，零失败/错误/跳过。
- 仅用发布单 JAR 运行密码矩阵，BC 保留 2 张证书，18 项服务全部通过；最终 build.sh 规范化包再次通过相同矩阵。
- 独立 JVM 验证已有全局 BC provider 时仍使用自己的签名 BC，保持宿主注册列表不变；卸载临时文件删除通过。
- AES/DES/DESede 输出与 SunJCE 对照；SM4、SM3、BC PBKDF2 使用已知向量；内置 HMAC 与对应 Mac 输出核对。
- SM2 使用独立 OpenSSL 生成的密文/SPKI/PKCS#8 向量；验证私钥解密、公钥加密、JSON 字段保留、C3 篡改拒绝。
- 9 组规则在 source/packaged 模式各通过 19 个用例，包含示例 06 的精确签名头检查；原独立 agent 8 个 fixtures 在新包通过。
- provider 加载器验证并发复用、依赖缺失和签名内容篡改拒绝。

上述新 18 项矩阵覆盖正确的 EC SM2 路径，未将 BC 本身仍缺失的 SM2 工厂别名报告为新增支持；也不是对用户原先 18 项服务探测的逐项重放。

离线重放命令见 [Skill 验证记录](../skills/universal-crypto-rules/references/validation.md#9-bc-打包与-sm2-修复后验证2026-10-10)。旧包失败日志保留在独立的历史记录中。没有在真实 Burp 页签/网络流量上验证，也未运行 JDK 17/26。
