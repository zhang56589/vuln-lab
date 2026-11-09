# vuln-lab 项目规则

> 用于指导 Trae 生成/修改代码时遵循统一规范。

## 1. 项目定位

覆盖 5 类常见 Web 漏洞（SQLi / XSS / IDOR / SSRF / CSRF）的攻防演示靶场。
每个漏洞场景同时提供两套实现：

- **Vulnerable**（漏洞版）：直接暴露安全弱点，用于攻击演示。
- **Secure**（修复版）：使用预编译、白名单过滤、权限校验等手段修复。

技术栈：**Java 17 + Spring Boot 3.2.x + MyBatis-Plus + H2 + Jsoup**。

---

## 2. URL 前缀约束（强制）

| 版本 | URL 前缀 | 说明 |
|------|---------|------|
| 漏洞版 | `/vuln/` | 必须以此前缀开头 |
| 修复版 | `/secure/` | 必须以此前缀开头 |

控制器包路径对应：
- 漏洞版：`com.example.vulnlab.controller.vuln`
- 修复版：`com.example.vulnlab.controller.secure`

---

## 3. 代码注释规范（强制）

### 3.1 漏洞版
漏洞版代码必须在漏洞点旁加注释：

```java
// [漏洞点] 此处直接拼接 SQL，存在 SQL 注入风险
// [漏洞点] 此处将用户输入原样写入 HTML，存在 XSS 风险
// [漏洞点] 此处未校验订单归属，存在水平越权风险
// [漏洞点] 此处直接请求用户传入的 URL，存在 SSRF 风险
// [漏洞点] 此处未校验 CSRF Token，存在跨站请求伪造风险
```

### 3.2 修复版
修复版代码必须在防御点旁加注释：

```java
// 防御点：使用 MyBatis-Plus QueryWrapper + 预编译 #{} 防止 SQL 注入
// 防御点：使用 Jsoup HtmlSanitizer 白名单过滤用户输入，防止 XSS
// 防御点：从 Session 取出当前用户，强制校验订单归属，防止水平越权
// 防御点：解析 IP 并拦截内网网段 + 限制协议，防止 SSRF
// 防御点：CSRFTokenFilter 强制校验 Session Token，防止 CSRF
```

---

## 4. Secure 版编码规范

修复版代码必须符合以下现代企业级规范：

1. **严禁**出现明显安全漏洞（不得回退到 Vulnerable 实现）。
2. **输入校验**：对所有外部入参使用 `@Valid` / 手动校验非空、长度、类型。
3. **权限校验**：涉及用户数据的接口必须校验当前登录用户身份。
4. **异常处理**：使用统一异常处理器，禁止向客户端暴露堆栈信息。
5. **响应格式**：统一使用 `com.example.vulnlab.common.R<T>` 包装返回。

---

## 5. 单元测试规范

- 测试类继承 `@SpringBootTest` + `@AutoConfigureMockMvc`。
- 每个测试方法必须在注释中写明 **攻击 Payload**。
- 同一测试类中同时验证：
  - 漏洞接口被成功攻击（HTTP 200 + 返回被篡改的数据/脚本）。
  - 修复接口成功防御（HTTP 400/403 + 错误提示）。

测试类命名约定：`<漏洞类型>Test.java`，如 `SqlInjectionTest.java`、`XssAttackTest.java`。

---

## 6. 禁止事项

1. **禁止**引入 Spring Security 全家桶（过滤器、拦截器均自研）。
2. **禁止**引入 MySQL / PostgreSQL 等外部数据库（仅允许 H2）。
3. **禁止**在 Secure 版中出现硬编码密码。
4. **禁止**在日志中打印敏感信息（密码、Token、完整 SQL）。
5. **禁止**修改 Vulnerable 版的 URL 或行为（保持漏洞可复现）。

---

## 7. 包结构速查

```
com.example.vulnlab
├── VulnLabApplication   // 启动类
├── common                // R<T> 统一响应
├── controller
│   ├── vuln              // 漏洞版 5 个 Controller
│   └── secure            // 修复版 5 个 Controller
├── service               // 业务逻辑
├── mapper                // MyBatis-Plus Mapper
├── entity                // User / Orders / Comment / Account
└── filter                // CSRFTokenFilter / SSRFGuard 等
```
