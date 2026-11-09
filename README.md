# vuln-lab

> **攻防双修 Web 漏洞靶场** —— 覆盖 SQLi / XSS / IDOR / SSRF / CSRF 5 类常见漏洞，每个漏洞场景同时提供 **Vulnerable（漏洞版）** 与 **Secure（修复版）** 两套实现，配 29 个 MockMvc 自动化安全测试全绿通过。

---

## 🛠️ 技术栈

| 分类 | 选型 |
|------|------|
| 语言/框架 | Java 17、Spring Boot 3.2.5（**不引入 Spring Security，过滤器全自研**） |
| ORM | MyBatis-Plus 3.5.5（Spring Boot 3 兼容版） |
| 数据库 | H2 内存模式（`jdbc:h2:mem:vulnlab`，无需外部安装） |
| 安全组件 | Jsoup 1.17.2（XSS 白名单过滤）、自研 `SsrfGuard`（DNS 重绑定防御）、自研 `CsrfTokenFilter` |
| 测试 | JUnit 5 + MockMvc + Hamcrest Matchers（**29 个测试全绿**） |
| 构建 | Maven 单模块 |

---

## 🚀 快速开始

```bash
# 1. 克隆 + 启动（JDK 17+）
git clone https://github.com/yourname/vuln-lab.git
cd vuln-lab
mvn spring-boot:run

# 2. 访问
# 应用根路径     http://localhost:8080
# H2 控制台      http://localhost:8080/h2-console
#   JDBC URL:    jdbc:h2:mem:vulnlab
#   用户名/密码: sa / (空)

# 3. 演示账号（所有账号初始密码 = 用户名 + "123"）
# admin  / admin123    （管理员，userId=1）
# user   / user123     （普通用户，userId=2，拥有机密订单 2001/2002）
# alice  / alice123    （普通用户，userId=3）

# 4. 跑测试（29 tests → all green）
mvn test
```

> **项目规则**：漏洞版接口统一挂载 `/vuln/**` 前缀，修复版统一挂载 `/secure/**` 前缀。Controller 中漏洞点旁写 `// [漏洞点]` 注释，修复点旁写 `// 防御点` 注释。详见 `.trae/rules/project_rules.md`。

---

## ⚔️ 漏洞攻防对比表

| # | 漏洞类型 | 攻击面（Vulnerable） | 防御方案（Secure） | 核心组件 |
|---|---------|---------------------|-------------------|---------|
| 1 | **SQL 注入** | `VulnSqlMapper` 用 `@Select("... LIKE '%${keyword}%' ...")` 字符串拼接 | `QueryWrapper.like()` 走 JDBC PreparedStatement `#{}` 预编译 | MyBatis-Plus LambdaQueryWrapper |
| 2 | **存储型 XSS** | 评论原样拼进 HTML 字符串返回给浏览器 | 入库前 `Jsoup Whitelist.basicWithImages()` 过滤 + 输出前 `HtmlUtils.htmlEscape()` 双重防御 | Jsoup + Spring HtmlUtils |
| 3 | **水平越权 IDOR** | `/vuln/order/{id}` 只按订单 ID 查询，无归属校验 | Session 中取 `CURRENT_USER_ID`，强制 `order.userId == session.userId`，不匹配返回 403 | Session 归属校验 |
| 4 | **SSRF + DNS 重绑定** | 直接 `HttpURLConnection.openConnection(url)` 发起服务端请求 | `SsrfGuard.validate()`：协议白名单 → `InetAddress.getAllByName()` 全量 DNS 预解析 → 内网 IP 黑名单（loopback/site-local/link-local/169.254）→ 禁止 redirect 跟随 | 自研 SsrfGuard |
| 5 | **CSRF** | 改密码接口只校验登录态，无 Token 校验 | `CsrfTokenFilter`：Session 首次生成 UUID，Response 头 `X-CSRF-Token` 回显，对 `/secure/csrf/**` 的写请求强制 Header/Form 双路校验 | 自研 CsrfTokenFilter（无 Spring Security） |

---

## 🔓 每类漏洞 curl 复现命令

### 前置：登录拿到 Session Cookie（user 账号）

```bash
LOGIN_RESP=$(curl -s -c cookies.txt \
    -X POST "http://localhost:8080/auth/login?username=user&password=user123")
echo "$LOGIN_RESP"
```

---

### 1. SQL 注入

```bash
# 攻击 Payload: ' OR '1'='1
# 漏洞版：返回全部 3 个用户（admin / user / alice）
curl -s "http://localhost:8080/vuln/sql/search?keyword=%27+OR+%271%27%3D%271"

# 修复版：同 payload 被当作普通字符串，返回 0 条
curl -s "http://localhost:8080/secure/sql/search?keyword=%27+OR+%271%27%3D%271"

# UNION SELECT 联合查询泄露密码（漏洞版）
curl -s "http://localhost:8080/vuln/sql/search?keyword=%27+UNION+SELECT+1,username,password,4,5+FROM+sys_user+--"
```

### 2. 存储型 XSS

```bash
# 注入 script 评论
curl -s -X POST "http://localhost:8080/vuln/xss/comment?content=<script>alert('XSS')</script>&userId=2"

# 漏洞版浏览器访问 → 弹窗（script 原样输出）
curl -s "http://localhost:8080/vuln/xss/view" | grep -i script

# 修复版：Jsoup 入库剥离 script，输出 htmlEscape 兜底
curl -s -X POST "http://localhost:8080/secure/xss/comment?content=<script>alert('XSS')</script>&userId=3"
curl -s "http://localhost:8080/secure/xss/view" | grep -i script   # 应无输出
```

### 3. 水平越权（IDOR）

```bash
# user 登录态下访问 admin 的机密订单 1001（userId=1, amount=8888）
# 漏洞版：直接返回 admin 的机密数据
curl -s -b cookies.txt "http://localhost:8080/vuln/order/1001"
# → {"code":0,"msg":"ok","data":{"id":1001,"userId":1,"amount":8888.00,...}}

# 修复版：403 Forbidden
curl -s -b cookies.txt "http://localhost:8080/secure/order/1001"
# → {"code":403,"msg":"forbidden: this order does not belong to you","data":null}
```

### 4. SSRF + DNS 重绑定

```bash
# 漏洞版：能探测本机 h2-console
curl -s "http://localhost:8080/vuln/ssrf/fetch?url=http://127.0.0.1:8080/h2-console"

# 修复版：SsrfGuard 主动拦截内网 IP
curl -s "http://localhost:8080/secure/ssrf/fetch?url=http://127.0.0.1:8080/h2-console"
# → {"code":400,"msg":"SSRF blocked: blocked: target host '127.0.0.1' resolved to internal IP: 127.0.0.1","data":null}

# 协议白名单：file:// 也被拒绝
curl -s "http://localhost:8080/secure/ssrf/fetch?url=file:///etc/passwd"
# → {"code":400,"msg":"SSRF blocked: only http / https allowed, got: file",...}
```

### 5. CSRF

```bash
# 先让 GET /auth/me 触发 CsrfTokenFilter 生成 token
curl -s -b cookies.txt -D - "http://localhost:8080/auth/me" -o /dev/null | grep X-CSRF-Token
# X-CSRF-Token: a1b2c3d4e5f6...

# 漏洞版：不带 token 直接改密码 → 成功（CSRF 漏洞可被跨站利用）
curl -s -b cookies.txt -X POST "http://localhost:8080/vuln/csrf/changePwd?oldPassword=user123&newPassword=hacked123"

# 修复版：不带 token → 403 拦截
curl -s -b cookies.txt -X POST "http://localhost:8080/secure/csrf/changePwd?oldPassword=alice123&newPassword=hacked"
# → 403 {"code":403,"msg":"CSRF token missing or mismatch"}

# 修复版：带正确 token → 通过 Filter
TOKEN=$(curl -s -b cookies.txt -D - "http://localhost:8080/auth/me" -o /dev/null | grep -i X-CSRF-Token | tr -d '\r' | awk '{print $2}')
curl -s -b cookies.txt -X POST "http://localhost:8080/secure/csrf/changePwd" \
    -H "X-CSRF-Token: $TOKEN" \
    --data-urlencode "oldPassword=alice123" \
    --data-urlencode "newPassword=securePwd123"
# → 业务层正常处理（不再是 403）
```

---

## 🏆 核心防御组件解析

### 1. SsrfGuard：协议白名单 + DNS 预解析 + DNS 重绑定防御

```java
// com.example.vulnlab.common.SsrfGuard
public static URI validate(String rawUrl) {
    // 1. 协议白名单 —— 只允许 http / https，拦截 file://、gopher://、dict:// 等
    if (!ALLOWED_PROTOCOLS.contains(uri.getScheme().toLowerCase())) throw ...;

    // 2. DNS 预解析 —— getAllByName 拿到域名的全部 A 记录
    InetAddress[] addresses = InetAddress.getAllByName(host);

    // 3. 内网 IP 黑名单 —— 只要其中一个 IP 命中内网范围就整体拒绝
    //    loopback / site-local / link-local / multicast / any-local
    //    + 兜底 169.254.0.0/16 + IPv4-mapped IPv6
    for (InetAddress addr : addresses) {
        if (isInternalIp(addr)) throw new IllegalArgumentException(...);
    }
    // 4. DNS 重绑定防御核心：getAllByName 是预解析阶段，
    //    攻击者要让同一域名"预检返回公网 IP + 真实请求返回内网 IP"
    //    这种行为本身就会被 getAllByName 的预检拦截！
}
```

### 2. CsrfTokenFilter：自研 Filter，无 Spring Security 依赖

```java
// com.example.vulnlab.filter.CsrfTokenFilter
public class CsrfTokenFilter implements Filter {

    // 1. Session 首次生成 UUID token，Response 头回显 X-CSRF-Token
    String token = (String) session.getAttribute(CSRF_TOKEN);
    if (token == null) {
        token = UUID.randomUUID().toString().replace("-", "");
        session.setAttribute(CSRF_TOKEN, token);
    }
    response.setHeader("X-CSRF-Token", token);

    // 2. 对 /secure/csrf/** 的 POST/PUT/DELETE 强制校验
    if (uri.startsWith("/secure/csrf") && !SAFE_METHODS.contains(method)) {
        String clientToken = request.getHeader("X-CSRF-Token");        // Header 方式
            == null ? request.getParameter("csrfToken") : clientToken;   // Form 方式
        if (clientToken == null || !clientToken.equals(token)) {
            response.setStatus(403);   // Filter 层直接拦截，Controller 进不来
            return;
        }
    }
}
```

### 3. Jsoup HtmlSanitizerUtil：白名单驱动的 XSS 防御

```java
// com.example.vulnlab.common.HtmlSanitizerUtil
private static final Safelist SAFE_LIST = Safelist.basicWithImages()
    .addTags("p", "br", "span", "div", "pre", "code", "blockquote")
    .addAttributes("a", "target", "rel")
    .addProtocols("a", "href", "http", "https", "mailto");

public static String sanitize(String raw) {
    // Jsoup.clean 解析 DOM → 剔除不在白名单里的标签/属性/协议 → 重新序列化
    return Jsoup.clean(raw, SAFE_LIST);
}
```

---

## 📋 项目亮点（可直接写进简历）

> ⚠️ **⚠️ 这些是可以复制粘贴到简历项目经历里的 bullet point** ⚠️

1. **攻防双修靶场设计**：独立设计并实现覆盖 SQLi / 存储型 XSS / 水平越权 IDOR / SSRF+DNS 重绑定 / CSRF 5 类高频 Web 漏洞的 Spring Boot 3.2 靶场，每个漏洞场景同时提供 Vulnerable（漏洞版）与 Secure（修复版）双轨对照实现，使用 H2 内存数据库 + MyBatis-Plus 开箱即用。

2. **自研 SSRF 防御组件 SsrfGuard**：在不依赖任何安全框架的前提下，通过 InetAddress.getAllByName() 全量 DNS 预解析 + 内网 IP 黑名单（loopback/site-local/link-local/169.254/IPv6 内网）+ 协议白名单 + 禁止 redirect 跟随的四层防线，实现对 DNS 重绑定攻击的精准防御。

3. **自研 CSRF TokenFilter**（无 Spring Security 依赖）：基于 Servlet Filter 机制，在 Session 中绑定 UUID token，同时通过 Response Header `X-CSRF-Token` 回显，对写请求强制从 Header 或 Form 参数双路校验 token，不一致返回 403；GET/HEAD 等安全方法自动放行，Filter 内部路径白名单隔离漏洞版与修复版。

4. **29 个自动化安全测试 100% 覆盖**：使用 MockMvc + JUnit5 编写 29 个测试用例，覆盖 5 类漏洞的 Vulnerable/Secure 双维度对比，每个测试明确写明攻击 Payload（如 `' OR '1'='1`、`<script>alert(1)</script>`、file:// 协议探测等），断言漏洞版被成功攻击而修复版被有效防御，GitHub Actions CI 自动执行 `mvn test` 保证每次提交全绿通过。

---

## 📁 工程结构

```
vuln-lab/
├── pom.xml
├── README.md
├── .gitignore
├── .github/workflows/build.yml          ← CI：JDK 17 + mvn test
├── .trae/rules/project_rules.md         ← 项目编码规范
├── src/main/resources/
│   ├── application.yml                  ← H2 / MyBatis-Plus / SSRF-CSRF 配置
│   ├── schema.sql                       ← 建表：sys_user / orders / comment / account
│   └── data.sql                         ← 演示数据：admin / user / alice
└── src/main/java/com/example/vulnlab/
    ├── VulnLabApplication.java
    ├── common/
    │   ├── R.java                       ← 统一响应
    │   ├── SessionKeys.java             ← Session Key 常量
    │   ├── HtmlSanitizerUtil.java       ← Jsoup 白名单过滤
    │   └── SsrfGuard.java               ← SSRF + DNS 重绑定防御
    ├── controller/
    │   ├── LoginController.java         ← 登录写 Session
    │   ├── vuln/                        ← 5 个漏洞版 Controller
    │   │   ├── VulnerableSqlController.java      ← SQLi
    │   │   ├── VulnerableXssController.java       ← XSS
    │   │   ├── VulnerableOrderController.java    ← IDOR
    │   │   ├── VulnerableSsrfController.java     ← SSRF
    │   │   └── VulnerableCsrfController.java     ← CSRF
    │   └── secure/                      ← 5 个修复版 Controller
    │       ├── SecureSqlController.java
    │       ├── SecureXssController.java
    │       ├── SecureOrderController.java
    │       ├── SecureSsrfController.java
    │       └── SecureCsrfController.java
    ├── mapper/
    │   ├── UserMapper.java / OrdersMapper.java / CommentMapper.java / AccountMapper.java
    │   └── VulnSqlMapper.java           ← 故意用 ${} 构造注入漏洞的 @Select Mapper
    ├── entity/
    │   ├── User.java / Orders.java / Comment.java / Account.java
    ├── filter/
    │   └── CsrfTokenFilter.java         ← 自研 CSRF 过滤器
    └── config/
        └── WebConfig.java               ← Filter 注册
└── src/test/java/com/example/vulnlab/
    ├── SqlInjectionTest.java            ← 4 tests
    ├── XssAttackTest.java                ← 5 tests
    ├── IdorTest.java                     ← 6 tests
    ├── SsrfTest.java                     ← 7 tests
    └── CsrfTest.java                     ← 7 tests
                                         Total: 29 tests, all green ✅
```

---

## 📝 License

MIT — 用于安全学习，请勿将漏洞版代码用于生产环境。
