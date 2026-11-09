package com.example.vulnlab;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 服务端请求伪造（SSRF）攻防对比测试
 * <p>
 * 攻击 Payload:
 * <ul>
 *   <li>{@code http://127.0.0.1:8080/h2-console} — 探测内网本机服务</li>
 *   <li>{@code http://169.254.169.254/latest/meta-data/} — 云元数据泄露</li>
 *   <li>{@code file:///etc/passwd} — 非法协议白名单拦截</li>
 *   <li>{@code http://evil.com} (解析到 10.x) — DNS 重绑定防御</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("SSRF 攻防对比测试")
class SsrfTest {

    @Autowired
    private MockMvc mockMvc;

    // ================== 漏洞版：直接发起请求 ==================

    @Test
    @DisplayName("【漏洞版】请求 127.0.0.1 不会被 SSRF Guard 主动拦截（会尝试直接发请求）")
    void vuln_fetch_shouldAttemptDirectRequest() throws Exception {
        // MockMvc 测试时真实 Tomcat 还没在 8080 启动，所以漏洞版的 HttpURLConnection 会 Connection refused
        // 但关键是：漏洞版不会像 Secure 版那样先做 SsrfGuard.validate() 主动拒绝！
        // 这里的核心断言是 —— 漏洞版返回体里**绝不含 "SSRF blocked"**（这是 Secure 版才会返回的）
        MvcResult result = mockMvc.perform(get("/vuln/ssrf/fetch")
                        .param("url", "http://127.0.0.1:80/h2-console"))
                .andExpect(status().isOk())
                .andReturn();
        String body = result.getResponse().getContentAsString();
        // 漏洞版应直接尝试发起 HTTP 请求（可能 Connection refused，但不是 SsrfGuard 主动拦截）
        assertFalse(body.contains("SSRF blocked"),
                "漏洞版不会主动拦截 SSRF 请求！实际返回: " + body);
        // 进一步证明：漏洞版的错误是网络层面的（Connection refused），不是安全层面的拦截
        assertTrue(body.contains("Connection refused") || body.contains("fetch error")
                        || body.contains("remote http") || body.contains("ok"),
                "漏洞版返回的是网络错误或真实响应，而不是 SSRF 安全拦截。实际: " + body);
    }

    @Test
    @DisplayName("【漏洞版】file:// 协议直接被当作 URL 解析（无协议白名单）")
    void vuln_fetch_fileProtocol_noBlocking() throws Exception {
        // 漏洞版无协议白名单 —— file:// 会被 URI.create() 接受
        // 但 openConnection(file:...) 在某些 JDK 下有权限限制，所以这里只验证"没有被我们主动拒绝"
        MvcResult result = mockMvc.perform(get("/vuln/ssrf/fetch")
                        .param("url", "file:///etc/passwd"))
                .andExpect(status().isOk())
                .andReturn();
        String body = result.getResponse().getContentAsString();
        // 漏洞版错误信息可能是 "fetch error: ..." 但不是 "SSRF blocked"
        assertFalse(body.contains("SSRF blocked"),
                "漏洞版不应主动返回 SSRF blocked！实际返回: " + body);
    }

    // ================== 修复版：SSRF Guard 校验 ==================

    @Test
    @DisplayName("【修复版】127.0.0.1 内网 IP → 400 直接拦截")
    void secure_fetch_localhost_shouldBeBlocked() throws Exception {
        MvcResult result = mockMvc.perform(get("/secure/ssrf/fetch")
                        .param("url", "http://127.0.0.1:8080/h2-console"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(400))
                .andExpect(jsonPath("$.msg").value(org.hamcrest.Matchers.containsString("SSRF blocked")))
                .andExpect(jsonPath("$.msg").value(org.hamcrest.Matchers.containsString("internal IP")))
                .andReturn();
    }

    @Test
    @DisplayName("【修复版】169.254.169.254 云元数据 → 400 拦截")
    void secure_fetch_cloudMetadata_shouldBeBlocked() throws Exception {
        mockMvc.perform(get("/secure/ssrf/fetch")
                        .param("url", "http://169.254.169.254/latest/meta-data/"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(400))
                .andExpect(jsonPath("$.msg").value(org.hamcrest.Matchers.containsString("SSRF blocked")));
    }

    @Test
    @DisplayName("【修复版】192.168.1.1 内网 → 400 拦截")
    void secure_fetch_192_168_shouldBeBlocked() throws Exception {
        mockMvc.perform(get("/secure/ssrf/fetch")
                        .param("url", "http://192.168.1.1/admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(400))
                .andExpect(jsonPath("$.msg").value(org.hamcrest.Matchers.containsString("SSRF blocked")));
    }

    @Test
    @DisplayName("【修复版】file:// 非法协议 → 400 白名单拒绝")
    void secure_fetch_fileProtocol_shouldBeBlocked() throws Exception {
        mockMvc.perform(get("/secure/ssrf/fetch")
                        .param("url", "file:///etc/passwd"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(400))
                .andExpect(jsonPath("$.msg").value(org.hamcrest.Matchers.containsString("only http")));
    }

    @Test
    @DisplayName("【修复版】gopher:// 非法协议 → 400 白名单拒绝")
    void secure_fetch_gopherProtocol_shouldBeBlocked() throws Exception {
        mockMvc.perform(get("/secure/ssrf/fetch")
                        .param("url", "gopher://127.0.0.1:6379/_PING"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(400));
    }

    @Test
    @DisplayName("【修复版】空 URL → 400 参数校验")
    void secure_fetch_emptyUrl_shouldBeRejected() throws Exception {
        mockMvc.perform(get("/secure/ssrf/fetch")
                        .param("url", ""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(400));
    }
}
