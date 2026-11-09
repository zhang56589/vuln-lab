package com.example.vulnlab;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.example.vulnlab.common.SessionKeys;

/**
 * 跨站请求伪造（CSRF）攻防对比测试
 * <p>
 * 防御组件：自研 {@link com.example.vulnlab.filter.CsrfTokenFilter}
 * <ul>
 *   <li>任何请求首次到达时，Session 中生成 UUID token，并在 Response 头 {@code X-CSRF-Token} 回显</li>
 *   <li>对 {@code /secure/csrf/**} 的 POST/PUT/DELETE 强制校验客户端回传的 token</li>
 *   <li>Token 不匹配 → 403 "CSRF token missing or mismatch"</li>
 * </ul>
 * 注意：漏洞版 vuln 测试和修复版 secure 测试使用不同账号，避免 vuln 改密码污染 secure 测试。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("CSRF 攻防对比测试")
class CsrfTest {

    @Autowired
    private MockMvc mockMvc;

    /** 漏洞版 vuln 测试用 user（userId=2, pwd=user123） */
    private MockHttpSession loginAsUser() {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(SessionKeys.CURRENT_USER_ID, 2L);
        session.setAttribute(SessionKeys.CURRENT_USERNAME, "user");
        return session;
    }

    /**
     * 修复版 secure 测试用 alice（userId=3, pwd=alice123），
     * 避免 vuln_changePwd_shouldSucceedWithoutToken 把 user 密码改掉后污染 secure 测试。
     */
    private MockHttpSession loginAsAlice() {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(SessionKeys.CURRENT_USER_ID, 3L);
        session.setAttribute(SessionKeys.CURRENT_USERNAME, "alice");
        return session;
    }

    private String fetchCsrfToken(MockHttpSession session) throws Exception {
        MvcResult result = mockMvc.perform(get("/auth/me").session(session))
                .andExpect(status().isOk())
                .andReturn();
        return result.getResponse().getHeader("X-CSRF-Token");
    }

    // ================== 漏洞版：无 token 校验 ==================

    @Test
    @DisplayName("【漏洞版】不带任何 CSRF Token → 改密码成功（漏洞可被跨站利用）")
    void vuln_changePwd_shouldSucceedWithoutToken() throws Exception {
        MockHttpSession session = loginAsUser();

        // POST /vuln/csrf/changePwd 只校验 oldPassword 对不对，不校验 CSRF token
        // → 这就是 CSRF 漏洞：攻击者在恶意网页上构造跨站 POST 就能改用户密码
        mockMvc.perform(post("/vuln/csrf/changePwd")
                        .session(session)
                        .param("oldPassword", "user123")
                        .param("newPassword", "newPwd123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0))
                .andExpect(jsonPath("$.msg").value(org.hamcrest.Matchers.containsString("vuln mode")));
    }

    // ================== 修复版：Filter 强制校验 ==================
    // 全部使用 alice 账号，确保密码未被 vuln 测试污染

    @Test
    @DisplayName("【修复版】不带 CSRF Token → 403（Filter 拦截）")
    void secure_changePwd_shouldFailWithoutToken() throws Exception {
        MockHttpSession session = loginAsAlice();

        // 不带 X-CSRF-Token 头也不带 csrfToken 参数 → Filter 直接 403
        mockMvc.perform(post("/secure/csrf/changePwd")
                        .session(session)
                        .param("oldPassword", "alice123")
                        .param("newPassword", "hacked"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(403))
                .andExpect(jsonPath("$.msg").value("CSRF token missing or mismatch"));
    }

    @Test
    @DisplayName("【修复版】带错误 Token → 403（Session 绑定值不匹配）")
    void secure_changePwd_shouldFailWithWrongToken() throws Exception {
        MockHttpSession session = loginAsAlice();
        fetchCsrfToken(session);   // 让 Filter 在 Session 里生成并绑定 token

        mockMvc.perform(post("/secure/csrf/changePwd")
                        .session(session)
                        .header("X-CSRF-Token", "hacked-fake-token-xxxx")
                        .param("oldPassword", "alice123")
                        .param("newPassword", "hacked"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(403))
                .andExpect(jsonPath("$.msg").value("CSRF token missing or mismatch"));
    }

    @Test
    @DisplayName("【修复版】带正确 Token → Filter 放行（业务层 oldPassword 对不对是另一回事）")
    void secure_changePwd_shouldPassFilterWithCorrectToken() throws Exception {
        MockHttpSession session = loginAsAlice();
        String realToken = fetchCsrfToken(session);

        org.junit.jupiter.api.Assertions.assertNotNull(realToken,
                "CsrfTokenFilter 应该在 Response 头回显 X-CSRF-Token");

        // 核心断言：带正确 token 时，请求**能到达 Controller**（不是 403 CSRF 拦截）
        // 业务层 oldPassword 校验通过与否是另一回事，不在 CSRF 防御范围内
        mockMvc.perform(post("/secure/csrf/changePwd")
                        .session(session)
                        .header("X-CSRF-Token", realToken)
                        .param("oldPassword", "alice123")
                        .param("newPassword", "securePwd123"))
                .andExpect(status().isOk())
                // Filter 校验不通过 → 403；所以通过 Filter 后一定不是 403
                .andExpect(jsonPath("$.code").value(org.hamcrest.Matchers.not(403)));
    }

    @Test
    @DisplayName("【修复版】Token 也支持 Form 表单参数 csrfToken 回传")
    void secure_changePwd_shouldAcceptFormParamToken() throws Exception {
        MockHttpSession session = loginAsAlice();
        String realToken = fetchCsrfToken(session);

        mockMvc.perform(post("/secure/csrf/changePwd")
                        .session(session)
                        .param("csrfToken", realToken)
                        .param("oldPassword", "alice123")
                        .param("newPassword", "formPwd123"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(org.hamcrest.Matchers.not(403)));
    }

    @Test
    @DisplayName("GET /secure/csrf/** 是安全方法 → 不应触发 CSRF 校验")
    void secure_csrf_getRequest_shouldPass() throws Exception {
        MockHttpSession session = loginAsAlice();
        // GET 在 Filter 的 SAFE_METHODS 里 → 直接放行，不可能 403
        mockMvc.perform(get("/secure/csrf/changePwd").session(session))
                .andExpect(status().reason(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("Forbidden"))));
    }
}
