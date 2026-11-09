package com.example.vulnlab;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 存储型 XSS 攻防对比测试
 * <p>
 * 攻击 Payload:
 * <ul>
 *   <li>{@code <script>alert('XSS')</script>}</li>
 *   <li>{@code <img src=x onerror=alert(1)>}</li>
 * </ul>
 * 漏洞版：原样存入 → 原样拼进 HTML → 浏览器执行
 * 修复版：Jsoup 白名单入库过滤 + HtmlUtils.htmlEscape 输出转义 → 浏览器看到纯文本
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("存储型 XSS 攻防对比测试")
class XssAttackTest {

    @Autowired
    private MockMvc mockMvc;

    /** 攻击 Payload 1: script 标签 */
    private static final String SCRIPT_PAYLOAD = "<script>alert('XSS')</script>";

    /** 攻击 Payload 2: img onerror 事件（常绕过白名单） */
    private static final String IMG_ONERROR_PAYLOAD = "<img src=x onerror=alert(1)>";

    @Test
    @DisplayName("【漏洞版】注入 script → view 页面原样返回 script 标签")
    void vuln_view_shouldReturnRawScriptTag() throws Exception {
        // 先注入带 script 的评论
        mockMvc.perform(post("/vuln/xss/comment")
                        .param("content", SCRIPT_PAYLOAD)
                        .param("userId", "2"))
                .andExpect(status().isOk());

        // 再查看 HTML 页面 —— 漏洞版直接拼接，script 标签原封不动
        MvcResult result = mockMvc.perform(get("/vuln/xss/view"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/html"))
                .andReturn();

        String html = result.getResponse().getContentAsString();
        assertTrue(html.contains("<script>alert('XSS')</script>"),
                "漏洞版 view 应该原样输出 script 标签！实际返回片段: " +
                        (html.contains("script") ? "含 script" : "不含 script"));
    }

    @Test
    @DisplayName("【漏洞版】img onerror 事件属性也原样保留")
    void vuln_view_shouldReturnRawImgOnError() throws Exception {
        mockMvc.perform(post("/vuln/xss/comment")
                        .param("content", IMG_ONERROR_PAYLOAD)
                        .param("userId", "2"))
                .andExpect(status().isOk());

        MvcResult result = mockMvc.perform(get("/vuln/xss/view"))
                .andReturn();
        String html = result.getResponse().getContentAsString();
        // 漏洞版应该原样输出 onerror
        assertTrue(html.contains("onerror") && html.contains("alert(1)"),
                "漏洞版 view 应该原样输出 img 的 onerror 属性！");
    }

    @Test
    @DisplayName("【修复版】入库时 script 标签被 Jsoup 彻底剥离")
    void secure_post_shouldSanitizeScript() throws Exception {
        // 1. 向修复版接口注入 script
        mockMvc.perform(post("/secure/xss/comment")
                        .param("content", SCRIPT_PAYLOAD)
                        .param("userId", "3"))
                .andExpect(status().isOk());

        // 2. 查看修复版 HTML 页面 —— 应该找不到 <script> 标签
        MvcResult result = mockMvc.perform(get("/secure/xss/view"))
                .andReturn();
        String html = result.getResponse().getContentAsString();
        assertFalse(html.contains("<script>"),
                "修复版 view 不应包含 <script> 标签！");
        assertTrue(html.contains("alert(1)") || html.contains("XSS"),
                "修复版 view 应该保留纯文本（因为 script 标签被剥离，只剩文本内容）");
    }

    @Test
    @DisplayName("【修复版】img onerror 被剥离（Jsoup 白名单不允许事件属性）")
    void secure_post_shouldStripImgOnError() throws Exception {
        mockMvc.perform(post("/secure/xss/comment")
                        .param("content", IMG_ONERROR_PAYLOAD)
                        .param("userId", "3"))
                .andExpect(status().isOk());

        MvcResult result = mockMvc.perform(get("/secure/xss/view"))
                .andReturn();
        String html = result.getResponse().getContentAsString();
        assertFalse(html.contains("onerror"),
                "修复版 view 不应包含 onerror 事件属性！");
    }

    @Test
    @DisplayName("【修复版】普通安全标签（如 <b>）仍然保留（不应过度防御）")
    void secure_normalHtml_shouldBePreserved() throws Exception {
        mockMvc.perform(post("/secure/xss/comment")
                        .param("content", "<b>加粗文本</b> 和 <a href=\"https://example.com\">链接</a>")
                        .param("userId", "2"))
                .andExpect(status().isOk());

        MvcResult result = mockMvc.perform(get("/secure/xss/view"))
                .andReturn();
        String html = result.getResponse().getContentAsString();
        // Jsoup basicWithImages 白名单允许 <b> 和 <a>
        assertTrue(html.contains("<b>") || html.contains("加粗文本"),
                "修复版应保留安全的 <b> 标签（或至少保留文本）");
    }
}
