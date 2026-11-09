package com.example.vulnlab.controller.secure;

import com.example.vulnlab.common.HtmlSanitizerUtil;
import com.example.vulnlab.entity.Comment;
import com.example.vulnlab.mapper.CommentMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import java.util.List;

/**
 * 存储型 XSS —— 修复版 Controller
 * <p>
 * 双重防御：
 * <ol>
 *   <li><b>入库前</b>：使用 {@link HtmlSanitizerUtil}（Jsoup 白名单）
 *       剥离危险标签与事件属性，只留安全标签。</li>
 *   <li><b>输出前</b>：使用 Spring 的 {@link HtmlUtils#htmlEscape(String)}
 *       做 HTML 实体转义，把 {@code < > & " '} 变成安全实体，
 *       即使白名单有遗漏也能兜底。</li>
 * </ol>
 *
 * <h3>攻击 Payload 会被怎样处理？</h3>
 * <pre>
 * 输入:  hello&lt;script&gt;alert('XSS!')&lt;/script&gt;world
 * ↓  入库 sanitize  ↓
 * 存储:  helloworld      (script 标签被整个剥离)
 * ↓  输出 htmlEscape ↓
 * 响应:  helloworld
 * 浏览器渲染: 纯文本，不会弹窗 ✅
 *
 * 如果攻击者用：&lt;img src=x onerror=alert(1)&gt;
 * ↓ sanitize 之后会去掉 onerror 属性
 * 存储:  &lt;img src="x"&gt;
 * </pre>
 */
@RestController
@RequestMapping("/secure/xss")
public class SecureXssController {

    @Autowired
    private CommentMapper commentMapper;

    /**
     * 发布评论 —— 修复版
     * <p>
     * 防御点：入库前先走 Jsoup 白名单过滤，危险标签/事件属性全部剥离。
     */
    @PostMapping("/comment")
    public String postComment(@RequestParam String content,
                              @RequestParam(defaultValue = "1") Long userId) {
        // 防御点 ①：Jsoup 白名单过滤，彻底剥离 <script> / onerror / javascript: 等危险内容
        String safeContent = HtmlSanitizerUtil.sanitize(content);

        Comment c = new Comment();
        c.setUserId(userId);
        c.setContent(safeContent);   // 存入的已经是安全的
        commentMapper.insert(c);
        return "{\"code\":0,\"msg\":\"safe comment posted, id=" + c.getId() + "\"}";
    }

    /**
     * 查看评论列表（完整 HTML 页面） —— 修复版
     * <p>
     * 防御点：输出前再做一次 HTML 实体转义，任何残留的特殊字符
     * 都会变成 {@code &lt;} {@code &gt;} 等实体，浏览器只会当文本显示。
     */
    @GetMapping(value = "/view", produces = MediaType.TEXT_HTML_VALUE)
    public String viewComments() {
        List<Comment> comments = commentMapper.selectList(null);

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><meta charset='UTF-8'>")
            .append("<title>Secure XSS Demo</title>")
            .append("<style>body{font-family:sans-serif;padding:20px;}")
            .append(".comment{border:1px solid #ddd;padding:10px;margin:8px 0;")
            .append("border-radius:4px;background:#f9f9f9;}</style></head><body>")
            .append("<h2>✅ 评论区（XSS 已修复）</h2>")
            .append("<p style='color:green'>🛡️ Jsoup 白名单过滤 + HtmlEscape 双重防御</p>");

        for (Comment c : comments) {
            // 防御点 ②：对输出再做 HTML 实体转义，兜底防御
            String safeDisplay = HtmlUtils.htmlEscape(c.getContent(), "UTF-8");
            html.append("<div class='comment'>")
                .append("<b>User#").append(c.getUserId()).append(":</b> ")
                .append(safeDisplay)    // ← 转义后输出
                .append("</div>");
        }
        html.append("</body></html>");
        return html.toString();
    }

    /**
     * JSON 返回 —— 修复版
     * <p>
     * 防御点：JSON 本身是安全载体（只要前端渲染时使用 textContent / Vue {{}}
     * 这种自动转义的方式，而不是 innerHTML / v-html）。
     */
    @GetMapping("/list")
    public List<Comment> list() {
        return commentMapper.selectList(null);
    }
}
