package com.example.vulnlab.controller.vuln;

import com.example.vulnlab.entity.Comment;
import com.example.vulnlab.mapper.CommentMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 存储型 XSS —— 漏洞版 Controller
 * <p>
 * 接收用户评论后<strong>原样存入数据库</strong>，
 * 在 {@code /view} 接口中把所有评论内容拼接进 HTML 页面字符串并原样返回，
 * 浏览器会直接执行其中的 {@code <script>} 标签。
 *
 * <h3>攻击示例</h3>
 * <pre>
 * # 1. 注入恶意评论
 * curl -X POST "http://localhost:8080/vuln/xss/comment" \
 *      -d "content=hello&lt;script&gt;alert('XSS!')&lt;/script&gt;world"
 *
 * # 2. 浏览器访问查看页面 → 弹窗 "XSS!"
 * http://localhost:8080/vuln/xss/view
 * </pre>
 */
@RestController
@RequestMapping("/vuln/xss")
public class VulnerableXssController {

    @Autowired
    private CommentMapper commentMapper;

    /**
     * 发布评论 —— 漏洞版
     * <p>
     * [漏洞点] 直接把用户输入写入数据库，没有任何 HTML 过滤/转义。
     */
    @PostMapping(value = "/comment", produces = "application/json;charset=UTF-8")
    public String postComment(@RequestParam String content,
                              @RequestParam(defaultValue = "1") Long userId) {
        // [漏洞点] 未过滤、未转义，原样存入
        Comment c = new Comment();
        c.setUserId(userId);
        c.setContent(content);
        commentMapper.insert(c);
        return "{\"code\":0,\"msg\":\"comment posted, id=" + c.getId() + "\"}";
    }

    /**
     * 查看评论列表（完整 HTML 页面） —— 漏洞版
     * <p>
     * [漏洞点] 把数据库里的评论内容直接拼进 HTML 字符串返回给浏览器，
     * 攻击者注入的 {@code <script>} 会被浏览器当作脚本执行。
     */
    @GetMapping(value = "/view", produces = MediaType.TEXT_HTML_VALUE)
    public String viewComments() {
        List<Comment> comments = commentMapper.selectList(null);

        // [漏洞点] 直接字符串拼接，不做任何 HTML 转义
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><meta charset='UTF-8'>")
            .append("<title>Vuln XSS Demo</title>")
            .append("<style>body{font-family:sans-serif;padding:20px;}")
            .append(".comment{border:1px solid #ddd;padding:10px;margin:8px 0;")
            .append("border-radius:4px;background:#f9f9f9;}</style></head><body>")
            .append("<h2>💬 评论区（XSS 漏洞演示）</h2>")
            .append("<p style='color:red'>⚠️ 此页面存在存储型 XSS，浏览器将直接执行评论中的脚本！</p>");

        for (Comment c : comments) {
            // [漏洞点] content 原样输出，script 会被执行
            html.append("<div class='comment'>")
                .append("<b>User#").append(c.getUserId()).append(":</b> ")
                .append(c.getContent())      // ← 直接拼接，不转义！
                .append("</div>");
        }
        html.append("</body></html>");
        return html.toString();
    }

    /**
     * 查询 JSON 接口（方便用脚本获取数据，同样存在 XSS）
     */
    @GetMapping("/list")
    public List<Comment> list() {
        return commentMapper.selectList(null);
    }
}
