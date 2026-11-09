package com.example.vulnlab.common;

import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;

/**
 * HTML 安全过滤工具（用于 XSS 防御）
 * <p>
 * 基于 <a href="https://jsoup.org/">Jsoup</a> 的 {@link Safelist} 白名单机制：
 * <ul>
 *   <li>默认只允许 {@code basicWithImages}（安全的基础标签 + 图片）</li>
 *   <li>所有事件属性（onclick / onerror / on*）自动剥离</li>
 *   <li>危险协议（javascript: / vbscript:）的 href/src 被改写为空</li>
 * </ul>
 */
public final class HtmlSanitizerUtil {

    private HtmlSanitizerUtil() {}

    /**
     * 允许的安全标签集合：基础标签 + 图片 + 超链接 + 行内样式（极有限）
     */
    private static final Safelist SAFE_LIST = Safelist.basicWithImages()
            .addTags("p", "br", "span", "div", "pre", "code", "blockquote")
            .addAttributes("a", "target", "rel")
            .addProtocols("a", "href", "http", "https", "mailto");

    /**
     * 使用白名单过滤 HTML，仅保留安全标签与属性。
     *
     * @param raw 用户输入（可能包含恶意脚本）
     * @return 过滤后的安全 HTML；若为 null 返回空串
     */
    public static String sanitize(String raw) {
        if (raw == null) return "";
        // Jsoup.clean 内部会：
        //   1. 解析输入为 DOM
        //   2. 剔除所有不在白名单中的标签/属性/协议
        //   3. 重新序列化输出
        return Jsoup.clean(raw, SAFE_LIST);
    }

    /**
     * 严格模式：移除所有标签，仅保留纯文本。
     * 适用于姓名、昵称这类绝对不允许 HTML 的字段。
     */
    public static String stripAllTags(String raw) {
        if (raw == null) return "";
        return Jsoup.parse(raw).text();
    }
}
