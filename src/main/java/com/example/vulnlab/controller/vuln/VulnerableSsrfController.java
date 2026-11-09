package com.example.vulnlab.controller.vuln;

import com.example.vulnlab.common.R;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URI;
import java.util.stream.Collectors;

/**
 * 服务端请求伪造（SSRF）—— 漏洞版 Controller
 * <p>
 * 直接把用户传入的 URL 丢给 JDK HttpClient 发请求，
 * 没有任何协议/IP 校验。攻击者可以：
 * <ul>
 *   <li>探测内网服务：{@code url=http://127.0.0.1:8080/h2-console}</li>
 *   <li>访问云元数据：{@code url=http://169.254.169.254/latest/meta-data/}</li>
 *   <li>攻击内网 Web：{@code url=http://192.168.1.1/admin}</li>
 * </ul>
 */
@RestController
@RequestMapping("/vuln/ssrf")
public class VulnerableSsrfController {

    /**
     * [漏洞点] 直接使用用户传入的 URL 发起服务端请求，无任何过滤。
     *
     * Payload 示例：
     * <pre>
     * # 探测本地服务
     * GET /vuln/ssrf/fetch?url=http://127.0.0.1:8080/h2-console
     *
     * # 访问云元数据（AWS/阿里云实例）
     * GET /vuln/ssrf/fetch?url=http://169.254.169.254/latest/meta-data/
     * </pre>
     */
    @GetMapping("/fetch")
    public R<String> fetch(@RequestParam String url) {
        // [漏洞点] 未做任何协议 / 域名 / IP 校验，直接请求
        try {
            URI uri = URI.create(url.trim());
            URL target = uri.toURL();
            HttpURLConnection conn = (HttpURLConnection) target.openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(5000);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestMethod("GET");

            int code = conn.getResponseCode();
            String body;
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(code >= 400 ? conn.getErrorStream() : conn.getInputStream()))) {
                body = br.lines().collect(Collectors.joining("\n"));
            }
            // 截断过长响应，避免把内存打爆
            if (body.length() > 2048) body = body.substring(0, 2048) + "...(truncated)";
            return R.ok("remote http " + code, body);
        } catch (Exception e) {
            return R.fail("fetch error: " + e.getMessage());
        }
    }
}
