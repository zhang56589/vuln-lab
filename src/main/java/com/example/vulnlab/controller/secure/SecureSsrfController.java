package com.example.vulnlab.controller.secure;

import com.example.vulnlab.common.R;
import com.example.vulnlab.common.SsrfGuard;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URI;
import java.util.stream.Collectors;

/**
 * 服务端请求伪造（SSRF）—— 修复版 Controller
 * <p>
 * 先发请求前，强制调用 {@link SsrfGuard#validate(String)}：
 * <ol>
 *   <li>协议白名单（http/https）</li>
 *   <li>DNS 预解析（getAllByName 拿到全部 A 记录）</li>
 *   <li>内网 IP 黑名单（loopback / 10.* / 172.16-31.* / 192.168.* / 169.254.* / IPv6 内网）</li>
 *   <li>DNS 重绑定防御：只要解析结果里有内网 IP 就拒绝</li>
 * </ol>
 * Payload 对比：
 * <pre>
 * Secure 接口会直接拒绝：
 *   url=http://127.0.0.1:8080/h2-console   → "blocked: target host '127.0.0.1' resolved to internal IP"
 *   url=http://169.254.169.254/...         → "blocked: target host '169.254.169.254' resolved to internal IP"
 *   url=http://evil.site.com                → 只要 evil.site.com 解析出 127.0.0.1 / 10.* 也一样拒绝
 * </pre>
 */
@RestController
@RequestMapping("/secure/ssrf")
public class SecureSsrfController {

    @GetMapping("/fetch")
    public R<String> fetch(@RequestParam String url) {
        try {
            // 防御点 ①：SsrfGuard 先做协议白名单 + DNS 预解析 + 内网黑名单校验
            URI safeUri = SsrfGuard.validate(url);

            // 防御点 ②：只对校验通过的 URI 发起请求
            URL target = safeUri.toURL();
            HttpURLConnection conn = (HttpURLConnection) target.openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(5000);
            conn.setInstanceFollowRedirects(false); // 防御点 ③：禁止自动跟随重定向，防 redirect 绕过
            conn.setRequestMethod("GET");

            int code = conn.getResponseCode();
            String body;
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(code >= 400 ? conn.getErrorStream() : conn.getInputStream()))) {
                body = br.lines().collect(Collectors.joining("\n"));
            }
            if (body.length() > 2048) body = body.substring(0, 2048) + "...(truncated)";
            return R.ok("remote http " + code, body);
        } catch (IllegalArgumentException e) {
            // 防御点 ④：校验失败统一返回 400 + 明确错误，不泄露内部拓扑
            return R.fail(400, "SSRF blocked: " + e.getMessage());
        } catch (Exception e) {
            return R.fail("fetch error: " + e.getMessage());
        }
    }
}
