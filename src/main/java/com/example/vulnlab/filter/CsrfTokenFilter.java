package com.example.vulnlab.filter;

import com.example.vulnlab.common.SessionKeys;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

/**
 * 自研 CSRF 防御 Filter（双提交 Cookie 模式简化版）
 * <p>
 * 工作流程：
 * <ol>
 *   <li>任何请求首次到达时，在 Session 中生成并绑定一个 {@code csrf_token}（UUID）</li>
 *   <li>同时在响应头 {@code X-CSRF-Token} 中回显该 token（前端可取到后塞到后续请求头/表单里）</li>
 *   <li>对 {@code /secure/csrf/**} 下的写操作（POST/PUT/DELETE）强制校验</li>
 *   <li>客户端必须通过 {@code X-CSRF-Token} 请求头或 {@code csrfToken} 表单参数回传 token</li>
 *   <li>与 Session 中绑定的值比对，不一致直接 403</li>
 * </ol>
 * <p>
 * 为什么能防 CSRF？
 * 攻击者在自己网站上无法读取目标站的 Session（浏览器同源策略），
 * 因此也无法知道 Session 中绑定的 csrf_token 值，自然无法构造合法的跨站 POST 请求。
 */
public class CsrfTokenFilter implements Filter {

    /** 需要做 CSRF 校验的路径前缀 */
    private static final String SECURE_CSRF_PREFIX = "/secure/csrf";

    /** 豁免路径（token 生成接口、登录、h2-console） */
    private static final List<String> EXCLUDE_PATHS = List.of(
            "/csrf/token",
            "/auth/login",
            "/auth/logout",
            "/vuln/",          // 漏洞版全部豁免（故意不防御）
            "/h2-console"
    );

    /** 需要校验的危险方法 */
    private static final List<String> SAFE_METHODS = List.of("GET", "HEAD", "OPTIONS", "TRACE");

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        String uri = request.getRequestURI();
        String method = request.getMethod().toUpperCase();

        HttpSession session = request.getSession(true); // 若无则创建

        // ---- 1. Session 首次生成 token ----
        String token = (String) session.getAttribute(SessionKeys.CSRF_TOKEN);
        if (token == null) {
            token = UUID.randomUUID().toString().replace("-", "");
            session.setAttribute(SessionKeys.CSRF_TOKEN, token);
        }
        // 无论什么请求都把 token 通过响应头回显给前端（前端取到后带回后续写请求）
        response.setHeader("X-CSRF-Token", token);

        // ---- 2. 判断是否需要做 CSRF 校验 ----
        if (SAFE_METHODS.contains(method) || isExcluded(uri)) {
            chain.doFilter(req, res);
            return;
        }

        if (!uri.startsWith(SECURE_CSRF_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        // ---- 3. 读取客户端回传的 token ----
        String clientToken = extractClientToken(request);
        if (clientToken == null || !clientToken.equals(token)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(
                    "{\"code\":403,\"msg\":\"CSRF token missing or mismatch\",\"data\":null}");
            return;
        }

        chain.doFilter(req, res);
    }

    private boolean isExcluded(String uri) {
        for (String p : EXCLUDE_PATHS) {
            if (uri.startsWith(p)) return true;
        }
        return false;
    }

    /**
     * 从 Header（X-CSRF-Token）或 Form 表单参数（csrfToken）中提取客户端 token。
     * 注意：为了能读取表单参数，我们用一个简单的 wrapper 暴露 getParameter。
     */
    private String extractClientToken(HttpServletRequest request) {
        String header = request.getHeader("X-CSRF-Token");
        if (header != null && !header.isBlank()) return header.trim();

        // 从请求参数读（适用于 Form 表单 POST）
        String param = request.getParameter("csrfToken");
        if (param != null && !param.isBlank()) return param.trim();

        return null;
    }
}
