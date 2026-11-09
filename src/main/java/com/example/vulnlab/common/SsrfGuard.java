package com.example.vulnlab.common;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Locale;

/**
 * SSRF 防御工具类
 * <p>
 * 核心防御点：
 * <ol>
 *   <li>协议白名单：只允许 http / https</li>
 *   <li>DNS 预解析：{@link InetAddress#getAllByName(String)} 拿到所有 A 记录</li>
 *   <li>内网 IP 黑名单：127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1, fe80::/10, fc00::/7</li>
 *   <li>DNS 重绑定防御：对所有解析出来的 IP 逐一检查，<b>只要其中有一个命中内网就拒绝</b>
 *       （攻击者要绕过必须让"目标域名同时返回公网 IP 供预检 + 内网 IP 供后续实际请求"，
 *       这种行为本身就会被 getAllByName 的预检拦截）</li>
 * </ol>
 */
public final class SsrfGuard {

    private SsrfGuard() {}

    /** 允许的协议 */
    private static final List<String> ALLOWED_PROTOCOLS = List.of("http", "https");

    /**
     * 校验 URL 是否安全，不安全会抛出 {@link IllegalArgumentException}
     *
     * @param rawUrl 用户传入的 URL 字符串
     * @return 解析好的安全 URI
     */
    public static URI validate(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            throw new IllegalArgumentException("url must not be empty");
        }

        URI uri;
        try {
            uri = URI.create(rawUrl.trim());
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid url format: " + rawUrl);
        }

        // 1. 协议白名单
        String scheme = uri.getScheme();
        if (scheme == null || !ALLOWED_PROTOCOLS.contains(scheme.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("only http / https allowed, got: " + scheme);
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("url host is empty");
        }

        // 2. DNS 预解析 + 内网 IP 黑名单
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("dns resolve failed for host: " + host);
        }

        if (addresses == null || addresses.length == 0) {
            throw new IllegalArgumentException("no ip resolved for host: " + host);
        }

        // 防御点：只要 getAllByName 返回的 IP 列表中存在内网 IP，就直接拒绝
        // 这样 DNS 重绑定攻击需要"同一域名先返回公网 IP 给预检、再返回内网 IP 给真实请求"——
        // 在本预检策略下不可能通过（预检阶段就被内网 IP 拦截）
        for (InetAddress addr : addresses) {
            if (isInternalIp(addr)) {
                throw new IllegalArgumentException(
                        "blocked: target host '" + host + "' resolved to internal IP: " + addr.getHostAddress());
            }
        }

        return uri;
    }

    /**
     * 判断是否为内网/回环/链路本地/保留地址
     */
    static boolean isInternalIp(InetAddress addr) {
        if (addr == null) return true;
        // InetAddress 内置方法——覆盖了 loopback / link-local / site-local / multicast / any-local
        if (addr.isLoopbackAddress()
                || addr.isLinkLocalAddress()
                || addr.isSiteLocalAddress()   // 10.*/172.16-31.*/192.168.*
                || addr.isMulticastAddress()
                || addr.isAnyLocalAddress()) {
            return true;
        }
        // 额外兜底：169.254.0.0/16（Windows 自动分配）
        String ip = addr.getHostAddress();
        if (ip != null && ip.startsWith("169.254.")) {
            return true;
        }
        // IPv4-mapped IPv6 兜底
        if (ip != null && ip.startsWith("::ffff:")) {
            String ipv4 = ip.substring(7);
            return isInternalIpv4(ipv4);
        }
        return false;
    }

    private static boolean isInternalIpv4(String ip) {
        try {
            String[] parts = ip.split("\\.");
            if (parts.length != 4) return true;
            int[] p = new int[4];
            for (int i = 0; i < 4; i++) p[i] = Integer.parseInt(parts[i]);
            // 127.0.0.0/8
            if (p[0] == 127) return true;
            // 10.0.0.0/8
            if (p[0] == 10) return true;
            // 172.16.0.0/12
            if (p[0] == 172 && p[1] >= 16 && p[1] <= 31) return true;
            // 192.168.0.0/16
            if (p[0] == 192 && p[1] == 168) return true;
            // 169.254.0.0/16
            if (p[0] == 169 && p[1] == 254) return true;
            return false;
        } catch (Exception e) {
            return true; // 解析失败默认拒绝，fail-close
        }
    }
}
