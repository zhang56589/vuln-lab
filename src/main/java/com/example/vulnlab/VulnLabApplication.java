package com.example.vulnlab;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * vuln-lab 启动类
 * <p>
 * 5 类漏洞靶场：SQLi / XSS / IDOR / SSRF / CSRF
 * 所有漏洞版接口前缀：/vuln/
 * 所有修复版接口前缀：/secure/
 */
@SpringBootApplication
@MapperScan("com.example.vulnlab.mapper")
public class VulnLabApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnLabApplication.class, args);
        System.out.println("""
                ============================================================
                   vuln-lab started on http://localhost:8080
                   H2 Console : http://localhost:8080/h2-console
                   JDBC URL   : jdbc:h2:mem:vulnlab  (user: sa, pwd: empty)
                   ---- Demo Accounts ----
                   admin / admin123
                   user  / user123
                   alice / alice123
                ============================================================
                """);
    }
}
