package com.example.vulnlab.config;

import com.example.vulnlab.filter.CsrfTokenFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Web 组件注册配置（自研过滤器，不依赖 Spring Security）
 */
@Configuration
public class WebConfig {

    /**
     * 注册自研 CSRF Token 过滤器
     * <p>
     * 只对 {@code /*} 生效；Filter 内部再精细区分哪些路径需要校验。
     */
    @Bean
    public FilterRegistrationBean<CsrfTokenFilter> csrfTokenFilter() {
        FilterRegistrationBean<CsrfTokenFilter> reg = new FilterRegistrationBean<>();
        reg.setFilter(new CsrfTokenFilter());
        reg.addUrlPatterns("/*");
        reg.setName("csrfTokenFilter");
        reg.setOrder(1);
        return reg;
    }
}
