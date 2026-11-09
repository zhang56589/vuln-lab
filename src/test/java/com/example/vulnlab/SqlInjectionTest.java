package com.example.vulnlab;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * SQL 注入攻防对比测试
 * <p>
 * 攻击 Payload: {@code ' OR '1'='1}
 * <ul>
 *   <li>Vulnerable: 拼接进 SQL，绕过模糊查询 → 返回全部 3 个用户</li>
 *   <li>Secure:   QueryWrapper.like() 走预编译，payload 被当作普通字符串 → 返回 0 个</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("SQL 注入攻防对比测试")
class SqlInjectionTest {

    @Autowired
    private MockMvc mockMvc;

    /** 攻击 Payload：' OR '1'='1 */
    private static final String INJECT_PAYLOAD = "' OR '1'='1";

    @Test
    @DisplayName("【漏洞版】keyword=' OR '1'='1 → 返回全部 3 个用户（注入成功）")
    void vuln_search_shouldReturnAllUsers() throws Exception {
        // 攻击 Payload: keyword=' OR '1'='1
        // VulnSqlMapper 内部 @Select("... LIKE '%${keyword}%' ...")
        // → 最终 SQL 变为: ... WHERE username LIKE '%' OR '1'='1%' ...
        mockMvc.perform(get("/vuln/sql/search")
                        .param("keyword", INJECT_PAYLOAD))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0))
                // data 是数组，长度应该等于整张表的用户数（3）
                .andExpect(jsonPath("$.data", hasSize(3)))
                .andExpect(jsonPath("$.data[0].username").value("admin"))
                .andExpect(jsonPath("$.data[1].username").value("user"))
                .andExpect(jsonPath("$.data[2].username").value("alice"));
    }

    @Test
    @DisplayName("【修复版】同样 Payload → 返回 0 个用户（参数化防御）")
    void secure_search_shouldBlockInjection() throws Exception {
        // 修复版使用 MyBatis-Plus QueryWrapper.like()，底层走 PreparedStatement ?
        // payload 被当作普通字符串，LIKE '%' OR '1'='1%' 匹配不到任何记录
        mockMvc.perform(get("/secure/sql/search")
                        .param("keyword", INJECT_PAYLOAD))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0))
                .andExpect(jsonPath("$.data", hasSize(0)));
    }

    @Test
    @DisplayName("【修复版】正常查询 admin 仍然返回 1 条业务数据（不应误伤）")
    void secure_normalSearch_shouldWork() throws Exception {
        mockMvc.perform(get("/secure/sql/search")
                        .param("keyword", "admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0))
                .andExpect(jsonPath("$.data", hasSize(1)))
                .andExpect(jsonPath("$.data[0].username").value("admin"));
    }

    @Test
    @DisplayName("【漏洞版】联合查询 Payload 被成功执行（额外演示）")
    void vuln_unionSelectPayload_shouldSucceed() throws Exception {
        // UNION SELECT: 利用注入拼接额外的查询
        String unionPayload = "' UNION SELECT 1,'hack','hacker','HACK' --";
        MvcResult result = mockMvc.perform(get("/vuln/sql/search")
                        .param("keyword", unionPayload))
                .andExpect(status().isOk())
                .andReturn();

        // 结果里应该能看到我们注入的 "hack" / "hacker"
        String body = result.getResponse().getContentAsString();
        org.junit.jupiter.api.Assertions.assertTrue(
                body.contains("hack") || body.contains("hacker"),
                "UNION 注入应该能让我们自定义的记录出现在返回结果里，实际返回: " + body);
    }
}
