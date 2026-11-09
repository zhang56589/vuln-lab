package com.example.vulnlab;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.example.vulnlab.common.SessionKeys;

/**
 * 水平越权（IDOR）攻防对比测试
 * <p>
 * 测试场景：以 user（userId=2）登录，尝试访问 admin（userId=1）的机密订单 {id=1001}
 * <ul>
 *   <li>漏洞版：直接按 ID 返回 → 返回 200 + admin 机密数据</li>
 *   <li>修复版：Session.userId ≠ order.userId → 返回 403</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("水平越权 IDOR 攻防对比测试")
class IdorTest {

    @Autowired
    private MockMvc mockMvc;

    /** admin 的机密订单 ID（userId=1, amount=8888） */
    private static final Long ADMIN_ORDER_ID = 1001L;

    /** user 自己的订单 ID（userId=2） */
    private static final Long USER_OWN_ORDER_ID = 2001L;

    /** 以 user（userId=2）构造一个登录 Session */
    private MockHttpSession loginAsUser() {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(SessionKeys.CURRENT_USER_ID, 2L);
        session.setAttribute(SessionKeys.CURRENT_USERNAME, "user");
        return session;
    }

    @Test
    @DisplayName("【漏洞版】user 登录后直接 GET /vuln/order/1001 → 返回 admin 机密订单（越权成功）")
    void vuln_order_shouldReturnAnyOrderById() throws Exception {
        MockHttpSession session = loginAsUser();

        // 只按 order id 查询，完全不校验归属 → user 能看到 admin 的 8888 机密订单
        mockMvc.perform(get("/vuln/order/{id}", ADMIN_ORDER_ID)
                        .session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0))
                .andExpect(jsonPath("$.data.id").value(ADMIN_ORDER_ID.intValue()))
                // 关键断言：userId=1（admin）也能被返回 —— 说明越权
                .andExpect(jsonPath("$.data.userId").value(1))
                .andExpect(jsonPath("$.data.amount").value(8888.0));
    }

    @Test
    @DisplayName("【漏洞版】list 接口返回全部订单（无隔离）")
    void vuln_order_list_shouldReturnAll() throws Exception {
        MockHttpSession session = loginAsUser();
        mockMvc.perform(get("/vuln/order/list").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data", org.hamcrest.Matchers.hasSize(4)));
    }

    @Test
    @DisplayName("【修复版】user 访问 admin 的订单 → 403 Forbidden（越权被拦截）")
    void secure_order_shouldBlockCrossUser() throws Exception {
        MockHttpSession session = loginAsUser();

        mockMvc.perform(get("/secure/order/{id}", ADMIN_ORDER_ID)
                        .session(session))
                .andExpect(status().isOk())        // HTTP 200（业务错误码在 body）
                .andExpect(jsonPath("$.code").value(403))
                .andExpect(jsonPath("$.msg").value(org.hamcrest.Matchers.containsString("forbidden")));
    }

    @Test
    @DisplayName("【修复版】user 访问自己的订单 2001 → 正常返回 200 OK + 业务成功")
    void secure_order_shouldAllowOwner() throws Exception {
        MockHttpSession session = loginAsUser();

        mockMvc.perform(get("/secure/order/{id}", USER_OWN_ORDER_ID)
                        .session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0))
                .andExpect(jsonPath("$.data.id").value(USER_OWN_ORDER_ID.intValue()))
                .andExpect(jsonPath("$.data.userId").value(2));
    }

    @Test
    @DisplayName("【修复版】user 的 list 只返回自己的订单（数据隔离）")
    void secure_order_list_shouldFilterByUser() throws Exception {
        MockHttpSession session = loginAsUser();
        mockMvc.perform(get("/secure/order/list").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(0))
                // user=2 有两条订单：2001 / 2002
                .andExpect(jsonPath("$.data", org.hamcrest.Matchers.hasSize(2)))
                // 所有返回的 userId 必须等于 2
                .andExpect(jsonPath("$.data[0].userId").value(2))
                .andExpect(jsonPath("$.data[1].userId").value(2));
    }

    @Test
    @DisplayName("【修复版】未登录访问 → 401")
    void secure_order_shouldRejectAnonymous() throws Exception {
        // 不传 Session → 未登录
        mockMvc.perform(get("/secure/order/{id}", USER_OWN_ORDER_ID))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value(401));
    }
}
