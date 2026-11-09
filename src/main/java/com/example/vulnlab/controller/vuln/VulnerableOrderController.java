package com.example.vulnlab.controller.vuln;

import com.example.vulnlab.common.R;
import com.example.vulnlab.entity.Orders;
import com.example.vulnlab.mapper.OrdersMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * 水平越权（IDOR）—— 漏洞版 Controller
 * <p>
 * 直接按订单 ID 查询并返回，完全不校验订单归属者。
 * 只要知道订单 ID，任何人都能查看他人订单详情 → IDOR。
 *
 * <h3>攻击示例</h3>
 * <pre>
 * # 用 user（userId=2）登录，尝试查看 admin（userId=1）的机密订单
 * POST /auth/login?username=user&password=user123
 * GET  /vuln/order/1001
 * → 成功返回 admin 的订单！  ❌  漏洞复现
 * </pre>
 */
@RestController
@RequestMapping("/vuln/order")
public class VulnerableOrderController {

    @Autowired
    private OrdersMapper ordersMapper;

    /**
     * [漏洞点] 只按 ID 查询，完全没有用户身份校验。
     * 攻击者只要知道订单号就能看到任何订单的详情（包括机密金额）。
     */
    @GetMapping("/{id}")
    public R<Orders> getOrder(@PathVariable Long id) {
        // [漏洞点] 未校验当前登录用户与订单所属人的关系
        Orders order = ordersMapper.selectById(id);
        if (order == null) {
            return R.fail(404, "order not found");
        }
        return R.ok(order);
    }

    /**
     * [漏洞点] 列出所有订单，不做用户隔离。
     */
    @GetMapping("/list")
    public R<?> listAll() {
        // [漏洞点] 无任何权限过滤，返回整张订单表
        return R.ok(ordersMapper.selectList(null));
    }
}
