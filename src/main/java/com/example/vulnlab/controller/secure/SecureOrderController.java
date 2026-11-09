package com.example.vulnlab.controller.secure;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.example.vulnlab.common.R;
import com.example.vulnlab.common.SessionKeys;
import com.example.vulnlab.entity.Orders;
import com.example.vulnlab.mapper.OrdersMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 水平越权（IDOR）—— 修复版 Controller
 * <p>
 * 强制从 {@link HttpSession} 取出当前登录用户的 userId，
 * 对每个订单查询都校验 {@code order.userId == session.userId}，
 * 不匹配返回 403 Forbidden。
 */
@RestController
@RequestMapping("/secure/order")
public class SecureOrderController {

    @Autowired
    private OrdersMapper ordersMapper;

    /**
     * 获取当前登录用户，未登录直接返回 401
     */
    private Long currentUserId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) return null;
        return (Long) session.getAttribute(SessionKeys.CURRENT_USER_ID);
    }

    /**
     * 按 ID 查询订单 —— 修复版
     * <p>
     * 防御点 ①：未登录 → 401。
     * 防御点 ②：订单 userId 与 session userId 不一致 → 403（水平越权）。
     */
    @GetMapping("/{id}")
    public R<Orders> getOrder(@PathVariable Long id, HttpServletRequest request) {
        Long userId = currentUserId(request);
        if (userId == null) {
            return R.fail(401, "please login first");
        }

        Orders order = ordersMapper.selectById(id);
        if (order == null) {
            return R.fail(404, "order not found");
        }

        // 防御点：强制校验订单归属，防止水平越权 IDOR
        if (!userId.equals(order.getUserId())) {
            return R.fail(403, "forbidden: this order does not belong to you");
        }
        return R.ok(order);
    }

    /**
     * 列出当前用户自己的订单 —— 修复版
     * <p>
     * 防御点：WHERE user_id = 当前登录用户，数据天然隔离。
     */
    @GetMapping("/list")
    public R<List<Orders>> listMine(HttpServletRequest request) {
        Long userId = currentUserId(request);
        if (userId == null) {
            return R.fail(401, "please login first");
        }

        // 防御点：QueryWrapper 加 user_id 精确过滤，多租户隔离
        LambdaQueryWrapper<Orders> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(Orders::getUserId, userId)
               .orderByDesc(Orders::getId);
        return R.ok(ordersMapper.selectList(wrapper));
    }
}
