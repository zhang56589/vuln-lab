package com.example.vulnlab.controller;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.example.vulnlab.common.R;
import com.example.vulnlab.common.SessionKeys;
import com.example.vulnlab.entity.User;
import com.example.vulnlab.mapper.UserMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * 统一登录入口（供 IDOR / CSRF 防御版演示使用）
 * <p>
 * 登录成功后把 {@code userId} 写入 {@link HttpSession}，
 * 后续 Secure 版的 IDOR / CSRF 接口将从 Session 中取 userId
 * 做权限校验。
 */
@RestController
@RequestMapping("/auth")
public class LoginController {

    @Autowired
    private UserMapper userMapper;

    /**
     * POST /auth/login?username=admin&password=admin123
     * → 登录成功，Session 中写入 current_user_id
     */
    @PostMapping("/login")
    public R<User> login(@RequestParam String username,
                         @RequestParam String password,
                         HttpServletRequest request) {
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(User::getUsername, username)
               .eq(User::getPassword, password);
        User u = userMapper.selectOne(wrapper);
        if (u == null) {
            return R.fail(401, "username or password incorrect");
        }

        // 写入 Session，作为"当前登录用户"的唯一依据
        HttpSession session = request.getSession(true);
        session.setAttribute(SessionKeys.CURRENT_USER_ID, u.getId());
        session.setAttribute(SessionKeys.CURRENT_USERNAME, u.getUsername());

        // 为 Secure CSRF 版预生成 token（CsrfTokenFilter 也会兜底生成）
        return R.ok("login ok", u);
    }

    /**
     * GET /auth/logout
     */
    @PostMapping("/logout")
    public R<String> logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        return R.ok("logout ok", null);
    }

    /**
     * GET /auth/me —— 查看当前 Session 中的登录用户
     */
    @GetMapping("/me")
    public R<User> me(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return R.fail(401, "not logged in");
        }
        Long userId = (Long) session.getAttribute(SessionKeys.CURRENT_USER_ID);
        if (userId == null) {
            return R.fail(401, "not logged in");
        }
        User u = userMapper.selectById(userId);
        return R.ok(u);
    }
}
