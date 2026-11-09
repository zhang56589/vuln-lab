package com.example.vulnlab.controller.secure;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.example.vulnlab.common.R;
import com.example.vulnlab.common.SessionKeys;
import com.example.vulnlab.entity.Account;
import com.example.vulnlab.mapper.AccountMapper;
import com.example.vulnlab.mapper.UserMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * 跨站请求伪造（CSRF）—— 修复版 Controller
 * <p>
 * 防御点 <b>不在 Controller 里</b>，而在 {@link com.example.vulnlab.filter.CsrfTokenFilter}：
 * <ul>
 *   <li>Filter 对所有 {@code /secure/csrf/**} 的写请求（POST/PUT/DELETE）强制校验</li>
 *   <li>客户端必须通过 {@code X-CSRF-Token} 头或 {@code csrfToken} 表单参数回传 token</li>
 *   <li>Token 与 Session 中绑定值不匹配 → 直接 403，Controller 根本进不来</li>
 * </ul>
 * <h3>攻击 Payload 对比</h3>
 * <pre>
 * # 攻击者构造的恶意表单 (无 token)
 * POST /secure/csrf/changePwd
 *   oldPassword=xxx&newPassword=hacked
 * → CsrfTokenFilter 返回 403 "CSRF token missing or mismatch"  ✅ 防御成功
 *
 * # 合法客户端（先 GET /csrf/token 拿到 token，再带回）
 * POST /secure/csrf/changePwd
 *   X-CSRF-Token: a1b2c3d4...  ← 与 Session 绑定值匹配
 * → 正常改密
 * </pre>
 */
@RestController
@RequestMapping("/secure/csrf")
public class SecureCsrfController {

    @Autowired
    private AccountMapper accountMapper;

    @Autowired
    private UserMapper userMapper;

    /**
     * 改密码 —— 修复版
     * <p>
     * 防御点已由 {@link com.example.vulnlab.filter.CsrfTokenFilter} 在请求进入 Controller 之前统一完成，
     * 此处只做业务逻辑（旧密码校验 / 更新）。
     */
    @PostMapping("/changePwd")
    public R<String> changePassword(@RequestParam String oldPassword,
                                    @RequestParam String newPassword,
                                    HttpServletRequest request) {
        // 防御点（双保险）：Controller 层也可再读一次，但 Filter 已兜底
        HttpSession session = request.getSession(false);
        if (session == null) return R.fail(401, "not logged in");
        Long userId = (Long) session.getAttribute(SessionKeys.CURRENT_USER_ID);
        if (userId == null) return R.fail(401, "not logged in");

        Account account = accountMapper.selectOne(
                new LambdaQueryWrapper<Account>().eq(Account::getUserId, userId));
        if (account == null) return R.fail(404, "account not found");

        if (!account.getPassword().equals(oldPassword)) {
            return R.fail(400, "old password incorrect");
        }
        account.setPassword(newPassword);
        accountMapper.updateById(account);

        return R.ok("password changed securely (CSRF token verified by CsrfTokenFilter)", null);
    }
}
