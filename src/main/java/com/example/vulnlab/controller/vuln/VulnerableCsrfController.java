package com.example.vulnlab.controller.vuln;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
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
 * 跨站请求伪造（CSRF）—— 漏洞版 Controller
 * <p>
 * 修改密码接口 <b>没有任何 CSRF Token 校验</b>，
 * 只要用户浏览器登录态没过期，攻击者就能在自己的恶意网页上构造跨站 POST 请求，
 * 冒充用户修改密码 / 转账余额。
 *
 * <h3>攻击原理</h3>
 * <pre>
 * 攻击者自己页面 evil.com 放个表单：
 *   &lt;form action="http://localhost:8080/vuln/csrf/changePwd" method="POST"&gt;
 *     &lt;input type="hidden" name="oldPassword" value="anything" /&gt;
 *     &lt;input type="hidden" name="newPassword" value="hacked123" /&gt;
 *   &lt;/form&gt;
 *   &lt;script&gt;document.forms[0].submit()&lt;/script&gt;
 *
 * 受害者只要在浏览器中打开 evil.com（此时 localhost:8080 的 JSESSIONID 还在 Cookie 里），
 * 跨站请求就会被携带 Session 发送 → 密码被篡改。
 * </pre>
 */
@RestController
@RequestMapping("/vuln/csrf")
public class VulnerableCsrfController {

    @Autowired
    private AccountMapper accountMapper;

    @Autowired
    private UserMapper userMapper;

    /**
     * [漏洞点] 改密码接口，无任何 CSRF Token 校验，允许跨站请求。
     */
    @PostMapping("/changePwd")
    public R<String> changePassword(@RequestParam String oldPassword,
                                    @RequestParam String newPassword,
                                    HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return R.fail(401, "not logged in");
        }
        Long userId = (Long) session.getAttribute(SessionKeys.CURRENT_USER_ID);
        if (userId == null) {
            return R.fail(401, "not logged in");
        }

        Account account = accountMapper.selectOne(
                new LambdaQueryWrapper<Account>().eq(Account::getUserId, userId));
        if (account == null) return R.fail(404, "account not found");

        // [漏洞点] 只校验了登录态，但完全没校验 CSRF Token
        if (!account.getPassword().equals(oldPassword)) {
            return R.fail(400, "old password incorrect");
        }

        // 直接修改
        account.setPassword(newPassword);
        accountMapper.updateById(account);

        // 同步 sys_user 表的密码（Wrapper 泛型必须是 User，而非 Account）
        LambdaUpdateWrapper<com.example.vulnlab.entity.User> uw = new LambdaUpdateWrapper<>();
        uw.eq(com.example.vulnlab.entity.User::getId, userId)
          .set(com.example.vulnlab.entity.User::getPassword, newPassword);
        userMapper.update(null, uw);

        return R.ok("password changed in vuln mode (⚠️ no CSRF protection!)", null);
    }

    /**
     * GET /csrf/token —— 供前端拿当前 Session 绑定的 CSRF Token
     * （漏洞版本来不需要，但方便对比演示）
     */
    @GetMapping("/token")
    public R<String> getToken(HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        Object token = session.getAttribute(SessionKeys.CSRF_TOKEN);
        return R.ok((String) token);
    }
}
