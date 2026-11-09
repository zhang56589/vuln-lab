package com.example.vulnlab.controller.vuln;

import com.example.vulnlab.common.R;
import com.example.vulnlab.entity.User;
import com.example.vulnlab.mapper.VulnSqlMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * SQL 注入 —— 漏洞版 Controller
 * <p>
 * 直接调用 {@link VulnSqlMapper#searchUserVuln(String)}，
 * 该方法内部使用 {@code ${keyword}} 字符串拼接构造 SQL，
 * 从而让攻击者通过精心构造的 keyword 参数篡改查询逻辑。
 *
 * <h3>攻击 Payload 示例</h3>
 * <pre>
 * GET /vuln/sql/search?keyword=' OR '1'='1
 * → 返回所有用户（绕过模糊查询条件）
 *
 * GET /vuln/sql/search?keyword=' UNION SELECT 1,username,password,4,5 FROM user --
 * → 联合查询泄露所有账号密码
 * </pre>
 */
@RestController
@RequestMapping("/vuln/sql")
public class VulnerableSqlController {

    @Autowired
    private VulnSqlMapper vulnSqlMapper;

    /**
     * 模糊搜索用户 —— 漏洞版
     * <p>
     * [漏洞点] 直接透传 keyword 给使用 ${} 拼接的 Mapper，
     * 攻击者可构造 payload 绕过过滤或执行任意 SQL。
     */
    @GetMapping("/search")
    public R<List<User>> search(@RequestParam String keyword) {
        // [漏洞点] 未做任何过滤/参数化，直接透传给 ${} 拼接的 SQL
        List<User> users = vulnSqlMapper.searchUserVuln(keyword);
        return R.ok("found " + users.size() + " users", users);
    }

    /**
     * 登录查询 —— 漏洞版
     * <p>
     * 使用字符串拼接查询密码，经典 " ' OR '1'='1 " 登录绕过。
     * Payload: username=admin' OR '1'='1 & password=anything
     */
    @PostMapping("/login")
    public R<User> login(@RequestParam String username,
                         @RequestParam String password) {
        // [漏洞点] 再次演示：简单字符串拼接查询登录
        String sql = "SELECT id, username, nickname, role FROM user WHERE username = '"
                + username + "' AND password = '" + password + "'";
        // 直接拼接执行（内部仍然是 ${}，会被 VulnSqlMapper 兜底演示）
        User u = vulnSqlMapper.searchUserVuln(username).stream()
                .filter(x -> x.getUsername().equals(username))
                .findFirst().orElse(null);
        if (u != null) {
            return R.ok("login success", u);
        }
        return R.fail(401, "username or password incorrect");
    }
}
