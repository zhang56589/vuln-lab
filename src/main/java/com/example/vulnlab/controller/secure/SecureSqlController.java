package com.example.vulnlab.controller.secure;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.example.vulnlab.common.R;
import com.example.vulnlab.entity.User;
import com.example.vulnlab.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * SQL 注入 —— 修复版 Controller
 * <p>
 * 使用 MyBatis-Plus 的 {@link LambdaQueryWrapper} 构造查询条件，
 * 框架内部统一使用 JDBC PreparedStatement 预编译 {@code #{}}，
 * 所有用户输入只会作为参数值绑定，绝不会进入 SQL 语法位置。
 */
@RestController
@RequestMapping("/secure/sql")
public class SecureSqlController {

    @Autowired
    private UserMapper userMapper;

    /**
     * 模糊搜索用户 —— 修复版
     * <p>
     * 防御点：QueryWrapper.like() 底层走 PreparedStatement 的 ? 占位符，
     * 攻击者输入的 {@code ' OR '1'='1} 会被当作普通字符串值进行 LIKE 匹配，
     * 不会破坏 SQL 结构。
     */
    @GetMapping("/search")
    public R<List<User>> search(@RequestParam String keyword) {
        // 防御点：使用 MyBatis-Plus LambdaQueryWrapper 参数化查询，防止 SQL 注入
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.and(w -> w
                .like(User::getUsername, keyword)
                .or()
                .like(User::getNickname, keyword));
        wrapper.select(User::getId, User::getUsername, User::getNickname, User::getUserRole);

        List<User> users = userMapper.selectList(wrapper);
        return R.ok("found " + users.size() + " users", users);
    }

    /**
     * 登录查询 —— 修复版
     * <p>
     * 防御点：eq() 条件同样走预编译，配合密码哈希（本 demo 简化为明文字段相等），
     * 无法通过注入绕过校验。
     */
    @PostMapping("/login")
    public R<User> login(@RequestParam String username,
                         @RequestParam String password) {
        // 防御点：eq() 条件走 PreparedStatement 预编译，杜绝拼接
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(User::getUsername, username)
               .eq(User::getPassword, password);
        User u = userMapper.selectOne(wrapper);
        if (u != null) {
            return R.ok("login success", u);
        }
        return R.fail(401, "username or password incorrect");
    }
}
