package com.example.vulnlab.mapper;

import com.example.vulnlab.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

/**
 * SQL 注入演示专用 Mapper
 * <p>
 * 故意使用 {@code ${keyword}} 字符串拼接，而非 {@code #{keyword}} 预编译，
 * 从而制造真正的 SQL 注入漏洞。
 */
@Mapper
public interface VulnSqlMapper {

    /**
     * [漏洞点] 使用 ${} 直接拼接 keyword，存在 SQL 注入。
     * <p>
     * 典型 Payload：
     * <ul>
     *   <li>{@code ' OR '1'='1}           —— 绕过模糊查询，返回全部用户</li>
     *   <li>{@code ' UNION SELECT 1,username,password,4,5 FROM sys_user --}  —— 联合查询泄露密码</li>
     *   <li>{@code '; DROP TABLE sys_user; --}                                —— 堆叠查询删表（H2 支持）</li>
     * </ul>
     */
    // [漏洞点] 此处使用 ${} 直接拼接 keyword，存在 SQL 注入风险
    @Select("SELECT id, username, nickname, user_role FROM sys_user WHERE username LIKE '%${keyword}%' OR nickname LIKE '%${keyword}%'")
    List<User> searchUserVuln(@Param("keyword") String keyword);
}
