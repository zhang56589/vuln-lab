package com.example.vulnlab.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;

import java.math.BigDecimal;

/**
 * 账户表：account（用于 CSRF 场景：改密码 / 转账余额）
 */
@TableName("account")
public class Account {

    @TableId(type = IdType.AUTO)
    private Long id;

    private Long userId;
    private BigDecimal balance;
    private String password;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    public BigDecimal getBalance() { return balance; }
    public void setBalance(BigDecimal balance) { this.balance = balance; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    @Override
    public String toString() {
        return "Account{id=" + id + ", userId=" + userId + ", balance=" + balance + "}";
    }
}
