package com.example.vulnlab.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * 订单表：orders（用于水平越权 IDOR 场景）
 */
@TableName("orders")
public class Orders {

    @TableId(type = IdType.AUTO)
    private Long id;

    private Long userId;
    private BigDecimal amount;
    private String description;
    private Integer status;        // 0=待支付 1=已支付

    private LocalDateTime createdAt;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public Integer getStatus() { return status; }
    public void setStatus(Integer status) { this.status = status; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    @Override
    public String toString() {
        return "Orders{id=" + id + ", userId=" + userId + ", amount=" + amount
                + ", description='" + description + "', status=" + status + "}";
    }
}
