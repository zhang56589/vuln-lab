-- ============================================================
-- vuln-lab H2 建表脚本
-- 注意：H2 2.2+ 中 user / role / order 等为保留关键字，
-- 因此用户表命名为 sys_user，角色字段命名为 user_role，彻底避开保留字。
-- ============================================================

-- ---------- 用户表 ----------
CREATE TABLE IF NOT EXISTS sys_user (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(64)  NOT NULL UNIQUE,
    password    VARCHAR(128) NOT NULL,
    nickname    VARCHAR(64)  DEFAULT NULL,
    user_role   VARCHAR(32)  NOT NULL DEFAULT 'USER',
    created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

-- ---------- 订单表（用于水平越权 IDOR 场景）----------
CREATE TABLE IF NOT EXISTS orders (
    id          BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id     BIGINT        NOT NULL,
    amount      DECIMAL(12,2) NOT NULL,
    description VARCHAR(255)  DEFAULT NULL,
    status      INT           NOT NULL DEFAULT 0,
    created_at  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP
);

-- ---------- 评论表（用于 XSS 场景）----------
CREATE TABLE IF NOT EXISTS comment (
    id         BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT       NOT NULL,
    content    VARCHAR(1024) NOT NULL,
    created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

-- ---------- 账户表（用于 CSRF 场景：改密码/转账余额）----------
CREATE TABLE IF NOT EXISTS account (
    id         BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id    BIGINT       NOT NULL UNIQUE,
    balance    DECIMAL(14,2) NOT NULL DEFAULT 0,
    password   VARCHAR(128) NOT NULL
);
