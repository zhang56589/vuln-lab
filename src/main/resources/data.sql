-- ============================================================
-- vuln-lab 演示数据
-- ============================================================

-- ---------- 用户 ----------
INSERT INTO sys_user (id, username, password, nickname, user_role) VALUES
(1, 'admin', 'admin123', '超级管理员', 'ADMIN'),
(2, 'user',  'user123',  '张三',       'USER'),
(3, 'alice', 'alice123', '爱丽丝',     'USER');

-- ---------- 订单（用于 IDOR 越权：user=2 的订单不应被 user=3 访问）----------
INSERT INTO orders (id, user_id, amount, description, status) VALUES
(1001, 1, 8888.00, '管理员的机密订单',       1),
(2001, 2,  199.00, '张三的电脑订单',         1),
(2002, 2,   59.90, '张三的鼠标订单',         0),
(3001, 3, 3200.00, '爱丽丝的键盘订单',       1);

-- ---------- 评论（用于 XSS：包含普通文本，方便注入脚本攻击演示）----------
INSERT INTO comment (id, user_id, content) VALUES
(1, 2, '这个商品质量真不错，值得推荐！'),
(2, 3, '物流很快，包装也很用心。'),
(3, 2, '价格合理，下次还会再来。');

-- ---------- 账户（用于 CSRF：admin 和 user 各有余额）----------
INSERT INTO account (id, user_id, balance, password) VALUES
(1, 1, 99999.99, 'admin123'),
(2, 2,  5000.00, 'user123'),
(3, 3,  1200.50, 'alice123');
