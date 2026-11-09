package com.example.vulnlab.common;

/**
 * HttpSession 中使用的 Key 常量
 */
public final class SessionKeys {

    private SessionKeys() {}

    /** 当前登录用户 ID */
    public static final String CURRENT_USER_ID = "current_user_id";

    /** 当前登录用户名 */
    public static final String CURRENT_USERNAME = "current_username";

    /** CSRF Token（由 CsrfTokenFilter 写入） */
    public static final String CSRF_TOKEN = "csrf_token";
}
