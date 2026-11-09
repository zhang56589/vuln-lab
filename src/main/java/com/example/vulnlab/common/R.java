package com.example.vulnlab.common;

import java.io.Serializable;

/**
 * 统一响应包装类
 * <pre>
 * {
 *   "code": 0,        // 0=成功，非0=失败
 *   "msg":  "ok",
 *   "data": {...}
 * }
 * </pre>
 *
 * @param <T> 业务数据类型
 */
public class R<T> implements Serializable {

    private int code;
    private String msg;
    private T data;

    public R() {}

    public R(int code, String msg, T data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }

    // ---------- 工厂方法 ----------

    public static <T> R<T> ok() {
        return new R<>(0, "ok", null);
    }

    public static <T> R<T> ok(T data) {
        return new R<>(0, "ok", data);
    }

    public static <T> R<T> ok(String msg, T data) {
        return new R<>(0, msg, data);
    }

    public static <T> R<T> fail(String msg) {
        return new R<>(500, msg, null);
    }

    public static <T> R<T> fail(int code, String msg) {
        return new R<>(code, msg, null);
    }

    // ---------- getter / setter ----------

    public int getCode() { return code; }
    public void setCode(int code) { this.code = code; }
    public String getMsg() { return msg; }
    public void setMsg(String msg) { this.msg = msg; }
    public T getData() { return data; }
    public void setData(T data) { this.data = data; }

    @Override
    public String toString() {
        return "R{code=" + code + ", msg='" + msg + "', data=" + data + "}";
    }
}
