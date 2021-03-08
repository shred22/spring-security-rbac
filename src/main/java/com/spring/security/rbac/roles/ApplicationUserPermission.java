package com.spring.security.rbac.roles;

public enum ApplicationUserPermission {
    USER_EDIT("user:read"),
    USER_DELETE("user:write"),
    USER_READ("user:read"),
    USER_WRITE("user:write");

    private final String permission;

    ApplicationUserPermission(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }
}
