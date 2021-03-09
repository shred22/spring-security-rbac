package com.spring.security.rbac.roles;

import static com.spring.security.rbac.roles.ApplicationUserPermission.USER_DELETE;
import static com.spring.security.rbac.roles.ApplicationUserPermission.USER_EDIT;
import static com.spring.security.rbac.roles.ApplicationUserPermission.USER_READ;
import static com.spring.security.rbac.roles.ApplicationUserPermission.USER_WRITE;

import com.google.common.collect.Sets;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.core.authority.SimpleGrantedAuthority;


public enum ApplicationUserRole {
  MERCHANT_ADMIN(Sets.newHashSet(USER_READ, USER_WRITE, USER_EDIT, USER_DELETE)),
  WP_ADMIN(Sets.newHashSet(USER_READ, USER_EDIT));

  private final Set<ApplicationUserPermission> permissions;

  ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
    this.permissions = permissions;
  }

  public Set<ApplicationUserPermission> getPermissions() {
    return permissions;
  }

  public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
    Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
        .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
        .collect(Collectors.toSet());
    permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
    return permissions;
  }
}
