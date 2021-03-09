package com.spring.security.rbac.model.security;

import java.util.Collection;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Document(collection = "Users")
@NoArgsConstructor
@AllArgsConstructor
public class ApplicationUserDetails implements UserDetails {

  @Field("username")
  private String username;
  private String password;
  private Collection<SimpleGrantedAuthority> authorities;
  private boolean isAccountNonExpired;
  private boolean isAccountNonLocked;
  private boolean isCredentialsNonExpired;
  private boolean isEnabled;

  @Override
  public Collection<SimpleGrantedAuthority> getAuthorities() {
    return authorities;
  }

  public void setAuthorities(Collection<SimpleGrantedAuthority> authorities) {
    this.authorities = authorities;
  }

  @Override
  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  @Override
  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  @Override
  public boolean isAccountNonExpired() {
    return isAccountNonExpired;
  }

  public void setAccountNonExpired(boolean accountNonExpired) {
    isAccountNonExpired = accountNonExpired;
  }

  @Override
  public boolean isAccountNonLocked() {
    return isAccountNonLocked;
  }

  public void setAccountNonLocked(boolean accountNonLocked) {
    isAccountNonLocked = accountNonLocked;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return isCredentialsNonExpired;
  }

  public void setCredentialsNonExpired(boolean credentialsNonExpired) {
    isCredentialsNonExpired = credentialsNonExpired;
  }

  @Override
  public boolean isEnabled() {
    return isEnabled;
  }

  public void setEnabled(boolean enabled) {
    isEnabled = enabled;
  }
}
