package com.spring.security.rbac.config;

import static com.spring.security.rbac.roles.ApplicationUserPermission.USER_DELETE;
import static com.spring.security.rbac.roles.ApplicationUserPermission.USER_READ;
import static com.spring.security.rbac.roles.ApplicationUserPermission.USER_WRITE;
import static com.spring.security.rbac.roles.ApplicationUserRole.MERCHANT_ADMIN;

import com.spring.security.rbac.jwt.JwtConfig;
import com.spring.security.rbac.jwt.JwtTokenVerifier;
import com.spring.security.rbac.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import com.spring.security.rbac.repository.ApplicationUserDetailsRepository;
import com.spring.security.rbac.service.ApplicationUserDetailsService;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  private final PasswordEncoder passwordEncoder;
  private final ApplicationUserDetailsService userDetailsService;
  private final SecretKey secretKey;
  private final JwtConfig jwtConfig;

  @Autowired
  public WebSecurityConfig(PasswordEncoder passwordEncoder,
      ApplicationUserDetailsService applicationUserService,
      SecretKey secretKey,
      JwtConfig jwtConfig) {
    this.passwordEncoder = passwordEncoder;
    this.userDetailsService = applicationUserService;
    this.secretKey = secretKey;
    this.jwtConfig = jwtConfig;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {

    http.csrf().disable()
        .sessionManagement().sessionCreationPolicy(
        SessionCreationPolicy.STATELESS)
        .and()
        .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
        .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig),JwtUsernameAndPasswordAuthenticationFilter.class)
        .authorizeRequests()
        .antMatchers("/permitted")
        .permitAll()
        .antMatchers(HttpMethod.GET, "/secured").hasRole(MERCHANT_ADMIN.name())
        .antMatchers(HttpMethod.GET, "/secured")
        .hasAnyAuthority(USER_WRITE.getPermission(), USER_READ.getPermission(),
            USER_DELETE.getPermission())
        .anyRequest()
        .authenticated();
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService)
        .passwordEncoder(passwordEncoder);
  }


}
