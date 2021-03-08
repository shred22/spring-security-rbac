package com.spring.security.rbac.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import static com.spring.security.rbac.roles.ApplicationUserPermission.USER_READ;
import static com.spring.security.rbac.roles.ApplicationUserPermission.USER_WRITE;
import static com.spring.security.rbac.roles.ApplicationUserRole.MERCHANT_ADMIN;

@Slf4j
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public WebSecurityConfig(UserDetailsService userDetailsService, PasswordEncoder encoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = encoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {



        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/permitted")
                .permitAll()
                .antMatchers(HttpMethod.GET,"/secured").hasRole(MERCHANT_ADMIN.name())
                //.antMatchers(HttpMethod.GET,"/secured").hasAnyAuthority(USER_WRITE.getPermission(), USER_READ.getPermission())
                .anyRequest()
                .authenticated()
        .and()
        .formLogin();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
    }



}
