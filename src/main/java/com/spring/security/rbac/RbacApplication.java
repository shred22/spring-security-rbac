package com.spring.security.rbac;

import com.spring.security.rbac.model.security.ApplicationUserDetails;
import com.spring.security.rbac.repository.ApplicationUserDetailsRepository;
import java.util.Arrays;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableConfigurationProperties
public class RbacApplication {

  public static void main(String[] args) {
    ConfigurableApplicationContext context = SpringApplication.run(RbacApplication.class, args);

   /* ApplicationUserDetailsRepository repository = context
        .getBean(ApplicationUserDetailsRepository.class);

    PasswordEncoder passwordEncoder = context.getBean(PasswordEncoder
        .class);

    ApplicationUserDetails user = new ApplicationUserDetails();
    user.setUsername("akank");
    user.setPassword(passwordEncoder.encode("password"));
    user.setAccountNonExpired(true);
    user.setAuthorities(Arrays.asList(new SimpleGrantedAuthority("ROLE_MERCHANT_ADMIN"),
        new SimpleGrantedAuthority("user:read"),
        new SimpleGrantedAuthority("user:write")));
    user.setAccountNonLocked(true);
    user.setCredentialsNonExpired(true);
    user.setEnabled(true);

    repository.save(user);

    System.out.println(
        "**********************************Persisted User ************************************");*/

  }
}
