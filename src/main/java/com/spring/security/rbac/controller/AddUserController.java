package com.spring.security.rbac.controller;


import com.spring.security.rbac.model.security.ApplicationUserDetails;
import com.spring.security.rbac.repository.ApplicationUserDetailsRepository;
import com.spring.security.rbac.roles.ApplicationUserRole;
import java.util.Collections;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class AddUserController {

  private final ApplicationUserDetailsRepository repository;
  private final PasswordEncoder passwordEncoder;

  public AddUserController(
      ApplicationUserDetailsRepository repository,
      PasswordEncoder passwordEncoder) {
    this.repository = repository;
    this.passwordEncoder = passwordEncoder;
  }

  @GetMapping("/adduser")
  public ResponseEntity<ApplicationUserDetails> addUser(@RequestParam("name") String username) {

    ApplicationUserDetails user = new ApplicationUserDetails();
    user.setEnabled(true);
    user.setUsername(username);
    user.setPassword(passwordEncoder.encode("password"));
    user.setCredentialsNonExpired(true);
    user.setAccountNonLocked(true);
    user.setAccountNonExpired(true);
    user.setAuthorities(Collections
        .unmodifiableCollection(ApplicationUserRole.MERCHANT_ADMIN.getGrantedAuthorities()));
    repository.save(user);


    log.info("SAVED USER IN MONGO DB  WITH USERNAME {}", username);
    return ResponseEntity.ok(user);
  }
}
