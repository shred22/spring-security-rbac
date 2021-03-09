package com.spring.security.rbac.service;

import com.spring.security.rbac.repository.ApplicationUserDetailsRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class ApplicationUserDetailsService implements UserDetailsService {

  private final ApplicationUserDetailsRepository repository;
  private final PasswordEncoder encoder;

  public ApplicationUserDetailsService(ApplicationUserDetailsRepository repository,
      PasswordEncoder encoder) {
    this.repository = repository;
    this.encoder = encoder;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return repository.findByUsername(username);
  }
}
