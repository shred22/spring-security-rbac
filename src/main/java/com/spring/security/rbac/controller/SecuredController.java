package com.spring.security.rbac.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring.security.rbac.model.SecuredResponse;
import com.spring.security.rbac.model.security.ApplicationUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;

@RestController
public class SecuredController {

    @Autowired
    private PasswordEncoder encoder;


    @GetMapping("/secured")
    public ResponseEntity<SecuredResponse> securedResource() throws JsonProcessingException {
        ApplicationUserDetails userDetails = new ApplicationUserDetails();
        userDetails.setUsername("shred");
        userDetails.setPassword(encoder.encode("password"));
        userDetails.setAccountNonExpired(true);
        userDetails.setAccountNonLocked(true);
        userDetails.setCredentialsNonExpired(true);
        userDetails.setEnabled(true);
        userDetails.setAuthorities(unmodifiableList(asList(new SimpleGrantedAuthority("ROLE_MERCHANTADMIN"))));

        System.out.println(new ObjectMapper().writeValueAsString(userDetails));
        return ResponseEntity.ok(SecuredResponse.builder()
                .message("Secured Response").build());
    }
}
