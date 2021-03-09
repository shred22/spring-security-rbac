package com.spring.security.rbac.repository;

import com.spring.security.rbac.model.security.ApplicationUserDetails;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ApplicationUserDetailsRepository extends
    MongoRepository<ApplicationUserDetails, String> {

  ApplicationUserDetails findByUsername(String username);
}
