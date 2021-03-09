package com.spring.security.rbac.converter;

import com.mongodb.DBObject;
import com.spring.security.rbac.model.security.ApplicationUserDetails;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.stereotype.Component;

@Component
@ReadingConverter
public class StringListToAuthorityListConverter implements
    Converter<DBObject, ApplicationUserDetails> {


  @Override
  public ApplicationUserDetails convert(DBObject source) {
    ApplicationUserDetails userDetails = new ApplicationUserDetails();
    userDetails.setUsername((String) source.get("username"));
    userDetails.setEnabled(true);
    userDetails.setAccountNonExpired(true);
    userDetails.setCredentialsNonExpired(true);
    userDetails.setAccountNonLocked(true);
    userDetails.setPassword("password");
    return userDetails;
  }
}
