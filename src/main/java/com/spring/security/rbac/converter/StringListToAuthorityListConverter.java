package com.spring.security.rbac.converter;

import com.mongodb.DBObject;
import com.spring.security.rbac.model.security.ApplicationUserDetails;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static java.util.stream.Collectors.toCollection;

@Component
@ReadingConverter
public class StringListToAuthorityListConverter implements Converter<DBObject, ApplicationUserDetails> {


    @Override
    public ApplicationUserDetails convert(DBObject source) {
        ApplicationUserDetails userDetails = new ApplicationUserDetails();
        userDetails.setUsername((String)source.get("username"));
        userDetails.setEnabled(true);
        userDetails.setAccountNonExpired(true);
        userDetails.setCredentialsNonExpired(true);
        userDetails.setAccountNonLocked(true);
        userDetails.setPassword("password");
        return userDetails;
    }
}
