package com.spring.security.rbac.converter;

import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import com.spring.security.rbac.model.security.ApplicationUserDetails;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.WritingConverter;
import org.springframework.stereotype.Component;

@Component
@WritingConverter
public class AuthorityListToStringListConverter implements
    Converter<ApplicationUserDetails, DBObject> {


  @Override
  public DBObject convert(ApplicationUserDetails user) {
    DBObject dbObject = new BasicDBObject();
    dbObject.put("name", "shreyas");
    dbObject.put("password", "password");
    return dbObject;
  }
}
