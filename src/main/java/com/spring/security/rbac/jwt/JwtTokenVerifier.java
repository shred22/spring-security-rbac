package com.spring.security.rbac.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.base.Strings;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtTokenVerifier extends OncePerRequestFilter {

  private final SecretKey secretKey;
  private final JwtConfig jwtConfig;

  public JwtTokenVerifier(SecretKey secretKey,
      JwtConfig jwtConfig) {
    this.secretKey = secretKey;
    this.jwtConfig = jwtConfig;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());

    if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader
        .startsWith(jwtConfig.getTokenPrefix())) {
      filterChain.doFilter(request, response);
      return;
    }

    String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "").trim();
    DecodedJWT jwt = null;
    Set<SimpleGrantedAuthority> simpleGrantedAuthorities = new HashSet<>();
    try {

      Algorithm algorithm = Algorithm.HMAC256("secret");
      JWTVerifier verifier = JWT.require(algorithm)
          .withIssuer("auth0")
          .build(); //Reusable verifier instance
      jwt = verifier.verify(token);
      /*List<Map<String, String>> authorities = (List<Map<String, String>>)
          jwt.getClaim("authorities");*/
    } catch (JWTVerificationException exception) {
      //Invalid signature/claims
    }
          /*  Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);

            Claims body = claimsJws.getBody();

            String username = body.getSubject();

            var authorities = (List<Map<String, String>>) body.get("authorities");

            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());*/

    Authentication authentication = new UsernamePasswordAuthenticationToken(
        jwt.getSubject(),
        null,
        Arrays.asList(new SimpleGrantedAuthority("ROLE_MERCHANT_ADMIN")));

    SecurityContextHolder.getContext().setAuthentication(authentication);

    filterChain.doFilter(request, response);
  }
}
