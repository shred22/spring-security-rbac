package com.spring.security.rbac.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.base.Strings;
import com.spring.security.rbac.jwt.util.PemUtils;
import java.io.File;
import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
      RSAPrivateKey privateKey = PemUtils.readPrivateKeyFromFile(new File("private_key.pem"), "RSA");
      RSAPublicKey publicKey = PemUtils.readPublicKeyFromFile(new File("jwt_public.pem"), "RSA");
      Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
      JWTVerifier verifier = JWT.require(algorithm)
          .withIssuer(jwtConfig.getIssuer())
          .build(); //Reusable verifier instance
      jwt = verifier.verify(token);

    } catch (JWTVerificationException exception) {

      throw new RuntimeException(exception);
    }

    Authentication authentication = new UsernamePasswordAuthenticationToken(
        jwt.getSubject(),
        jwt,
        Arrays.asList(new SimpleGrantedAuthority("ROLE_MERCHANT_ADMIN"), new SimpleGrantedAuthority("user:write"), new SimpleGrantedAuthority("user:read")));

    SecurityContextHolder.getContext().setAuthentication(authentication);

    filterChain.doFilter(request, response);
  }
}
