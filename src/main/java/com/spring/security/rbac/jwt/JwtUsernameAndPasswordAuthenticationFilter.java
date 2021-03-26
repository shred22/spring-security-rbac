package com.spring.security.rbac.jwt;

import static java.time.temporal.ChronoUnit.DAYS;
import static java.util.Date.from;
import static java.util.stream.Collectors.toList;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring.security.rbac.jwt.util.PemUtils;
import com.spring.security.rbac.model.security.ApplicationUserDetails;
import com.spring.security.rbac.model.security.UsernameAndPasswordAuthenticationRequest;
import java.io.File;
import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.Date;
import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JwtUsernameAndPasswordAuthenticationFilter extends
    UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;
  private final JwtConfig jwtConfig;
  private final SecretKey secretKey;

  public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager,
      JwtConfig jwtConfig,
      SecretKey secretKey) {
    this.authenticationManager = authenticationManager;
    this.jwtConfig = jwtConfig;
    this.secretKey = secretKey;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {
    try {
      UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
          .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

      Authentication authentication = new UsernamePasswordAuthenticationToken(
          authenticationRequest.getUsername(),
          authenticationRequest.getPassword()
      );
      authentication.getAuthorities();
      return authenticationManager.authenticate(authentication);

    } catch (IOException e) {
      throw new RuntimeException(e);
    }

  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request,
      HttpServletResponse response, FilterChain chain, Authentication authResult)
      throws IOException, ServletException {
    RSAPrivateKey privateKey = PemUtils.readPrivateKeyFromFile(new File("private_key.pem"), "RSA");
    RSAPublicKey publicKey = PemUtils.readPublicKeyFromFile(new File("jwt_public.pem"), "RSA");

    Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);
      String token = JWT.create()
          .withIssuer(jwtConfig.getIssuer())
          .withExpiresAt(from(LocalDateTime.now().plus(7, DAYS).toInstant(ZoneOffset.UTC)))
          .withIssuedAt(new Date())
          .withSubject(((ApplicationUserDetails)authResult.getPrincipal()).getUsername())
          .withAudience(((ApplicationUserDetails)authResult.getPrincipal()).getUsername())
          .withClaim("authorities",
              authResult.getAuthorities().stream()
                  .map(GrantedAuthority::getAuthority).collect(toList()))
          .sign(algorithm);

      response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + " " + token);
  }
}
