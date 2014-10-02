package io.airlift.http.server.security;

import org.apache.shiro.authc.AuthenticationToken;

public class BearerAuthenticationToken implements AuthenticationToken {

  private static final long serialVersionUID = 4730887127400746879L;

  private final String token;

  public BearerAuthenticationToken(String token) {
    this.token = token;
  }

  public String getToken() {
    return token;
  }
  
  @Override
  public Object getPrincipal() {
    return null;
  }

  @Override
  public Object getCredentials() {
    return null;
  }
}
