package io.airlift.http.server.security;

import java.security.InvalidKeyException;
import java.security.SignatureException;

import net.oauth.jsontoken.JsonToken;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.realm.AuthenticatingRealm;

public class BearerTokenRealm extends AuthenticatingRealm {

  private Jwt jwt;

  public BearerTokenRealm() {
    this.jwt = new Jwt();
    setAuthenticationTokenClass(BearerAuthenticationToken.class);
  }

  @Override
  public AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

    BearerAuthenticationToken bearerToken = (BearerAuthenticationToken) token;
    //
    //Authorization: Bearer xxx.yyy.zzz
    //      
    // xxx.yyy.zzz => [base64 encoded JWT Header].[base64 encoded JWT Claims Set].[base64 encoded JWT Signature]
    //
    try {
      JsonToken jsonWebToken = jwt.deserializeAndVerify(bearerToken.getToken());
      User user = jwt.entity(jsonWebToken, "user", User.class);
      //
      // We have a valid bearer token so consider this being authenticated
      //
      return new SimpleAuthenticationInfo(user.getUsername(), jsonWebToken.getTokenString(), "BearerRealm");
    } catch (InvalidKeyException | SignatureException e) {
      //
      // Invalid encoding, wrong length, uninitialized, etc or something is wrong with the signature
      //
      throw new AuthenticationException(e);
    }
  }
}