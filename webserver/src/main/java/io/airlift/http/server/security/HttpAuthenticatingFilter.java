package io.airlift.http.server.security;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Collections;
import java.util.Locale;

/**
 * Requires the requesting user to be {@link org.apache.shiro.subject.Subject#isAuthenticated() authenticated} for the
 * request to continue, and if they're not, requires the user to login via the HTTP Basic protocol-specific challenge.
 * Upon successful login, they're allowed to continue on to the requested resource/url.
 * <p/>
 * This implementation is a 'clean room' Java implementation of Basic HTTP Authentication specification per
 * <a href="ftp://ftp.isi.edu/in-notes/rfc2617.txt">RFC 2617</a>.
 * <p/>
 * Basic authentication functions as follows:
 * <ol>
 * <li>A request comes in for a resource that requires authentication.</li>
 * <li>The server replies with a 401 response status, sets the <code>WWW-Authenticate</code> header, and the contents of a
 * page informing the user that the incoming resource requires authentication.</li>
 * <li>Upon receiving this <code>WWW-Authenticate</code> challenge from the server, the client then takes a
 * username and a password and puts them in the following format:
 * <p><code>username:password</code></p></li>
 * <li>This token is then base 64 encoded.</li>
 * <li>The client then sends another request for the same resource with the following header:<br/>
 * <p><code>Authorization: Basic <em>Base64_encoded_username_and_password</em></code></p></li>
 * </ol>
 * The {@link #onAccessDenied(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method will
 * only be called if the subject making the request is not
 * {@link org.apache.shiro.subject.Subject#isAuthenticated() authenticated}
 *
 * @see <a href="ftp://ftp.isi.edu/in-notes/rfc2617.txt">RFC 2617</a>
 * @see <a href="http://en.wikipedia.org/wiki/Basic_access_authentication">Basic Access Authentication</a>
 * @since 0.9
 */
public class HttpAuthenticatingFilter extends AuthenticatingFilter {

  /**
   * This class's private logger.
   */
  private static final Logger log = LoggerFactory.getLogger(HttpAuthenticatingFilter.class);

  /**
   * HTTP Authorization header, equal to <code>Authorization</code>
   */
  protected static final String AUTHORIZATION_HEADER = "Authorization";

  /**
   * HTTP Authentication header, equal to <code>WWW-Authenticate</code>
   */
  protected static final String AUTHENTICATE_HEADER = "WWW-Authenticate";

  /**
   * The name that is displayed during the challenge process of authentication, defauls to <code>application</code>
   * and can be overridden by the {@link #setApplicationName(String) setApplicationName} method.
   */
  private String applicationName = "application";

  /**
   * The authcScheme to look for in the <code>Authorization</code> header, defaults to <code>BASIC</code>
   */
  //
  // This is required in order to set the challenge
  //
  private String authcScheme = HttpServletRequest.BASIC_AUTH;

  /**
   * The authzScheme value to look for in the <code>Authorization</code> header, defaults to <code>BASIC</code>
   */
  private String authzScheme = HttpServletRequest.BASIC_AUTH;

  //
  // API
  //

  /**
   * Creates an AuthenticationToken for use during login attempt with the provided credentials in the http header.
   * <p/>
   * This implementation:
   * <ol><li>acquires the username and password based on the request's
   * {@link #getAuthzHeader(javax.servlet.ServletRequest) authorization header} via the
   * {@link #getPrincipalsAndCredentials(String, javax.servlet.ServletRequest) getPrincipalsAndCredentials} method</li>
   * <li>The return value of that method is converted to an <code>AuthenticationToken</code> via the
   * {@link #createToken(String, String, javax.servlet.ServletRequest, javax.servlet.ServletResponse) createToken} method</li>
   * <li>The created <code>AuthenticationToken</code> is returned.</li>
   * </ol>
   *
   * @param request  incoming ServletRequest
   * @param response outgoing ServletResponse
   * @return the AuthenticationToken used to execute the login attempt
   */
  protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {

    String authorizationHeader = getAuthzHeader(request);
    if (authorizationHeader == null || authorizationHeader.length() == 0) {
      // Create an empty authentication token since there is no
      // Authorization header.
      return createToken("", "", request, response);
    }

    if (log.isDebugEnabled()) {
      log.debug("Attempting to execute login with headers [" + authorizationHeader + "]");
    }

    //String[] prinCred = getPrincipalsAndCredentials(authorizationHeader, request);

    String[] authTokens = authorizationHeader.split(" ");
    if (authTokens == null || authTokens.length < 2) {
      return createToken("", "", request, response);
    }

    String scheme = authTokens[0];
    String encoded = authTokens[1];

    //
    //Authorization: Bearer AbCdEf123456
    //Authorization: Basic AbCdEf123456
    //

    AuthenticationToken token;

    //
    // Depending on the scheme we do different things
    //
    //Authorization: Bearer AbCdEf123456
    //Authorization: Basic AbCdEf123456
    //
    // If we have a Bearer token then we need to do all sorts of other stuff
    //
    if (scheme.toLowerCase().equals("basic")) {
      //
      //Authorization: Basic AbCdEf123456
      //
      String[] prinCred = Base64.decodeToString(encoded).split(":", 2);

      if (prinCred == null || prinCred.length < 2) {
        // Create an authentication token with an empty password,
        // since one hasn't been provided in the request.
        String username = prinCred == null || prinCred.length == 0 ? "" : prinCred[0];
        token = createToken(username, "", request, response);
      }

      String username = prinCred[0];
      String password = prinCred[1];

      token = createToken(username, password, request, response);

    } else {
      //
      //Authorization: Bearer AbCdEf123456
      //      
      // xxx.yyy.zzz => [JWT Header].[JWT Claims Set].[JWT Signature]
      //
      token = new BearerAuthenticationToken(encoded);
    }

    return token;
  }

  protected AuthenticationToken createToken(String username, String password, ServletRequest request, ServletResponse response) {
    boolean rememberMe = isRememberMe(request);
    String host = getHost(request);
    return createToken(username, password, rememberMe, host);
  }

  protected AuthenticationToken createToken(String username, String password, boolean rememberMe, String host) {
    return new UsernamePasswordToken(username, password, rememberMe, host);
  }

  //

  @Override
  protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
    return onAccessDeniedWhenWebBrower(request, response);
  }  
  
  //
  // so we need to change this as because the login is not done through the filter but a specific command
  // we have the case where we wind up in endless redirect for this use case of bearer tokens
  //  
  protected boolean onAccessDeniedWhenWebBrower(ServletRequest request, ServletResponse response) throws Exception {    
    if (isLoginRequest(request, response)) {
      //
      // Is this a login path?
      // 
      if (isLoginSubmission(request, response)) {
        //
        // The method is a POST
        //
        if (log.isTraceEnabled()) {
          log.trace("Login submission detected.  Attempting to execute login.");
        }
        return executeLogin(request, response);
      } else {
        if (log.isTraceEnabled()) {
          log.trace("Login page view.");
        }
        //allow them to see the login page ;)
        return true;
      }
    } else {
      if (log.isTraceEnabled()) {
        log.trace("Attempting to access a path which requires authentication.  Forwarding to the " + "Authentication url [" + getLoginUrl() + "]");
      }
      saveRequestAndRedirectToLogin(request, response);
      return false;
    }
  }  
  
  /**
   * Processes unauthenticated requests. It handles the two-stage request/challenge authentication protocol.
   *
   * @param request  incoming ServletRequest
   * @param response outgoing ServletResponse
   * @return true if the request should be processed; false if the request should not continue to be processed
   */
  protected boolean onAccessDeniedForNonWebBrowser(ServletRequest request, ServletResponse response) throws Exception {
    boolean loggedIn = false; //false by default or we wouldn't be in this method
    if (isLoginAttempt(request, response)) {
      loggedIn = executeLogin(request, response);
    }
    if (!loggedIn) {      
      sendChallenge(request, response);
    }
    return loggedIn;
  }

  //
  // Implementation
  //

  /**
   * Returns the name to use in the ServletResponse's <b><code>WWW-Authenticate</code></b> header.
   * <p/>
   * Per RFC 2617, this name name is displayed to the end user when they are asked to authenticate.  Unless overridden
   * by the {@link #setApplicationName(String) setApplicationName(String)} method, the default value is 'application'.
   * <p/>
   * Please see {@link #setApplicationName(String) setApplicationName(String)} for an example of how this functions.
   *
   * @return the name to use in the ServletResponse's 'WWW-Authenticate' header.
   */
  public String getApplicationName() {
    return applicationName;
  }

  /**
   * Sets the name to use in the ServletResponse's <b><code>WWW-Authenticate</code></b> header.
   * <p/>
   * Per RFC 2617, this name name is displayed to the end user when they are asked to authenticate.  Unless overridden
   * by this method, the default value is &quot;application&quot;
   * <p/>
   * For example, setting this property to the value <b><code>Awesome Webapp</code></b> will result in the
   * following header:
   * <p/>
   * <code>WWW-Authenticate: Basic realm=&quot;<b>Awesome Webapp</b>&quot;</code>
   * <p/>
   * Side note: As you can see from the header text, the HTTP Basic specification calls
   * this the authentication 'realm', but we call this the 'applicationName' instead to avoid confusion with
   * Shiro's Realm constructs.
   *
   * @param applicationName the name to use in the ServletResponse's 'WWW-Authenticate' header.
   */
  public void setApplicationName(String applicationName) {
    this.applicationName = applicationName;
  }

  /**
   * Returns the HTTP <b><code>Authorization</code></b> header value that this filter will respond to as indicating
   * a login request.
   * <p/>
   * Unless overridden by the {@link #setAuthzScheme(String) setAuthzScheme(String)} method, the
   * default value is <code>BASIC</code>.
   *
   * @return the Http 'Authorization' header value that this filter will respond to as indicating a login request
   */
  public String getAuthzScheme() {
    return authzScheme;
  }

  /**
   * Sets the HTTP <b><code>Authorization</code></b> header value that this filter will respond to as indicating a
   * login request.
   * <p/>
   * Unless overridden by this method, the default value is <code>BASIC</code>
   *
   * @param authzScheme the HTTP <code>Authorization</code> header value that this filter will respond to as
   *                    indicating a login request.
   */
  public void setAuthzScheme(String authzScheme) {
    this.authzScheme = authzScheme;
  }

  /**
   * Returns the HTTP <b><code>WWW-Authenticate</code></b> header scheme that this filter will use when sending
   * the HTTP Basic challenge response.  The default value is <code>BASIC</code>.
   *
   * @return the HTTP <code>WWW-Authenticate</code> header scheme that this filter will use when sending the HTTP
   *         Basic challenge response.
   * @see #sendChallenge
   */
  public String getAuthcScheme() {
    return authcScheme;
  }

  /**
   * Sets the HTTP <b><code>WWW-Authenticate</code></b> header scheme that this filter will use when sending the
   * HTTP Basic challenge response.  The default value is <code>BASIC</code>.
   *
   * @param authcScheme the HTTP <code>WWW-Authenticate</code> header scheme that this filter will use when
   *                    sending the Http Basic challenge response.
   * @see #sendChallenge
   */
  public void setAuthcScheme(String authcScheme) {
    this.authcScheme = authcScheme;
  }

  /**
   * Determines whether the incoming request is an attempt to log in.
   * <p/>
   * The default implementation obtains the value of the request's
   * {@link #AUTHORIZATION_HEADER AUTHORIZATION_HEADER}, and if it is not <code>null</code>, delegates
   * to {@link #isLoginAttempt(String) isLoginAttempt(authzHeaderValue)}. If the header is <code>null</code>,
   * <code>false</code> is returned.
   *
   * @param request  incoming ServletRequest
   * @param response outgoing ServletResponse
   * @return true if the incoming request is an attempt to log in based, false otherwise
   */
  protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
    String authzHeader = getAuthzHeader(request);
    return authzHeader != null && isLoginAttempt(authzHeader);
  }

  /**
   * Returns the {@link #AUTHORIZATION_HEADER AUTHORIZATION_HEADER} from the specified ServletRequest.
   * <p/>
   * This implementation merely casts the request to an <code>HttpServletRequest</code> and returns the header:
   * <p/>
   * <code>HttpServletRequest httpRequest = {@link WebUtils#toHttp(javax.servlet.ServletRequest) toHttp(reaquest)};<br/>
   * return httpRequest.getHeader({@link #AUTHORIZATION_HEADER AUTHORIZATION_HEADER});</code>
   *
   * @param request the incoming <code>ServletRequest</code>
   * @return the <code>Authorization</code> header's value.
   */
  protected String getAuthzHeader(ServletRequest request) {
    HttpServletRequest httpRequest = WebUtils.toHttp(request);
    return httpRequest.getHeader(AUTHORIZATION_HEADER);
  }

  /**
   * Default implementation that returns <code>true</code> if the specified <code>authzHeader</code>
   * starts with the same (case-insensitive) characters specified by the
   * {@link #getAuthzScheme() authzScheme}, <code>false</code> otherwise.
   * <p/>
   * That is:
   * <p/>
   * <code>String authzScheme = getAuthzScheme().toLowerCase();<br/>
   * return authzHeader.toLowerCase().startsWith(authzScheme);</code>
   *
   * @param authzHeader the 'Authorization' header value (guaranteed to be non-null if the
   *                    {@link #isLoginAttempt(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method is not overriden).
   * @return <code>true</code> if the authzHeader value matches that configured as defined by
   *         the {@link #getAuthzScheme() authzScheme}.
   */
  protected boolean isLoginAttempt(String authzHeader) {
    //SHIRO-415: use English Locale:
    String authzScheme = getAuthzScheme().toLowerCase(Locale.ENGLISH);
    return authzHeader.toLowerCase(Locale.ENGLISH).startsWith(authzScheme);
  }

  /**
   * Builds the challenge for authorization by setting a HTTP <code>401</code> (Unauthorized) status as well as the
   * response's {@link #AUTHENTICATE_HEADER AUTHENTICATE_HEADER}.
   * <p/>
   * The header value constructed is equal to:
   * <p/>
   * <code>{@link #getAuthcScheme() getAuthcScheme()} + " realm=\"" + {@link #getApplicationName() getApplicationName()} + "\"";</code>
   *
   * @param request  incoming ServletRequest, ignored by this implementation
   * @param response outgoing ServletResponse
   * @return false - this sends the challenge to be sent back
   */
  protected boolean sendChallenge(ServletRequest request, ServletResponse response) {
    if (log.isDebugEnabled()) {
      log.debug("Authentication required: sending 401 Authentication challenge response.");
    }
    HttpServletResponse httpResponse = WebUtils.toHttp(response);
    httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    String authcHeader = getAuthcScheme() + " realm=\"" + getApplicationName() + "\"";
    httpResponse.setHeader(AUTHENTICATE_HEADER, authcHeader);
    return false;
  }

  /**
   * This default implementation merely returns <code>true</code> if the request is an HTTP <code>POST</code>,
   * <code>false</code> otherwise. Can be overridden by subclasses for custom login submission detection behavior.
   *
   * @param request  the incoming ServletRequest
   * @param response the outgoing ServletResponse.
   * @return <code>true</code> if the request is an HTTP <code>POST</code>, <code>false</code> otherwise.
   */
  protected boolean isLoginSubmission(ServletRequest request, ServletResponse response) {
    return (request instanceof HttpServletRequest) && WebUtils.toHttp(request).getMethod().equalsIgnoreCase(POST_METHOD);
  }

}