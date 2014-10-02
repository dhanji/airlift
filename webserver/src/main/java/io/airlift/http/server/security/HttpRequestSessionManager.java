package io.airlift.http.server.security;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.web.session.mgt.WebSessionManager;
import org.apache.shiro.web.util.WebUtils;

/** 
 * Intended to keep session request-scoped and therefore not persist  them across multiple requests - a user must login 
 * on each request. This necessarily means that a mechanism like  form-based authentication isn't viable, but the 
 * intention is primarily for uses in stateless apis. 
 */
public class HttpRequestSessionManager implements WebSessionManager {

  static final String REQUEST_ATTRIBUTE_KEY = "__SHIRO_REQUEST_SESSION";

  @Override
  public Session start(SessionContext context) throws AuthorizationException {
    if (!WebUtils.isHttp(context)) {
      String msg = "SessionContext must be an HTTP compatible implementation.";
      throw new IllegalArgumentException(msg);
    }
    HttpServletRequest request = WebUtils.getHttpRequest(context);
    HttpServletResponse response = WebUtils.getHttpResponse(context);
    String host = getHost(context);
    Session session = createSession(request, response, host);
    request.setAttribute(REQUEST_ATTRIBUTE_KEY, session);
    return session;
  }

  @Override
  public Session getSession(SessionKey key) throws SessionException {
    if (!WebUtils.isHttp(key)) {
      String msg = "SessionKey must be an HTTP compatible implementation.";
      throw new IllegalArgumentException(msg);
    }
    HttpServletRequest request = WebUtils.getHttpRequest(key);
    return (Session) request.getAttribute(REQUEST_ATTRIBUTE_KEY);
  }

  private String getHost(SessionContext context) {
    String host = context.getHost();
    if (host == null) {
      ServletRequest request = WebUtils.getRequest(context);
      if (request != null) {
        host = request.getRemoteHost();
      }
    }
    return host;
  }

  @Override
  public boolean isServletContainerSessions() {
    //
    // If this is not set to true then Shiro rewrites the URLs with JSESSIONID
    //
    return true;
  }

  private Session createSession(HttpServletRequest request, HttpServletResponse response, String host) {
    HttpServletRequestSession session = new HttpServletRequestSession(request, response, host);
    return session;
  }
}