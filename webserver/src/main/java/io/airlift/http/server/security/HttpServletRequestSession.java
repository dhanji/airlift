package io.airlift.http.server.security;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;

import com.google.common.collect.Lists;

/** 
 * Session that is only tied to an HttpServletRequest. This can be used for applications that prefer to remain stateless. 
 */
public class HttpServletRequestSession implements Session {
  private HttpServletRequest request;
  private HttpServletResponse response;
  private String host;
  private UUID uuid;
  private Date start;

  public HttpServletRequestSession(HttpServletRequest request, HttpServletResponse response, String host) {
    this.request = request;
    this.response = response;
    this.host = host;
    this.uuid = UUID.randomUUID();
    this.start = new Date();
  }

  @Override
  public Serializable getId() {
    return uuid;
  }

  @Override
  public Date getStartTimestamp() {
    return start;
  }

  @Override
  public Date getLastAccessTime() {
    // the user only makes one request that involves this session 
    return start;
  }

  @Override
  public long getTimeout() throws InvalidSessionException {
    return -1;
  }

  @Override
  public void setTimeout(long maxIdleTimeInMillis) throws InvalidSessionException {
    // ignore this - the session ends with the request and that's that... 
  }

  @Override
  public String getHost() {
    return host;
  }

  @Override
  public void touch() throws InvalidSessionException {
    // do nothing - we don't timeout 
  }

  @Override
  public void stop() throws InvalidSessionException {
    // do nothing - i don't have a use case for this and the structure to support it, while not huge, adds significant complexity 
  }

  @SuppressWarnings({
    "unchecked"
  })
  @Override
  public Collection<Object> getAttributeKeys() throws InvalidSessionException {
    List<Object> attributes = Lists.newArrayList();
    attributes.addAll(Collections.list(request.getAttributeNames()));
    return attributes;
  }

  @Override
  public Object getAttribute(Object key) throws InvalidSessionException {
    return request.getAttribute(stringify(key));
  }

  @Override
  public void setAttribute(Object key, Object value) throws InvalidSessionException {
    request.setAttribute(stringify(key), value);
  }

  @Override
  public Object removeAttribute(Object objectKey) throws InvalidSessionException {
    String key = stringify(objectKey);
    Object formerValue = request.getAttribute(key);
    request.removeAttribute(key);
    return formerValue;
  }

  private String stringify(Object key) {
    return key == null ? null : key.toString();
  }
}
