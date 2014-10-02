package io.airlift.http.server;

public interface WebServer {

  public void start() throws Exception;

  public void join() throws Exception;

  public void stop() throws Exception;

}
