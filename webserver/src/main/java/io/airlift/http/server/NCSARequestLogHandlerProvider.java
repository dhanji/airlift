package io.airlift.http.server;

import org.eclipse.jetty.server.NCSARequestLog;
import org.eclipse.jetty.server.handler.RequestLogHandler;

import com.google.inject.Inject;
import com.google.inject.Provider;

public class NCSARequestLogHandlerProvider implements Provider<RequestLogHandler> {

  private final String logFile;

  @Inject
  public NCSARequestLogHandlerProvider() {
    this.logFile = "/tmp/jetty.log";
  }

  @Override
  public RequestLogHandler get() {
    RequestLogHandler requestLogHandler = new RequestLogHandler();
    NCSARequestLog requestLog = new NCSARequestLog(logFile);
    requestLog.setRetainDays(90);
    requestLog.setAppend(true);
    requestLog.setExtended(false);
    requestLog.setLogTimeZone("GMT");
    requestLogHandler.setRequestLog(requestLog);
    return requestLogHandler;
  }
}
