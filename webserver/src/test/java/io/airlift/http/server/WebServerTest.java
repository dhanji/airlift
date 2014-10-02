package io.airlift.http.server;

import io.airlift.http.server.WebServer;
import io.airlift.http.server.WebServerModule;

import java.util.HashMap;

import org.apache.shiro.web.env.EnvironmentLoaderListener;
import org.apache.shiro.web.servlet.ShiroFilter;
import org.eclipse.jetty.server.handler.RequestLogHandler;
import org.eclipse.jetty.servlets.GzipFilter;
import org.junit.Test;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.sun.jersey.guice.spi.container.servlet.GuiceContainer;

// thread pool configuration
// keystore for SSL
// mbean

public class WebServerTest {

  @Test
  public void server() throws Exception {

    Injector injector = Guice.createInjector(new WebServerModule() {
      @Override
      protected void configureWebServer() {        
                        
        server(8080);

        // Shiro
        // shiroEnvironmentClass
        // context parameters
        listener(EnvironmentLoaderListener.class);
        filter("/*").through(ShiroFilter.class);        
        
        // Filters
        //filter("/*").through(TimingFilter.class);
        //filter("/*").through(TraceTokenFilter.class);
        //filter("/*").through(GzipFilter.class);
        
        // Servlets
        serve("/one/*").with(ServletOne.class);
        serve("/two/*").with(ServletTwo.class, new HashMap<String, String>());
        
        // JAXRS resources
        serve("/api/*").with(GuiceContainer.class);
        bind(ResourceOne.class);
        bind(ResourceTwo.class);
        
        // Static content
        serve("/files").from("webapp").withWelcomeFile("index.html");
        
        // request log handling, this will likely be highly customized depending on logging/monitoring requirements
        // can likely make reasonable default bindings for standard log formats.
        bind(RequestLogHandler.class).toProvider(NCSARequestLogHandlerProvider.class);
      }
    });

    WebServer server = injector.getInstance(WebServer.class);
    server.start();
    server.join();
    //server.stop();
  }
}
