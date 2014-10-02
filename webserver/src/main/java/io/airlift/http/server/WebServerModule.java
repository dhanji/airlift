package io.airlift.http.server;

import io.airlift.node.NodeInfo;
import io.airlift.tracetoken.TraceTokenManager;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.Filter;
import javax.servlet.Servlet;
import javax.servlet.ServletContextListener;
import javax.servlet.http.HttpServlet;

import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.RequestLogHandler;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.server.handler.StatisticsHandler;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;
import org.weakref.jmx.com.google.common.collect.Lists;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Sets;
import com.google.common.primitives.Ints;
import com.google.inject.AbstractModule;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Provider;

/**
 * structure is:
 *
 * server
 *    |--- statistics handler
 *           |--- context handler
 *           |       |--- trace token filter
 *           |       |--- gzip response filter
 *           |       |--- gzip request filter
 *           |       |--- security handler
 *           |       |--- user provided filters
 *           |       |--- the servlet (normally GuiceContainer)
 *           |       |--- resource handlers
 *           |--- log handler
 *    |-- admin context handler
 *           \ --- the admin servlet
 */
public class WebServerModule extends AbstractModule {

  private WebServerBuilder builder;

  protected WebServerBuilder server(int port) {
    return builder.setPort(port);
  }

  protected FilterBuilder filter(String pathSpec) {
    FilterBuilder filterBuilder = new FilterBuilder(pathSpec);
    builder.addFilterBuilder(filterBuilder);
    return filterBuilder;
  }

  protected ResourceBuilder serve(String resourcesLocation) {
    ResourceBuilder resourceBuilder = new ResourceBuilder(resourcesLocation);
    builder.addResourceBuilder(resourceBuilder);
    return resourceBuilder;
  }
  protected void listener(Class<? extends ServletContextListener> contextListenerClass) {
    builder.addContextListenerClass(contextListenerClass);
  }
  
  @Override
  protected void configure() {
    builder = new WebServerBuilder();
    configureWebServer();
    bind(WebServer.class).toProvider(new Provider<WebServer>() {

      @Inject
      Injector injector;
      
      @Inject 
      RequestLogHandler requestLogHandler;
      
      @Override
      public WebServer get() {
        List<FilterDefinition> filterDefinitions = Lists.newArrayList();
        for (FilterBuilder filterBuilder : builder.getFilterBuilders()) {
          Filter filter = injector.getInstance(filterBuilder.filterClass);
          filterDefinitions.add(new FilterDefinition(filterBuilder.getPathSpec(), filter));
        }

        List<ServletDefinition> servletDefinitions = Lists.newArrayList();
        for (ResourceBuilder resourceBuilder : builder.getResourceBuilders()) {
          if (resourceBuilder.getServletClass() != null) {
            HttpServlet servlet = injector.getInstance(resourceBuilder.getServletClass());
            servletDefinitions.add(new ServletDefinition(servlet, resourceBuilder.getInitParams(), resourceBuilder.getBaseUri()));
          }
        }
        
        List<ServletContextListener> contextListeners = Lists.newArrayList();
        for(Class<? extends ServletContextListener> contextListenerClass : builder.getContextListenerClasses()) {
          ServletContextListener contextListener = injector.getInstance(contextListenerClass);
          contextListeners.add(contextListener);
        }
        
        return new Jetty9WebServer(builder, contextListeners, filterDefinitions, servletDefinitions, requestLogHandler);
      }
    });
  }

  protected void configureWebServer() {
  }

  class Jetty9WebServer implements WebServer {

    private final Server server;
    private final ServerConnector httpConnector;
    private final ServerConnector httpsConnector;


    public Jetty9WebServer(WebServerBuilder builder, List<ServletContextListener> contextListeners, List<FilterDefinition> filterDefinitions, List<ServletDefinition> servletDefinitions, RequestLogHandler requestLogHandler) {

      // How to set these up correctly

      HttpServerConfig config = new HttpServerConfig();
      NodeInfo nodeInfo = new NodeInfo("test");
      HttpServerInfo httpServerInfo = new HttpServerInfo(config, nodeInfo);

      Preconditions.checkNotNull(httpServerInfo, "httpServerInfo is null");
      Preconditions.checkNotNull(nodeInfo, "nodeInfo is null");
      Preconditions.checkNotNull(config, "config is null");
      //Preconditions.checkNotNull(theServlet, "theServlet is null");

      QueuedThreadPool threadPool = new QueuedThreadPool(config.getMaxThreads());
      threadPool.setMinThreads(config.getMinThreads());
      threadPool.setIdleTimeout(Ints.checkedCast(config.getThreadMaxIdleTime().toMillis()));
      threadPool.setName("http-worker");
      server = new Server(threadPool);

      //      if (mbeanServer != null) {
      //        MBeanContainer mbeanContainer = new MBeanContainer(mbeanServer);
      //        server.addBean(mbeanContainer);
      //      }

      // set up HTTP connector
      if (config.isHttpEnabled()) {
        HttpConfiguration httpConfiguration = new HttpConfiguration();
        httpConfiguration.setSendServerVersion(false);
        httpConfiguration.setSendXPoweredBy(false);
        if (config.getMaxRequestHeaderSize() != null) {
          httpConfiguration.setRequestHeaderSize(Ints.checkedCast(config.getMaxRequestHeaderSize().toBytes()));
        }

        // if https is enabled, set the CONFIDENTIAL and INTEGRAL redirection information
        if (config.isHttpsEnabled()) {
          httpConfiguration.setSecureScheme("https");
          httpConfiguration.setSecurePort(httpServerInfo.getHttpsUri().getPort());
        }

        httpConnector = new ServerConnector(server, new HttpConnectionFactory(httpConfiguration));
        httpConnector.setName("http");
        httpConnector.setPort(httpServerInfo.getHttpUri().getPort());
        httpConnector.setIdleTimeout(config.getNetworkMaxIdleTime().toMillis());
        httpConnector.setHost(nodeInfo.getBindIp().getHostAddress());
        server.addConnector(httpConnector);
      } else {
        httpConnector = null;
      }

      // set up NIO-based HTTPS connector
      if (config.isHttpsEnabled()) {
        HttpConfiguration httpsConfiguration = new HttpConfiguration();
        httpsConfiguration.setSendServerVersion(false);
        httpsConfiguration.setSendXPoweredBy(false);
        if (config.getMaxRequestHeaderSize() != null) {
          httpsConfiguration.setRequestHeaderSize(Ints.checkedCast(config.getMaxRequestHeaderSize().toBytes()));
        }
        httpsConfiguration.addCustomizer(new SecureRequestCustomizer());

        SslContextFactory sslContextFactory = new SslContextFactory(config.getKeystorePath());
        sslContextFactory.setKeyStorePassword(config.getKeystorePassword());
        SslConnectionFactory sslConnectionFactory = new SslConnectionFactory(sslContextFactory, "http/1.1");

        httpsConnector = new ServerConnector(server, sslConnectionFactory, new HttpConnectionFactory(httpsConfiguration));
        httpsConnector.setName("https");
        httpsConnector.setPort(httpServerInfo.getHttpsUri().getPort());
        httpsConnector.setIdleTimeout(config.getNetworkMaxIdleTime().toMillis());
        httpsConnector.setHost(nodeInfo.getBindIp().getHostAddress());

        server.addConnector(httpsConnector);
      } else {
        httpsConnector = null;
      }

      /*
       * if (theAdminServlet != null && config.isAdminEnabled()) { HttpConfiguration adminConfiguration = new HttpConfiguration(); adminConfiguration.setSendServerVersion(false);
       * adminConfiguration.setSendXPoweredBy(false); if (config.getMaxRequestHeaderSize() != null) {
       * adminConfiguration.setRequestHeaderSize(Ints.checkedCast(config.getMaxRequestHeaderSize().toBytes())); }
       * 
       * QueuedThreadPool adminThreadPool = new QueuedThreadPool(config.getAdminMaxThreads()); adminThreadPool.setName("http-admin-worker"); adminThreadPool.setMinThreads(config.getAdminMinThreads());
       * adminThreadPool.setIdleTimeout(Ints.checkedCast(config.getThreadMaxIdleTime().toMillis()));
       * 
       * if (config.isHttpsEnabled()) { adminConfiguration.addCustomizer(new SecureRequestCustomizer());
       * 
       * SslContextFactory sslContextFactory = new SslContextFactory(config.getKeystorePath()); sslContextFactory.setKeyStorePassword(config.getKeystorePassword()); SslConnectionFactory
       * sslConnectionFactory = new SslConnectionFactory(sslContextFactory, "http/1.1"); adminConnector = new ServerConnector(server, adminThreadPool, null, null, 0, -1, sslConnectionFactory, new
       * HttpConnectionFactory(adminConfiguration)); } else { adminConnector = new ServerConnector(server, adminThreadPool, null, null, 0, -1, new HttpConnectionFactory(adminConfiguration)); }
       * 
       * adminConnector.setName("admin"); adminConnector.setPort(httpServerInfo.getAdminUri().getPort()); adminConnector.setIdleTimeout(config.getNetworkMaxIdleTime().toMillis());
       * adminConnector.setHost(nodeInfo.getBindIp().getHostAddress());
       * 
       * server.addConnector(adminConnector); } else { adminConnector = null; }
       */

      /**
       * structure is:
       *
       * server
       *    |--- statistics handler
       *           |--- context handler
       *           |       |--- trace token filter
       *           |       |--- gzip response filter
       *           |       |--- gzip request filter
       *           |       |--- security handler
       *           |       |--- user provided filters
       *           |       |--- the servlet (normally GuiceContainer)
       *           |       |--- resource handlers
       *           |--- log handler
       *    |-- admin context handler
       *           \ --- the admin servlet
       */
      
      HandlerCollection handlers = new HandlerCollection();

      //
      // Static resources: these need to be first or they don't appear to be found
      //
      for (ResourceBuilder resourceBuilder : builder.getResourceBuilders()) {
        if (resourceBuilder.getClassPathResourceBase() != null) {
          ResourceHandler handler = new ResourceHandler();
          handler.setResourceBase(resourceBuilder.getClassPathResourceBase());
          handlers.addHandler(handler);
          //handlers.addHandler(new ClassPathResourceHandler(resourceBuilder.getBaseUri(), resourceBuilder.getClassPathResourceBase(), resourceBuilder.getWelcomeFiles()));
        }
      }

      ServletContextHandler context = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
      //context.getInitParams().put("org.eclipse.jetty.servlet.SessionIdPathParameterName", "none");
      
      // ServletContextListeners
      for(ServletContextListener contextListener : contextListeners) {
        context.addEventListener(contextListener);
      }
      
      // Filters
      for (FilterDefinition filterDefinition : filterDefinitions) {
        System.out.println(filterDefinition.getFilter() + " --> " + filterDefinition.getPathSpec());
        context.addFilter(new FilterHolder(filterDefinition.getFilter()), filterDefinition.getPathSpec(), null);
      }

      // Servlets
      for (ServletDefinition sd : servletDefinitions) {
        createServletContext(context, sd.getServlet(), sd.getPathSpec(), sd.getInitParams(), Sets.<Filter> newHashSet(), null, null, "http", "https");
      }

      handlers.addHandler(context);

      // RequestLogHandler
      handlers.addHandler(requestLogHandler);

      RequestLogHandler statsRecorder = new RequestLogHandler();
      statsRecorder.setRequestLog(new StatsRecordingHandler(new RequestStats()));
      handlers.addHandler(statsRecorder);

      // add handlers to Jetty
      StatisticsHandler statsHandler = new StatisticsHandler();
      statsHandler.setHandler(handlers);

      HandlerList rootHandlers = new HandlerList();

      rootHandlers.addHandler(statsHandler);
      server.setHandler(rootHandlers);

    }

    // We either create a context handler with a bunch of pathspecs and just create one
    protected void createServletContext(ServletContextHandler context, Servlet servlet, String pathSpec, Map<String, String> parameters, Set<Filter> filters, TraceTokenManager tokenManager,
        LoginService loginService, String... connectorNames) {
      
      ServletHolder servletHolder = new ServletHolder(servlet);
      servletHolder.setInitParameters(ImmutableMap.copyOf(parameters));
      context.addServlet(servletHolder, pathSpec);

      // Starting with Jetty 9 there is no way to specify connectors directly, but
      // there is this wonky @ConnectorName virtual hosts automatically added
      //String[] virtualHosts = new String[connectorNames.length];
      //for (int i = 0; i < connectorNames.length; i++) {
      //  virtualHosts[i] = "@" + connectorNames[i];
      //}
      //context.setVirtualHosts(virtualHosts);
      //return context;
    }

    @Override
    public void start() throws Exception {
      server.start();
      //server.join();
    }

    @Override
    public void join() throws Exception {
      server.join();
    }

    @Override
    public void stop() throws Exception {
      server.stop();
    }
  }

  //
  // Builders
  //

  public static class WebServerBuilder {

    private int port;
    private List<ResourceBuilder> resourceBuilders = Lists.newArrayList();
    private List<FilterBuilder> filterBuilders = Lists.newArrayList();
    private List<Class<? extends ServletContextListener>> contextListenerClasses = Lists.newArrayList(); 

    public WebServerBuilder setPort(int port) {
      this.port = port;
      return this;
    }

    public void addContextListenerClass(Class<? extends ServletContextListener> contextListenerClass) {
      contextListenerClasses.add(contextListenerClass);
    }

    public List<Class<? extends ServletContextListener>> getContextListenerClasses() {
      return contextListenerClasses;
    }
    
    public int getPort() {
      return port;
    }

    public void addFilterBuilder(FilterBuilder filterBuilder) {
      filterBuilders.add(filterBuilder);
    }

    public List<FilterBuilder> getFilterBuilders() {
      return filterBuilders;
    }

    public void addResourceBuilder(ResourceBuilder resourceBuilder) {
      resourceBuilders.add(resourceBuilder);
    }

    public List<ResourceBuilder> getResourceBuilders() {
      return resourceBuilders;
    }
  }

  //
  // Filters
  //
  public static class FilterBuilder {

    String pathSpec;
    Class<? extends Filter> filterClass;

    public FilterBuilder(String pathSpec) {
      this.pathSpec = pathSpec;
    }

    public FilterBuilder through(Class<? extends Filter> filterClass) {
      this.filterClass = filterClass;
      return this;
    }

    public String getPathSpec() {
      return pathSpec;
    }

    public Class<? extends Filter> getFilterClass() {
      return filterClass;
    }
  }

  public static class FilterDefinition {
    String pathSpec;
    Filter filter;

    public FilterDefinition(String pathSpec, Filter filter) {
      this.pathSpec = pathSpec;
      this.filter = filter;
    }

    public String getPathSpec() {
      return pathSpec;
    }

    public Filter getFilter() {
      return filter;
    }
  }

  public static class ServletDefinition {
    HttpServlet servlet;
    Map<String, String> initParams;
    String pathSpec;

    public ServletDefinition(HttpServlet servlet, Map<String, String> initParams, String pathSpec) {
      this.servlet = servlet;
      this.initParams = initParams;
      this.pathSpec = pathSpec;
    }

    public HttpServlet getServlet() {
      return servlet;
    }

    public Map<String, String> getInitParams() {
      if (initParams == null) {
        return Collections.emptyMap();
      }
      return initParams;
    }

    public String getPathSpec() {
      return pathSpec;
    }
  }

  //
  // Resources
  //
  public static class ResourceBuilder {
    //
    // Resource
    //
    private String baseUri;
    private String classPathResourceBase;
    private List<String> welcomeFiles = Lists.newArrayList();
    //
    // Servlet
    //
    private Class<? extends HttpServlet> servletClass;
    private Map<String, String> initParams;

    public ResourceBuilder(String baseUri) {
      this.baseUri = baseUri;
    }

    public String getBaseUri() {
      return baseUri;
    }

    public void setBaseUri(String baseUri) {
      this.baseUri = baseUri;
    }

    public ResourceBuilder from(String classPathResourceBase) {
      this.classPathResourceBase = classPathResourceBase;
      return this;
    }

    public String getClassPathResourceBase() {
      return classPathResourceBase;
    }

    public ResourceBuilder withWelcomeFile(String welcomeFile) {
      welcomeFiles.add(welcomeFile);
      return this;
    }

    public List<String> getWelcomeFiles() {
      return welcomeFiles;
    }

    //
    // Servlet
    //
    public ResourceBuilder with(Class<? extends HttpServlet> servlet) {
      this.servletClass = servlet;
      return this;
    }

    public Class<? extends HttpServlet> getServletClass() {
      return servletClass;
    }

    public Map<String, String> getInitParams() {
      return initParams;
    }

    public void with(Class<? extends HttpServlet> servletClass, Map<String, String> initParams) {
      this.servletClass = servletClass;
      this.initParams = initParams;
    }
  }
}
