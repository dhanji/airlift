package io.airlift.http.server;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

import com.google.inject.Singleton;

@Singleton
@Path("/two")
public class ResourceTwo {

  @GET
  public Response userAgent() {
    return Response.status(200).entity("two").build();
  }
}
