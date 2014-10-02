package io.airlift.http.server;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;

import com.google.inject.Singleton;

@Singleton
@Path("/one")
public class ResourceOne {

  @GET
  public Response userAgent() {
    return Response.status(200).entity("one").build();
  }
}
