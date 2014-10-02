package io.airlift.http.server.security;

import io.airlift.http.server.PasswordHash;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.List;
import java.util.regex.Pattern;

import net.oauth.jsontoken.Checker;
import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.JsonTokenParser;
import net.oauth.jsontoken.SystemClock;
import net.oauth.jsontoken.crypto.HmacSHA256Signer;
import net.oauth.jsontoken.crypto.HmacSHA256Verifier;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.crypto.Verifier;
import net.oauth.jsontoken.discovery.VerifierProvider;
import net.oauth.jsontoken.discovery.VerifierProviders;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import com.google.common.collect.Lists;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class Jwt {

  private static final String ISSUER = "Takari";
  private String SIGNING_KEY = "alk;akljds;lfakjd;lfkja";
  private static Gson gson = new Gson();

  public String createSerializedAndSignedJsonWebToken() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, InvalidKeySpecException {
    return createToken().serializeAndSign();
  }

  //
  // serializedAndSignedJsonWebToken = 
  // => [base64 encoded JWT Header].[base64 encoded JWT Claims Set].[base64 encoded JWT Signature]
  // ==> xxx.yyy.zzz 
  // ==> eyJhbGciOiJIUzI1NiIsImtpZCI6InVzZXJpZCJ9.eyJpc3MiOiJUYWthcmkiLCJhdWQ4OGVjNzBmMWI4In19.IimZANztiE58L9iairoV4
  //
  public JsonToken deserializeAndVerify(String serializedAndSignedJsonWebToken) throws InvalidKeyException, SignatureException {
    final Verifier hmacVerifier = new HmacSHA256Verifier(SIGNING_KEY.getBytes());
    VerifierProviders providers = new VerifierProviders();
    VerifierProvider hmacLocator = new VerifierProvider() {
      @Override
      public List<Verifier> findVerifier(String signerId, String keyId) {
        return Lists.newArrayList(hmacVerifier);
      }
    };
    providers = new VerifierProviders();
    providers.setVerifierProvider(SignatureAlgorithm.HS256, hmacLocator);

    JsonTokenParser parser = new JsonTokenParser(new SystemClock(), providers, new Checker[] {});
    // this actually deserializes and then verifies, bad method name
    return parser.verifyAndDeserialize(serializedAndSignedJsonWebToken);
  }

  public <T> T payloadAs(String json, Class<T> classOfT) {
    return gson.fromJson(json, classOfT);
  }

  public <T> T payloadAs(JsonObject json, Class<T> classOfT) {
    return gson.fromJson(json, classOfT);
  }

  public <T> T entity(JsonToken jsonToken, String entityKey, Class<T> classOfT) {
    return gson.fromJson(jsonToken.getPayloadAsJsonObject().getAsJsonObject(entityKey), classOfT);
  }  
  
  //
  //
  //

  private JsonToken createToken() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
    //Current time and signing algorithm
    Calendar cal = Calendar.getInstance();
    HmacSHA256Signer signer = new HmacSHA256Signer(ISSUER, "userid", SIGNING_KEY.getBytes());

    //Configure JSON token
    JsonToken token = new JsonToken(signer);
    token.setAudience("Takari");
    token.setParam("typ", "takari/authentication/user/v1");
    // issue date
    token.setIssuedAt(new org.joda.time.Instant(cal.getTimeInMillis()));
    // expiration data
    token.setExpiration(new org.joda.time.Instant(cal.getTimeInMillis() + 60000L));

    //Configure request object, which provides information of the item
    JsonObject request = new JsonObject();
    request.addProperty("username", "jvanzyl");
    // https://crackstation.net/hashing-security.htm
    request.addProperty("password", PasswordHash.createHash("1xhooka52monkeydumplings"));

    //request.addProperty("description", "Virtual chocolate cake to fill your virtual tummy");
    //request.addProperty("price", "10.50");
    //request.addProperty("currencyCode", "USD");
    //request.addProperty("sellerData", "user_id:1224245,offer_code:3098576987,affiliate:aksdfbovu9j");

    JsonObject payload = token.getPayloadAsJsonObject();
    payload.add("user", request);

    return token;
  }

  private String deserialize(String tokenString) {
    String[] pieces = splitTokenString(tokenString);
    String jwtPayloadSegment = pieces[1];
    JsonParser parser = new JsonParser();
    JsonElement payload = parser.parse(StringUtils.newStringUtf8(Base64.decodeBase64(jwtPayloadSegment)));
    return payload.toString();
  }

  /**
   * @param tokenString The original encoded representation of a JWT
   * @return Three components of the JWT as an array of strings
   */
  private String[] splitTokenString(String tokenString) {
    String[] pieces = tokenString.split(Pattern.quote("."));
    if (pieces.length != 3) {
      throw new IllegalStateException("Expected JWT to have 3 segments separated by '" + "." + "', but it has " + pieces.length + " segments");
    }
    return pieces;
  }

  public static void main(String[] args) throws Exception {
    Jwt jwt = new Jwt();
    String tokenString = jwt.createSerializedAndSignedJsonWebToken();
    System.out.println(tokenString);
    JsonToken s = jwt.deserializeAndVerify(tokenString);
    System.out.println(">> " + s);
        
    User u = jwt.entity(s, "user", User.class);
    System.out.println(u.getUsername());

  }
}
