package io.phasetwo.keycloak.rest;

import static io.phasetwo.keycloak.rest.AuthenticationFlowResource.RESULT_APPLIED;
import static io.phasetwo.keycloak.rest.AuthenticationFlowResource.RESULT_HEADER;
import static io.phasetwo.keycloak.rest.AuthenticationFlowResource.RESULT_UNCHANGED;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.BROWSER;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.V1;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.executionIds;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.load;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.v1WithoutSpnegoAndOtp;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.AbstractTestBase;
import io.restassured.response.Response;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * What happens to a browser login that is part way through a flow when replace mode rewrites that
 * flow. Every execution is recreated with a new id, so Keycloak cannot find the execution the login
 * was on and restarts it from the beginning: a user who started logging in before a stricter flow
 * was applied cannot finish under the old one. An identical re-post rewrites nothing, so it does not
 * disturb logins in progress.
 */
class ReplaceModeInFlightLoginTest extends AbstractTestBase {

  private static final String REALM_NAME = "replace-in-flight";
  private static final String CLIENT_ID = "in-flight-app";
  private static final String REDIRECT_URI = "http://localhost/callback";
  private static final String USERNAME = "alice";
  private static final String PASSWORD = "password";
  private static final Pattern FORM_ACTION =
      Pattern.compile(
          "id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"|action=\"([^\"]+)\"[^>]*id=\"kc-form-login\"");

  private String importUrl;

  @BeforeEach
  void setUp() throws IOException {
    AbstractTestBase.createRealm(REALM_NAME);
    importUrl = getAdminRealmUrl(REALM_NAME) + "/authentication-flow/import";

    ClientRepresentation client = new ClientRepresentation();
    client.setClientId(CLIENT_ID);
    client.setPublicClient(true);
    client.setStandardFlowEnabled(true);
    client.setRedirectUris(List.of(REDIRECT_URI));
    keycloak.realm(REALM_NAME).clients().create(client).close();

    UserRepresentation user = new UserRepresentation();
    user.setUsername(USERNAME);
    user.setEmail("alice@example.com");
    user.setFirstName("Alice");
    user.setLastName("Example");
    user.setEmailVerified(true);
    user.setEnabled(true);
    CredentialRepresentation password = new CredentialRepresentation();
    password.setType(CredentialRepresentation.PASSWORD);
    password.setValue(PASSWORD);
    password.setTemporary(false);
    user.setCredentials(List.of(password));
    keycloak.realm(REALM_NAME).users().create(user).close();

    assertEquals(RESULT_APPLIED, replace(load(V1)).header(RESULT_HEADER));
  }

  @AfterEach
  void tearDownRealm() {
    keycloak.realm(REALM_NAME).remove();
  }

  @Test
  void loginWithoutAReplace_completes() {
    LoginPage page = openLoginPage();

    Response response = page.submit(USERNAME, PASSWORD);

    assertLoggedIn(response);
  }

  @Test
  void loginInProgress_restartsWhenItsFlowIsReplaced() throws IOException {
    LoginPage page = openLoginPage();
    assertTrue(executionIds(keycloak, REALM_NAME, BROWSER).size() > 0);

    assertEquals(RESULT_APPLIED, replace(v1WithoutSpnegoAndOtp()).header(RESULT_HEADER));
    Response response = page.submit(USERNAME, PASSWORD);

    assertEquals(200, response.statusCode(), "the login page is shown again, not a redirect");
    LoginPage restarted = LoginPage.parse(response, page.cookies());
    assertFalse(
        restarted.action().equals(page.action()),
        "the restarted form posts to an execution of the new flow");

    assertLoggedIn(restarted.submit(USERNAME, PASSWORD));
  }

  @Test
  void loginInProgress_survivesAnIdenticalRepost() throws IOException {
    LoginPage page = openLoginPage();

    assertEquals(RESULT_UNCHANGED, replace(load(V1)).header(RESULT_HEADER));

    assertLoggedIn(page.submit(USERNAME, PASSWORD));
  }

  private Response replace(Object payload) {
    return ReplaceModeTestSupport.post(keycloak, importUrl, payload, "replace");
  }

  private LoginPage openLoginPage() {
    Response response =
        given()
            .redirects()
            .follow(false)
            .queryParam("client_id", CLIENT_ID)
            .queryParam("redirect_uri", REDIRECT_URI)
            .queryParam("response_type", "code")
            .queryParam("scope", "openid")
            .get(getAuthUrl() + "/realms/" + REALM_NAME + "/protocol/openid-connect/auth");
    assertEquals(200, response.statusCode(), response.asString());
    return LoginPage.parse(response, response.getCookies());
  }

  private static void assertLoggedIn(Response response) {
    assertEquals(302, response.statusCode(), response.asString());
    String location = response.header("Location");
    assertNotNull(location);
    assertTrue(
        location.startsWith(REDIRECT_URI) && location.contains("code="),
        "redirected back to the client with a code: " + location);
  }

  /** The username/password form of the login page, and the cookies of its login session. */
  private record LoginPage(String action, Map<String, String> cookies) {

    static LoginPage parse(Response response, Map<String, String> cookies) {
      Matcher matcher = FORM_ACTION.matcher(response.asString());
      assertTrue(matcher.find(), "login form in page: " + response.asString());
      String action = matcher.group(1) != null ? matcher.group(1) : matcher.group(2);
      return new LoginPage(action.replace("&amp;", "&"), cookies);
    }

    Response submit(String username, String password) {
      return given()
          .redirects()
          .follow(false)
          .urlEncodingEnabled(false)
          .cookies(cookies)
          .contentType("application/x-www-form-urlencoded")
          .formParam("username", username)
          .formParam("password", password)
          .post(action);
    }
  }
}
