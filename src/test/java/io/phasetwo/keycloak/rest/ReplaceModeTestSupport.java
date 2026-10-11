package io.phasetwo.keycloak.rest;

import static io.restassured.RestAssured.given;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.phasetwo.keycloak.model.AuthenticationFlowPayload;
import io.restassured.response.Response;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.common.util.StreamUtil;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;

/** Payload loading and request helpers shared by the replace-mode test classes. */
final class ReplaceModeTestSupport {

  static final String V1 = "json/authentication-flow-import-v1.json";
  static final String V2 = "json/authentication-flow-import-v2.json";

  static final String BROWSER = "Copy of browser";
  static final String BROWSER_FORMS = "Copy of browser forms";
  static final String BROWSER_OTP = "Copy of browser Browser - Conditional OTP";
  static final String FIRST_BROKER_LOGIN = "Copy of first broker login";

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private ReplaceModeTestSupport() {}

  static AuthenticationFlowPayload load(String resource) throws IOException {
    try (InputStream is =
        ReplaceModeTestSupport.class.getClassLoader().getResourceAsStream(resource)) {
      String json = StreamUtil.readString(is, StandardCharsets.UTF_8);
      return MAPPER.readValue(json, AuthenticationFlowPayload.class);
    }
  }

  /**
   * v1 without the {@code auth-spnego} execution on the browser flow and without the conditional
   * OTP subflow: exercises a changed execution list and an orphaned subflow.
   */
  static AuthenticationFlowPayload v1WithoutSpnegoAndOtp() throws IOException {
    AuthenticationFlowPayload payload = load(V1);
    List<AuthenticationFlowRepresentation> flows = new ArrayList<>();
    for (AuthenticationFlowRepresentation flow : payload.getAuthenticationFlows()) {
      if (BROWSER_OTP.equals(flow.getAlias())) {
        continue;
      }
      flow.setAuthenticationExecutions(
          new ArrayList<>(
              flow.getAuthenticationExecutions().stream()
                  .filter(e -> !"auth-spnego".equals(e.getAuthenticator()))
                  .filter(e -> !BROWSER_OTP.equals(e.getFlowAlias()))
                  .toList()));
      flows.add(flow);
    }
    payload.setAuthenticationFlows(flows);
    return payload;
  }

  static Response post(Keycloak keycloak, String importUrl, Object payload, String mode) {
    var request =
        given()
            .headers("Authorization", "Bearer " + keycloak.tokenManager().getAccessTokenString())
            .contentType("application/json")
            .body(payload);
    if (mode != null) {
      request = request.queryParam("mode", mode);
    }
    return request.post(importUrl);
  }

  static String flowId(Keycloak keycloak, String realm, String alias) {
    return keycloak.realm(realm).flows().getFlows().stream()
        .filter(f -> alias.equals(f.getAlias()))
        .map(AuthenticationFlowRepresentation::getId)
        .findFirst()
        .orElseThrow(() -> new AssertionError("No top-level flow with alias " + alias));
  }

  static List<String> authenticators(Keycloak keycloak, String realm, String alias) {
    return keycloak.realm(realm).flows().getExecutions(alias).stream()
        .map(AuthenticationExecutionInfoRepresentation::getProviderId)
        .toList();
  }

  static List<String> executionIds(Keycloak keycloak, String realm, String alias) {
    return keycloak.realm(realm).flows().getExecutions(alias).stream()
        .map(AuthenticationExecutionInfoRepresentation::getId)
        .toList();
  }
}
