package io.phasetwo.keycloak.rest;

import static io.phasetwo.keycloak.rest.AuthenticationFlowResource.DRY_RUN_HEADER;
import static io.phasetwo.keycloak.rest.AuthenticationFlowResource.RESULT_APPLIED;
import static io.phasetwo.keycloak.rest.AuthenticationFlowResource.RESULT_HEADER;
import static io.phasetwo.keycloak.rest.AuthenticationFlowResource.RESULT_UNCHANGED;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.BROWSER;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.BROWSER_FORMS;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.BROWSER_OTP;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.FIRST_BROKER_LOGIN;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.V1;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.V2;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.authenticators;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.executionIds;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.flow;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.flowId;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.load;
import static io.phasetwo.keycloak.rest.ReplaceModeTestSupport.v1WithoutSpnegoAndOtp;
import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.AbstractTestBase;
import io.phasetwo.keycloak.model.AuthenticationFlowPayload;
import io.phasetwo.keycloak.model.ClientFlowPayload;
import io.restassured.response.Response;
import jakarta.ws.rs.NotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.AuthenticationExecutionExportRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;

/**
 * Replace mode selected per request with {@code ?mode=replace}. The container's default stays
 * versioned, so the versioned suite runs unchanged against the same server.
 */
class AuthenticationFlowsReplaceModeApiTest extends AbstractTestBase {

  private static final String REALM_NAME = "replace-test";

  private RealmResource realm;
  private String importUrl;

  @BeforeEach
  void createRealm() {
    AbstractTestBase.createRealm(REALM_NAME);
    realm = keycloak.realm(REALM_NAME);
    importUrl = getAdminRealmUrl(REALM_NAME) + "/authentication-flow/import";
  }

  @AfterEach
  void removeRealm() {
    realm.remove();
  }

  private Response post(Object payload) {
    return ReplaceModeTestSupport.post(keycloak, importUrl, payload, "replace");
  }

  @Test
  void firstImport_createsFlowsUnderPlainAliases_andBindsThem() throws IOException {
    int before = realm.flows().getFlows().size();

    Response response = post(load(V1));

    assertEquals(200, response.statusCode(), response.asString());
    assertEquals(RESULT_APPLIED, response.header(RESULT_HEADER));
    assertEquals(BROWSER, response.jsonPath().getString("browserFlowBinding"));
    assertEquals(before + 2, realm.flows().getFlows().size());
    assertEquals(BROWSER, realm.toRepresentation().getBrowserFlow());
    assertTrue(authenticators(keycloak, REALM_NAME, BROWSER).contains("auth-spnego"));
    assertEquals(
        List.of("conditional-user-configured", "auth-otp-form", "auth-recovery-authn-code-form"),
        authenticators(keycloak, REALM_NAME, BROWSER_OTP));
  }

  @Test
  void identicalRepost_isNoOp_andKeepsEveryId() throws IOException {
    assertEquals(200, post(load(V1)).statusCode());
    int flows = realm.flows().getFlows().size();
    String browserId = flowId(keycloak, REALM_NAME, BROWSER);
    List<String> executions = executionIds(keycloak, REALM_NAME, BROWSER);

    Response response = post(load(V1));

    assertEquals(200, response.statusCode(), response.asString());
    assertEquals(RESULT_UNCHANGED, response.header(RESULT_HEADER));
    assertEquals(flows, realm.flows().getFlows().size());
    assertEquals(browserId, flowId(keycloak, REALM_NAME, BROWSER));
    assertEquals(executions, executionIds(keycloak, REALM_NAME, BROWSER));
  }

  @Test
  void modifiedPayload_replacesExecutionsInPlace_andKeepsFlowId() throws IOException {
    assertEquals(200, post(load(V1)).statusCode());
    int flows = realm.flows().getFlows().size();
    String browserId = flowId(keycloak, REALM_NAME, BROWSER);
    String brokerId = flowId(keycloak, REALM_NAME, FIRST_BROKER_LOGIN);

    Response response = post(v1WithoutSpnegoAndOtp());

    assertEquals(200, response.statusCode(), response.asString());
    assertEquals(RESULT_APPLIED, response.header(RESULT_HEADER));
    assertEquals(flows, realm.flows().getFlows().size(), "no new top-level flows");
    assertEquals(browserId, flowId(keycloak, REALM_NAME, BROWSER), "flow id is stable");
    assertEquals(brokerId, flowId(keycloak, REALM_NAME, FIRST_BROKER_LOGIN));
    assertFalse(authenticators(keycloak, REALM_NAME, BROWSER).contains("auth-spnego"));
    assertEquals(
        List.of("auth-username-password-form"),
        authenticators(keycloak, REALM_NAME, BROWSER_FORMS));
    assertThrows(
        NotFoundException.class,
        () -> realm.flows().getExecutions(BROWSER_OTP),
        "orphaned subflow is deleted");
    assertEquals(BROWSER, realm.toRepresentation().getBrowserFlow());
  }

  @Test
  void replacingBackAndForth_convergesOnThePayload() throws IOException {
    assertEquals(200, post(load(V1)).statusCode());
    assertEquals(200, post(v1WithoutSpnegoAndOtp()).statusCode());

    Response response = post(load(V1));

    assertEquals(RESULT_APPLIED, response.header(RESULT_HEADER));
    assertTrue(authenticators(keycloak, REALM_NAME, BROWSER).contains("auth-spnego"));
    assertEquals(3, authenticators(keycloak, REALM_NAME, BROWSER_OTP).size());
    assertEquals(RESULT_UNCHANGED, post(load(V1)).header(RESULT_HEADER));
  }

  @Test
  void bindingsMadeOutsideThePayload_surviveAReplace() throws IOException {
    assertEquals(200, post(load(V1)).statusCode());
    String browserId = flowId(keycloak, REALM_NAME, BROWSER);
    ClientRepresentation client = new ClientRepresentation();
    client.setClientId("canary");
    client.setAuthenticationFlowBindingOverrides(Map.of("browser", browserId));
    realm.clients().create(client).close();
    RealmRepresentation rep = realm.toRepresentation();
    rep.setDirectGrantFlow(BROWSER);
    realm.update(rep);

    assertEquals(200, post(v1WithoutSpnegoAndOtp()).statusCode());

    ClientRepresentation canary = realm.clients().findByClientId("canary").getFirst();
    assertEquals(browserId, canary.getAuthenticationFlowBindingOverrides().get("browser"));
    assertEquals(BROWSER, realm.toRepresentation().getDirectGrantFlow());
    assertEquals(BROWSER, realm.toRepresentation().getBrowserFlow());
  }

  @Test
  void configsAreUpsertedByAlias_andNeverDeleted() throws IOException {
    assertEquals(200, post(load(V1)).statusCode());
    List<String> configsAfterV1 = configAliases();
    assertTrue(configsAfterV1.contains("Copy of first broker login review profile config 2"));

    // v2 is v1 with the two configs renamed to "... config 3"
    Response response = post(load(V2));

    assertEquals(200, response.statusCode(), response.asString());
    assertEquals(RESULT_APPLIED, response.header(RESULT_HEADER));
    List<String> configsAfterV2 = configAliases();
    assertTrue(configsAfterV2.contains("Copy of first broker login review profile config 3"));
    assertTrue(
        configsAfterV2.contains("Copy of first broker login review profile config 2"),
        "configs may be shared with other flows, so a replace does not delete them");

    // changing a config value is detected and applied in place
    AuthenticationFlowPayload v2 = load(V2);
    v2.getAuthenticatorConfig().getFirst().getConfig().put("update.profile.on.first.login", "off");
    assertEquals(RESULT_APPLIED, post(v2).header(RESULT_HEADER));
    assertEquals(RESULT_UNCHANGED, post(v2).header(RESULT_HEADER));
    assertEquals(configsAfterV2.size(), configAliases().size());
  }

  @Test
  void builtInFlowAlias_isRejected_andNothingIsWritten() throws IOException {
    List<String> browserBefore = authenticators(keycloak, REALM_NAME, "browser");
    int flows = realm.flows().getFlows().size();
    AuthenticationFlowPayload payload = load(V1);
    payload.getAuthenticationFlows().stream()
        .filter(f -> BROWSER.equals(f.getAlias()))
        .forEach(f -> f.setAlias("browser"));
    payload.setBrowserFlowBinding("browser");

    Response response = post(payload);

    assertEquals(400, response.statusCode(), response.asString());
    assertTrue(response.asString().contains("Built-in flow cannot be replaced: browser"));
    assertEquals(browserBefore, authenticators(keycloak, REALM_NAME, "browser"));
    assertEquals(flows, realm.flows().getFlows().size());
  }

  @Test
  void failedBinding_rollsBackTheWholeReplace() throws IOException {
    assertEquals(200, post(load(V1)).statusCode());
    List<String> executions = executionIds(keycloak, REALM_NAME, BROWSER);
    AuthenticationFlowPayload broken = v1WithoutSpnegoAndOtp();
    ClientFlowPayload binding = new ClientFlowPayload();
    binding.setClientId("does-not-exist");
    binding.setBrowserFlowBinding(BROWSER);
    broken.setClientFlowBinding(binding);

    Response response = post(broken);

    assertEquals(400, response.statusCode(), response.asString());
    assertEquals(executions, executionIds(keycloak, REALM_NAME, BROWSER), "old executions intact");
    assertEquals(3, authenticators(keycloak, REALM_NAME, BROWSER_OTP).size(), "subflow intact");
    assertEquals(
        RESULT_UNCHANGED,
        post(load(V1)).header(RESULT_HEADER),
        "the recorded hash was rolled back together with the flows");
  }

  @Test
  void danglingReferences_areRejectedBeforeAnythingIsWritten() throws IOException {
    int flows = realm.flows().getFlows().size();
    AuthenticationFlowPayload payload = load(V1);
    payload.getAuthenticationFlows().removeIf(f -> BROWSER_OTP.equals(f.getAlias()));

    Response response = post(payload);

    assertEquals(400, response.statusCode(), response.asString());
    assertTrue(response.asString().contains("not in the payload"), response.asString());
    assertEquals(flows, realm.flows().getFlows().size());
  }

  @Test
  void missingRequiredArrays_areRejectedWith400() throws IOException {
    AuthenticationFlowPayload payload = load(V1);
    payload.setAuthenticatorConfig(null);

    assertEquals(400, post(payload).statusCode());
  }

  @Test
  void unknownMode_isRejectedWith400() throws IOException {
    Response response = ReplaceModeTestSupport.post(keycloak, importUrl, load(V1), "bogus");

    assertEquals(400, response.statusCode(), response.asString());
    assertTrue(response.asString().contains("Unknown import mode 'bogus'"));
  }

  @Test
  void explicitVersionedMode_stillPrefixesAliases() throws IOException {
    Response response = ReplaceModeTestSupport.post(keycloak, importUrl, load(V1), "versioned");

    assertEquals(200, response.statusCode(), response.asString());
    String binding = response.jsonPath().getString("browserFlowBinding");
    assertNotEquals(BROWSER, binding);
    assertTrue(binding.endsWith("-" + BROWSER));
  }

  // -------------------------------------------------------------------------------------------
  // Validation
  // -------------------------------------------------------------------------------------------

  @Test
  void unknownAuthenticatorProvider_isRejected() throws IOException {
    AuthenticationFlowPayload payload = load(V1);
    flow(payload, BROWSER_FORMS).getAuthenticationExecutions().getFirst().setAuthenticator("nope");

    assertRejected(payload, "unknown Authenticator provider 'nope'");
  }

  @Test
  void unknownFlowProviderId_isRejected() throws IOException {
    AuthenticationFlowPayload payload = load(V1);
    flow(payload, BROWSER_FORMS).setProviderId("weird-flow");

    assertRejected(payload, "unknown providerId 'weird-flow'");
  }

  @Test
  void subflowCycle_isRejected() throws IOException {
    // browser no longer reaches forms; forms -> OTP -> forms is a cycle nobody can enter
    AuthenticationFlowPayload payload = load(V1);
    flow(payload, BROWSER).getAuthenticationExecutions().removeIf(e -> e.isAuthenticatorFlow());
    AuthenticationExecutionExportRepresentation back =
        new AuthenticationExecutionExportRepresentation();
    back.setAuthenticatorFlow(true);
    back.setFlowAlias(BROWSER_FORMS);
    back.setRequirement("REQUIRED");
    back.setPriority(99);
    flow(payload, BROWSER_OTP).getAuthenticationExecutions().add(back);

    assertRejected(payload, "subflow reference cycle");
  }

  @Test
  void subflowWithTwoParents_isRejected() throws IOException {
    AuthenticationFlowPayload payload = load(V1);
    AuthenticationExecutionExportRepresentation second =
        new AuthenticationExecutionExportRepresentation();
    second.setAuthenticatorFlow(true);
    second.setFlowAlias(BROWSER_OTP);
    second.setRequirement("CONDITIONAL");
    second.setPriority(99);
    flow(payload, FIRST_BROKER_LOGIN).getAuthenticationExecutions().add(second);

    assertRejected(payload, "a subflow can have only one parent");
  }

  @Test
  void topLevelFlowUsedAsSubflow_isRejected() throws IOException {
    AuthenticationFlowPayload payload = load(V1);
    flow(payload, BROWSER_FORMS).setTopLevel(true);

    assertRejected(payload, "is top-level but is used as a subflow");
  }

  @Test
  void orphanedSubflowInPayload_isRejected() throws IOException {
    AuthenticationFlowPayload payload = load(V1);
    flow(payload, BROWSER_FORMS)
        .getAuthenticationExecutions()
        .removeIf(e -> e.isAuthenticatorFlow());

    assertRejected(payload, "is not reachable from any top-level flow");
  }

  @Test
  void changingWhetherAnExistingFlowIsTopLevel_isRejected() throws IOException {
    assertEquals(200, post(load(V1)).statusCode());
    List<String> executions = executionIds(keycloak, REALM_NAME, BROWSER);
    // promote "forms" to a top-level flow of its own
    AuthenticationFlowPayload payload = load(V1);
    flow(payload, BROWSER).getAuthenticationExecutions().removeIf(e -> e.isAuthenticatorFlow());
    flow(payload, BROWSER_FORMS).setTopLevel(true);

    Response response = post(payload);

    assertEquals(400, response.statusCode(), response.asString());
    assertTrue(
        response.asString().contains("exists as a subflow and cannot be replaced as a top-level"),
        response.asString());
    assertEquals(executions, executionIds(keycloak, REALM_NAME, BROWSER));
  }

  @Test
  void subflowUsedByAFlowOutsideThePayload_isRejected() throws IOException {
    assertEquals(200, post(load(V1)).statusCode());
    // a new top-level flow that claims the existing "forms" subflow of "Copy of browser"
    AuthenticationFlowPayload full = load(V1);
    AuthenticationFlowRepresentation other = new AuthenticationFlowRepresentation();
    other.setAlias("Other");
    other.setProviderId("basic-flow");
    other.setTopLevel(true);
    AuthenticationExecutionExportRepresentation forms =
        new AuthenticationExecutionExportRepresentation();
    forms.setAuthenticatorFlow(true);
    forms.setFlowAlias(BROWSER_FORMS);
    forms.setRequirement("REQUIRED");
    forms.setPriority(10);
    other.setAuthenticationExecutions(new ArrayList<>(List.of(forms)));
    AuthenticationFlowPayload payload = new AuthenticationFlowPayload();
    payload.setAuthenticationFlows(
        new ArrayList<>(List.of(other, flow(full, BROWSER_FORMS), flow(full, BROWSER_OTP))));
    payload.setAuthenticatorConfig(new ArrayList<>());

    assertRejected(payload, "is also used as a subflow by 'Copy of browser'");
  }

  @Test
  void orphanedSubflowSharedWithAnotherFlow_isKept() throws IOException {
    // Keycloak's own realm import lets two flows share a subflow; replace mode must not delete it
    // from under the flow that is not in the payload.
    String sharedRealm = "replace-shared-subflow";
    AuthenticationFlowPayload v1 = load(V1);
    AuthenticationFlowRepresentation other = new AuthenticationFlowRepresentation();
    other.setAlias("Other");
    other.setProviderId("basic-flow");
    other.setTopLevel(true);
    AuthenticationExecutionExportRepresentation otp =
        new AuthenticationExecutionExportRepresentation();
    otp.setAuthenticatorFlow(true);
    otp.setFlowAlias(BROWSER_OTP);
    otp.setRequirement("CONDITIONAL");
    otp.setPriority(10);
    other.setAuthenticationExecutions(new ArrayList<>(List.of(otp)));
    List<AuthenticationFlowRepresentation> flows = new ArrayList<>(v1.getAuthenticationFlows());
    flows.add(other);
    RealmRepresentation rep = new RealmRepresentation();
    rep.setRealm(sharedRealm);
    rep.setEnabled(true);
    rep.setAuthenticationFlows(flows);
    rep.setAuthenticatorConfig(v1.getAuthenticatorConfig());
    keycloak.realms().create(rep);
    try {
      Response response =
          ReplaceModeTestSupport.post(
              keycloak,
              getAdminRealmUrl(sharedRealm) + "/authentication-flow/import",
              v1WithoutSpnegoAndOtp(),
              "replace");

      assertEquals(200, response.statusCode(), response.asString());
      assertEquals(
          List.of("auth-username-password-form"),
          authenticators(keycloak, sharedRealm, BROWSER_FORMS));
      assertEquals(
          3,
          authenticators(keycloak, sharedRealm, BROWSER_OTP).size(),
          "subflow still used by 'Other' is kept intact");
    } finally {
      keycloak.realm(sharedRealm).remove();
    }
  }

  // -------------------------------------------------------------------------------------------
  // Dry run
  // -------------------------------------------------------------------------------------------

  private Response dryRun(Object payload, String mode) {
    return ReplaceModeTestSupport.post(
        keycloak, importUrl, payload, mode, Map.of("dryRun", "true"));
  }

  @Test
  void dryRun_reportsTheChange_butWritesNothing() throws IOException {
    assertEquals(200, post(load(V1)).statusCode());
    List<String> executions = executionIds(keycloak, REALM_NAME, BROWSER);

    Response response = dryRun(v1WithoutSpnegoAndOtp(), "replace");

    assertEquals(200, response.statusCode(), response.asString());
    assertEquals("true", response.header(DRY_RUN_HEADER));
    assertEquals(RESULT_APPLIED, response.header(RESULT_HEADER), "would apply");
    assertEquals(executions, executionIds(keycloak, REALM_NAME, BROWSER));
    assertEquals(3, authenticators(keycloak, REALM_NAME, BROWSER_OTP).size());
    assertEquals(RESULT_UNCHANGED, post(load(V1)).header(RESULT_HEADER), "hash not recorded");
  }

  @Test
  void dryRun_ofAnIdenticalPayload_reportsUnchanged() throws IOException {
    assertEquals(200, post(load(V1)).statusCode());

    Response response = dryRun(load(V1), "replace");

    assertEquals(200, response.statusCode(), response.asString());
    assertEquals(RESULT_UNCHANGED, response.header(RESULT_HEADER));
  }

  @Test
  void dryRun_onAnEmptyRealm_createsNothing() throws IOException {
    int flows = realm.flows().getFlows().size();
    String browser = realm.toRepresentation().getBrowserFlow();
    List<String> configs = configAliases();

    Response response = dryRun(load(V1), "replace");

    assertEquals(200, response.statusCode(), response.asString());
    assertEquals(flows, realm.flows().getFlows().size());
    assertEquals(browser, realm.toRepresentation().getBrowserFlow());
    assertEquals(configs, configAliases());
  }

  @Test
  void dryRun_returnsTheSameValidationErrors() throws IOException {
    AuthenticationFlowPayload payload = load(V1);
    ClientFlowPayload binding = new ClientFlowPayload();
    binding.setClientId("does-not-exist");
    binding.setBrowserFlowBinding(BROWSER);
    payload.setClientFlowBinding(binding);

    Response response = dryRun(payload, "replace");

    assertEquals(400, response.statusCode(), response.asString());
    assertTrue(response.asString().contains("Missing client with id: does-not-exist"));
  }

  @Test
  void dryRun_inVersionedMode_createsNothing() throws IOException {
    int flows = realm.flows().getFlows().size();

    Response response = dryRun(load(V1), "versioned");

    assertEquals(200, response.statusCode(), response.asString());
    assertEquals("true", response.header(DRY_RUN_HEADER));
    assertEquals(flows, realm.flows().getFlows().size());
  }

  // -------------------------------------------------------------------------------------------
  // Export
  // -------------------------------------------------------------------------------------------

  private Response export(String... aliases) {
    var request =
        given()
            .headers("Authorization", "Bearer " + keycloak.tokenManager().getAccessTokenString());
    if (aliases.length > 0) {
      request = request.queryParam("alias", (Object[]) aliases);
    }
    return request.get(getAdminRealmUrl(REALM_NAME) + "/authentication-flow/export");
  }

  @Test
  void export_returnsTheFlowTreeAndItsConfigs_inImportFormat() throws IOException {
    assertEquals(200, post(load(V1)).statusCode());

    Response response = export(BROWSER);

    assertEquals(200, response.statusCode(), response.asString());
    AuthenticationFlowPayload exported = response.as(AuthenticationFlowPayload.class);
    assertEquals(
        List.of(BROWSER, BROWSER_FORMS, BROWSER_OTP),
        exported.getAuthenticationFlows().stream()
            .map(AuthenticationFlowRepresentation::getAlias)
            .toList());
    assertTrue(exported.getAuthenticationFlows().stream().allMatch(f -> f.getId() == null));
    assertTrue(exported.getAuthenticatorConfig().isEmpty(), "browser tree uses no configs");
    assertEquals(null, exported.getBrowserFlowBinding(), "bindings are not exported");

    AuthenticationFlowPayload broker =
        export(FIRST_BROKER_LOGIN).as(AuthenticationFlowPayload.class);
    assertEquals(
        List.of(
            "Copy of first broker login create unique user config 2",
            "Copy of first broker login review profile config 2"),
        broker.getAuthenticatorConfig().stream()
            .map(AuthenticatorConfigRepresentation::getAlias)
            .toList());
  }

  @Test
  void export_withoutAlias_returnsEveryNonBuiltInTopLevelFlow() throws IOException {
    assertEquals(200, post(load(V1)).statusCode());

    AuthenticationFlowPayload exported = export().as(AuthenticationFlowPayload.class);

    assertEquals(5, exported.getAuthenticationFlows().size());
    assertTrue(exported.getAuthenticationFlows().stream().noneMatch(f -> f.isBuiltIn()));
    assertEquals(2, exported.getAuthenticatorConfig().size());
  }

  @Test
  void export_roundTrips_andReimportingItIsANoOpForTheFlows() throws IOException {
    assertEquals(200, post(load(V1)).statusCode());
    AuthenticationFlowPayload exported = export().as(AuthenticationFlowPayload.class);

    String copyRealm = "replace-export-copy";
    AbstractTestBase.createRealm(copyRealm);
    try {
      Response response =
          ReplaceModeTestSupport.post(
              keycloak,
              getAdminRealmUrl(copyRealm) + "/authentication-flow/import",
              exported,
              "replace");
      assertEquals(200, response.statusCode(), response.asString());
      for (String alias : List.of(BROWSER, BROWSER_FORMS, BROWSER_OTP, FIRST_BROKER_LOGIN)) {
        assertEquals(
            authenticators(keycloak, REALM_NAME, alias),
            authenticators(keycloak, copyRealm, alias),
            alias);
      }
    } finally {
      keycloak.realm(copyRealm).remove();
    }

    assertEquals(200, post(exported).statusCode());
    assertEquals(
        RESULT_UNCHANGED,
        post(exported).header(RESULT_HEADER),
        "posting the same export twice is a no-op");
  }

  @Test
  void export_ofAnUnknownFlow_is404_andOfASubflow_is400() {
    assertEquals(404, export("does-not-exist").statusCode());
    assertEquals(400, export("forms").statusCode());
  }

  private void assertRejected(AuthenticationFlowPayload payload, String message) {
    int flows = realm.flows().getFlows().size();
    Response response = post(payload);
    assertEquals(400, response.statusCode(), response.asString());
    assertTrue(response.asString().contains(message), response.asString());
    assertEquals(flows, realm.flows().getFlows().size(), "nothing written");
  }

  private List<String> configAliases() {
    return realm.partialExport(false, false).getAuthenticatorConfig().stream()
        .map(AuthenticatorConfigRepresentation::getAlias)
        .toList();
  }
}
