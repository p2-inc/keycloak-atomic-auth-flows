package io.phasetwo.keycloak.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.phasetwo.keycloak.AbstractTestBase;
import io.phasetwo.keycloak.model.AuthenticationFlowPayload;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.util.StreamUtil;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

import static io.restassured.RestAssured.given;

class AuthenticationFlowsResourceApiTest extends AbstractTestBase {

    private String importUrl(String realmName) {
        return getAdminRealmUrl(realmName) + "/authentication-flow/import";
    }

    @Test
    void doingSameAuthenticationFlowTwiceWithoutForceParam_shouldResultIn409StatusError() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test";
        createTestRealm(realmName);

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-v1.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        // get no of flows at begining
        long initialFlowsCount = keycloak.realm(realmName).flows().getFlows().size();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .asString();

        JSONObject deserialized = new JSONObject(response);
        Assertions.assertNotNull(deserialized);

        //flows should be prefix with some specific hash
        String flowBinding = deserialized.get("browserFlowBinding").toString();
        String prefix = flowBinding.replace("-Browser flow", "");
        Assertions.assertNotNull(prefix);

        // get no of flows at end
        long flowsCount = keycloak.realm(realmName).flows().getFlows().size();
        Assertions.assertEquals(flowsCount, initialFlowsCount + 2);

        // retrying to import the same file will result in a error
        given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(409);

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void doingSameAuthenticationFlowWithForceParam_shouldResultInForceBindingParams() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test";
        createTestRealm(realmName);

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-v1.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        // get no of flows at begining
        long initialFlowsCount = keycloak.realm(realmName).flows().getFlows().size();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .asString();

        JSONObject deserialized = new JSONObject(response);
        Assertions.assertNotNull(deserialized);

        //flows should be prefix with some specific hash
        String flowBinding = deserialized.get("browserFlowBinding").toString();
        String prefix = flowBinding.replace("-Browser flow", "");
        Assertions.assertNotNull(prefix);

        // get no of flows at end
        long flowsCount = keycloak.realm(realmName).flows().getFlows().size();
        Assertions.assertEquals(flowsCount, initialFlowsCount + 2);

        // retrying to import the same file will result in a error
        var response2 = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .queryParam("force", true)
                .post(importUrl(realmName))
                .then()
                .statusCode(200)
                .extract()
                .asString();
        JSONObject deserialized2 = new JSONObject(response2);

        Assertions.assertNotNull(deserialized2);

        // get no of flows after second import
        long totalFlowsCount = keycloak.realm(realmName).flows().getFlows().size();
        Assertions.assertEquals(totalFlowsCount, flowsCount);

        //flows should be prefix with some specific hash
        var flowBinding1 = deserialized.get("browserFlowBinding");
        var flowBinding2 = deserialized2.get("browserFlowBinding");
        Assertions.assertEquals(flowBinding1, flowBinding2);

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void doingSameAuthenticationFlowImportTwiceWithForceParam_AndMissingBrowserFlow_shouldResultInForceBindingParams() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test";
        createTestRealm(realmName);

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-v1.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        // get no of flows at begining
        long initialFlowsCount = keycloak.realm(realmName).flows().getFlows().size();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .asString();

        JSONObject deserialized = new JSONObject(response);
        Assertions.assertNotNull(deserialized);

        //flows should be prefix with some specific hash
        String flowBinding = deserialized.get("browserFlowBinding").toString();
        String prefix = flowBinding.replace("-Browser flow", "");
        Assertions.assertNotNull(prefix);

        // get no of flows at end
        long flowsCount = keycloak.realm(realmName).flows().getFlows().size();
        Assertions.assertEquals(flowsCount, initialFlowsCount + 2);


        //import the same file will config change
        // Path to the resource file inside the resources folder
        String resourceFilePath2 = "json/authentication-flow-import-flow-binding-not-present.json";
        InputStream is2 = getClass().getClassLoader().getResourceAsStream(resourceFilePath2);

        String s2 = StreamUtil.readString(is2, Charset.defaultCharset());
        AuthenticationFlowPayload authenticationFlowPayload2 = objectMapper.readValue(s2, AuthenticationFlowPayload.class);

        // retrying to import the same file will result in a error
         given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload2)
                .queryParam("force", true)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(400);

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void importingFlowsWithoutAuthenticatorConfigArray_shouldResultIn500StatusError() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test";
        createTestRealm(realmName);

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-missing-config-array.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(500)
                .extract()
                .asString();

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void importingFlowsWithEmptyAuthenticatorConfigArray_shouldResultInSuccess() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test";
        createTestRealm(realmName);

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-empty-config-array.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        // get no of flows at beginning
        long initialFlowsCount = keycloak.realm(realmName).flows().getFlows().size();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .asString();
        JSONObject deserialized1 = new JSONObject(response);

        Assertions.assertNotNull(deserialized1);

        // get no of flows after first import
        long afterFirstImportFlowsCount = keycloak.realm(realmName).flows().getFlows().size();
        Assertions.assertEquals(afterFirstImportFlowsCount, initialFlowsCount + 1);

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }


    @Test
    void doingImportWithMisconfiguredFlow_shouldResultIn500StatusError() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test";
        createTestRealm(realmName);

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-invalid-flows-config.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(500)
                .extract()
                .asString();

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void doingFlowBindingWithFlowNotInTheRequestPayload_shouldResultIn400StatusError() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test";
        createTestRealm(realmName);

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-flow-binding-not-present.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(400)
                .extract()
                .asString();

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void doingClientBrowserFlowBindingWithFlowNotInTheRequestPayload_shouldResultIn400StatusError() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test";
        RealmResource realm = createTestRealm(realmName);
        createPublicClientInRealm(realm, "test-client");

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-client-flow-browser-flow-binding-not-present.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(400)
                .extract()
                .asString();

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void doingClientDirectFlowBindingWithFlowNotInTheRequestPayload_shouldResultIn400StatusError() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test";
        RealmResource realm = createTestRealm(realmName);
        createPublicClientInRealm(realm, "test-client");

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-client-flow-direct-flow-binding-not-present.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(400)
                .extract()
                .asString();

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void doingIdpFirstBrokerFlowBindingWithFlowNotInTheRequestPayload_shouldResultIn400StatusError() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test";
        RealmResource realm = createTestRealm(realmName);
        createIdentityProvider(realm, "test-idp");
        createIdentityProvider(realm, "test-idp2");

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-idp-flow-missing-first-login-flow-binding.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(400)
                .extract()
                .asString();

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void doingIdpPostBrokerFlowBindingWithFlowNotInTheRequestPayload_shouldResultIn400StatusError() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test";
        RealmResource realm = createTestRealm(realmName);
        createIdentityProvider(realm, "test-idp");

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-idp-flow-missing-post-login-flow-binding.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(400)
                .extract()
                .asString();

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void importAndChangeAttribute_shouldCreateANewSetOfAuthenticationFlows() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        var realmName = "test";
        createTestRealm(realmName);

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-v1.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        // get no of flows at beginning
        long initialFlowsCount = keycloak.realm(realmName).flows().getFlows().size();

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .asString();

        JSONObject deserialized1 = new JSONObject(response);

        Assertions.assertNotNull(deserialized1);

        // get no of flows after first import
        long afterFirstImportFlowsCount = keycloak.realm(realmName).flows().getFlows().size();
        Assertions.assertEquals(afterFirstImportFlowsCount, initialFlowsCount + 2);


        //import the same file will config change
        // Path to the resource file inside the resources folder
        String resourceFilePath2 = "json/authentication-flow-import-v2.json";
        InputStream is2 = getClass().getClassLoader().getResourceAsStream(resourceFilePath2);

        String s2 = StreamUtil.readString(is2, Charset.defaultCharset());
        AuthenticationFlowPayload authenticationFlowPayload2 = objectMapper.readValue(s2, AuthenticationFlowPayload.class);

        var response2 = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload2)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .asString();

        JSONObject deserialized2 = new JSONObject(response2);

        Assertions.assertNotNull(deserialized2);

        // get no of flows after second import
        long totalFlowsCount = keycloak.realm(realmName).flows().getFlows().size();
        Assertions.assertEquals(totalFlowsCount, afterFirstImportFlowsCount + 2);

        //flows should be prefix with some specific hash
        var flowBinding1 = deserialized1.get("browserFlowBinding");
        var flowBinding2 = deserialized2.get("browserFlowBinding");
        Assertions.assertNotEquals(flowBinding1, flowBinding2);

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void browserFlowBinding_shouldBeOptional() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        var realmName = "test";
        createTestRealm(realmName);

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-no-browser-flow.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .asString();

        JSONObject deserialized = new JSONObject(response);
        Assertions.assertNotNull(deserialized);

        //browser flow should not be present
        Assertions.assertFalse(deserialized.has("browserFlowBinding"));

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void setClientFlowBinding_shouldResultInSuccess() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test1";
        RealmResource realm = createTestRealm(realmName);

        createPublicClientInRealm(realm, "test-client");

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-client-flow.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .asString();

        JSONObject deserialized = new JSONObject(response);
        Assertions.assertNotNull(deserialized);

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void reimportInitialPayload_withForceParam_shouldNotCreateANewSetOfAuthenticationFlows() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        var realmName = "test";
        createTestRealm(realmName);

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-v1.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        // get no of flows at beginning
        long initialFlowsCount = keycloak.realm(realmName).flows().getFlows().size();

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .asString();

        JSONObject deserialized1 = new JSONObject(response);

        Assertions.assertNotNull(deserialized1);

        // get no of flows after first import
        long afterFirstImportFlowsCount = keycloak.realm(realmName).flows().getFlows().size();
        Assertions.assertEquals(afterFirstImportFlowsCount, initialFlowsCount + 2);


        //import the same file will config change
        // Path to the resource file inside the resources folder
        String resourceFilePath2 = "json/authentication-flow-import-v2.json";
        InputStream is2 = getClass().getClassLoader().getResourceAsStream(resourceFilePath2);

        String s2 = StreamUtil.readString(is2, Charset.defaultCharset());
        AuthenticationFlowPayload authenticationFlowPayload2 = objectMapper.readValue(s2, AuthenticationFlowPayload.class);

        var response2 = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload2)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .asString();

        JSONObject deserialized2 = new JSONObject(response2);

        Assertions.assertNotNull(deserialized2);

        // get no of flows after second import
        long totalFlowsCount = keycloak.realm(realmName).flows().getFlows().size();
        Assertions.assertEquals(totalFlowsCount, afterFirstImportFlowsCount + 2);

        //flows should be prefix with some specific hash
        var flowBinding1 = deserialized1.get("browserFlowBinding");
        var flowBinding2 = deserialized2.get("browserFlowBinding");
        Assertions.assertNotEquals(flowBinding1, flowBinding2);

        //perform a re-import request
        String response3 = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .queryParam("force", true)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .asString();

        JSONObject deserialized3 = new JSONObject(response3);

        Assertions.assertNotNull(deserialized3);

        // get no of flows after first import
        long reimportFlowsCount = keycloak.realm(realmName).flows().getFlows().size();
        Assertions.assertEquals(reimportFlowsCount, totalFlowsCount);

        //flows should be prefix with the first flow specific hash
        var flowBinding3 = deserialized3.get("browserFlowBinding");
        Assertions.assertEquals(flowBinding1, flowBinding3);

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }


    @Test
    void setIdpFlowBinding_shouldResultInSuccess() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test1";
        RealmResource realm = createTestRealm(realmName);

        createIdentityProvider(realm, "test-idp");
        createIdentityProvider(realm, "test-idp2");

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-idp-flow.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(200)
                .extract()
                .asString();

        JSONObject deserialized = new JSONObject(response);
        Assertions.assertNotNull(deserialized);

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    @Test
    void setIdpFlowBinding_shouldResultInErrorIfIdpAliasDoesNotExist() throws IOException {

        //create a new test realm. It will be easier to cleanup after creating flows
        String realmName = "test1";
        RealmResource realm = createTestRealm(realmName);

        createIdentityProvider(realm, "test-idp");

        // Path to the resource file inside the resources folder
        String resourceFilePath = "json/authentication-flow-import-idp-flow.json";
        InputStream is = getClass().getClassLoader().getResourceAsStream(resourceFilePath);

        String s = StreamUtil.readString(is, Charset.defaultCharset());
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticationFlowPayload authenticationFlowPayload = objectMapper.readValue(s, AuthenticationFlowPayload.class);

        //Get access token
        String accessToken = keycloak.tokenManager().getAccessTokenString();

        //perform a import request
        String response = given().headers(
                        "Authorization",
                        "Bearer " + accessToken
                ).contentType("application/json")
                .body(authenticationFlowPayload)
                .post(importUrl(realmName))
                .then()
                .assertThat()
                .statusCode(400)
                .extract()
                .asString();

        //remove realm
        keycloak.realms().realm(realmName).remove();
    }

    private static RealmResource createTestRealm(String realmName) {
        RealmRepresentation testRealm = new RealmRepresentation();
        testRealm.setRealm(realmName);
        keycloak.realms().create(testRealm);
        return keycloak.realm(realmName);
    }

    private static ClientRepresentation createPublicClientInRealm(RealmResource realm, String clientId) {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(clientId);
        client.setName(clientId);
        client.setPublicClient(true);
        client.setServiceAccountsEnabled(false);
        client.setDirectAccessGrantsEnabled(true);
        client.setEnabled(true);
        client.setSecret("secret");
        client.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        client.setFullScopeAllowed(false);
        realm.clients().create(client).close();

        return realm.clients().findByClientId(client.getClientId()).getFirst();
    }

    private static IdentityProviderResource createIdentityProvider(RealmResource realm, String alias) {
        IdentityProviderRepresentation identityProviderRepresentation = new IdentityProviderRepresentation();
        identityProviderRepresentation.setAlias(alias);
        identityProviderRepresentation.setProviderId("oidc");
        realm.identityProviders().create(identityProviderRepresentation).close();

        return realm.identityProviders().get(alias);
    }
}
