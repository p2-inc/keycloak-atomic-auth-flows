package io.phasetwo.keycloak.rest;

import static org.keycloak.models.utils.RecoveryAuthnCodesUtils.NOM_ALGORITHM_TO_HASH;

import io.phasetwo.keycloak.model.AuthenticationFlowPayload;
import io.phasetwo.keycloak.model.HashObject;
import io.phasetwo.keycloak.model.IdpFlowPayload;
import io.phasetwo.keycloak.model.ImportMode;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.common.util.Base64;
import org.keycloak.deployment.DeployedConfigurationsManager;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.migration.migrators.MigrateTo8_0_0;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowBindings;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.AuthenticationExecutionExportRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.util.JsonSerialization;

@Slf4j
public class AuthenticationFlowResource {

  /**
   * Response header set in {@link ImportMode#REPLACE} mode: {@code applied} when flows were
   * written, {@code unchanged} when the payload matched what the realm already has and nothing
   * but the bindings was touched.
   */
  public static final String RESULT_HEADER = "X-Import-Result";

  public static final String RESULT_APPLIED = "applied";
  public static final String RESULT_UNCHANGED = "unchanged";

  /**
   * Realm attribute prefix under which replace mode records, per flow alias, the hash of the
   * payload that last wrote that flow. Lets an identical re-post be a true no-op.
   */
  static final String HASH_ATTRIBUTE_PREFIX = "_providerConfig.authentication-flow.hash.";

  private final KeycloakSession session;
  private final RealmModel realm;
  private final AdminPermissionEvaluator auth;
  private final ImportMode defaultMode;

  public AuthenticationFlowResource(
      KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
    this(session, realm, auth, ImportMode.VERSIONED);
  }

  public AuthenticationFlowResource(
      KeycloakSession session,
      RealmModel realm,
      AdminPermissionEvaluator auth,
      ImportMode defaultMode) {
    super();
    this.realm = realm;
    this.auth = auth;
    this.session = session;
    this.defaultMode = defaultMode;
  }

  /**
   * Imports a complete set of flows, authenticator configs and bindings in one transaction.
   *
   * @param payload the flows, configs and bindings to apply
   * @param force   versioned mode only: re-apply the bindings when the same payload was already
   *                imported instead of answering {@code 409}
   * @param mode    {@code versioned} or {@code replace}; overrides the server-wide default
   *                configured on the provider (see {@link ImportMode})
   */
  @POST
  @Path("import")
  @Produces(MediaType.APPLICATION_JSON)
  public Response importAuthenticationFlows(
      AuthenticationFlowPayload payload,
      @QueryParam("force") Boolean force,
      @QueryParam("mode") String mode) {
    auth.realm().requireManageRealm();
    ImportMode importMode;
    try {
      importMode = ImportMode.parse(mode, defaultMode);
    } catch (IllegalArgumentException e) {
      throw ErrorResponse.error("Bad request. " + e.getMessage(), Response.Status.BAD_REQUEST);
    }
    return switch (importMode) {
      case VERSIONED -> importVersioned(payload, force != null && force);
      case REPLACE -> importReplace(payload);
    };
  }

  /**
   * Versioned mode: every import creates a new hash-prefixed set of flows and configs; nothing
   * that already exists is modified. See {@link ImportMode#VERSIONED}.
   */
  private Response importVersioned(AuthenticationFlowPayload payload, boolean forceBinding) {
    String payloadHash = hashImportedFlows(payload);
    var adaptedPayload = AuthenticationFlowPayload.prefixFlows(payload, payloadHash);
    try {
      var exists = fuzzySearchByConfigs(realm, adaptedPayload);
      if (exists) {
        if (forceBinding) {
          doBindings(session, realm, adaptedPayload);
        } else {
          log.error("Flows with same configs already imported. Hash: {}", payloadHash);
          return Response.status(Response.Status.CONFLICT)
              .entity("Flows with same configs already imported. Hash: %s ".formatted(payloadHash))
              .build();
        }
      }
      if (!exists) {
        importPayload(session, realm, adaptedPayload);
      }

      if (session.getTransactionManager().isActive()) {
        session.getTransactionManager().commit();
      }
      return Response.ok().entity(adaptedPayload).build();
    } catch (BadRequestException e) {
      session.getTransactionManager().setRollbackOnly();

      log.error("Bad request.", e);
      throw ErrorResponse.error("Bad request. " + e.getMessage(), Response.Status.BAD_REQUEST);
    } catch (Exception e) {
      session.getTransactionManager().setRollbackOnly();

      log.error("Internal error. Hash: {}", payloadHash, e);
      throw ErrorResponse.error("Server error.", Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Replace mode
  // ---------------------------------------------------------------------------------------------

  /**
   * Replace mode: flows keep their plain aliases, existing flows are overwritten in place (same
   * id, new executions), missing ones are created, and an identical re-post is a no-op. See
   * {@link ImportMode#REPLACE}.
   */
  private Response importReplace(AuthenticationFlowPayload payload) {
    String payloadHash = null;
    try {
      validateReplacePayload(payload);
      // same normalisation as versioned mode, with an empty prefix: drops unknown fields and
      // ids so the hash only reflects what the import actually writes
      AuthenticationFlowPayload plain = AuthenticationFlowPayload.prefixFlows(payload, "");
      plain
          .getAuthenticatorConfig()
          .forEach(
              config -> {
                if (config.getConfig() != null) {
                  config.setConfig(new TreeMap<>(config.getConfig()));
                }
              });
      payloadHash = hashImportedFlows(plain);
      rejectBuiltInFlows(realm, plain);

      boolean unchanged = isAlreadyApplied(realm, plain, payloadHash);
      if (unchanged) {
        log.info("Flows already applied, re-applying bindings only. Hash: {}", payloadHash);
      } else {
        replaceFlows(session, realm, plain);
        recordPayloadHash(realm, plain, payloadHash);
      }
      doBindings(session, realm, plain);

      if (session.getTransactionManager().isActive()) {
        session.getTransactionManager().commit();
      }
      return Response.ok()
          .entity(plain)
          .header(RESULT_HEADER, unchanged ? RESULT_UNCHANGED : RESULT_APPLIED)
          .build();
    } catch (BadRequestException e) {
      session.getTransactionManager().setRollbackOnly();

      log.error("Bad request.", e);
      throw ErrorResponse.error("Bad request. " + e.getMessage(), Response.Status.BAD_REQUEST);
    } catch (Exception e) {
      session.getTransactionManager().setRollbackOnly();

      log.error("Internal error. Hash: {}", payloadHash, e);
      throw ErrorResponse.error("Server error.", Response.Status.INTERNAL_SERVER_ERROR);
    }
  }

  /**
   * Structural validation of a replace-mode payload, before anything is read from or written to
   * the realm. Every problem is a {@link BadRequestException}.
   */
  private static void validateReplacePayload(AuthenticationFlowPayload payload) {
    if (payload == null) {
      throw new BadRequestException("Request body is required");
    }
    if (payload.getAuthenticationFlows() == null) {
      throw new BadRequestException("authenticationFlows is required");
    }
    if (payload.getAuthenticatorConfig() == null) {
      throw new BadRequestException("authenticatorConfig is required");
    }

    Set<String> configAliases = new HashSet<>();
    for (AuthenticatorConfigRepresentation config : payload.getAuthenticatorConfig()) {
      if (config == null || config.getAlias() == null || config.getAlias().isBlank()) {
        throw new BadRequestException("Every authenticatorConfig entry needs an alias");
      }
      if (!configAliases.add(config.getAlias())) {
        throw new BadRequestException("Duplicate authenticatorConfig alias: " + config.getAlias());
      }
    }

    Set<String> flowAliases = new HashSet<>();
    for (AuthenticationFlowRepresentation flow : payload.getAuthenticationFlows()) {
      if (flow == null || flow.getAlias() == null || flow.getAlias().isBlank()) {
        throw new BadRequestException("Every authenticationFlows entry needs an alias");
      }
      if (!flowAliases.add(flow.getAlias())) {
        throw new BadRequestException("Duplicate flow alias: " + flow.getAlias());
      }
      if (flow.getAuthenticationExecutions() == null) {
        flow.setAuthenticationExecutions(new ArrayList<>());
      }
    }

    for (AuthenticationFlowRepresentation flow : payload.getAuthenticationFlows()) {
      for (AuthenticationExecutionExportRepresentation execution :
          flow.getAuthenticationExecutions()) {
        if (execution == null) {
          throw new BadRequestException(
              "Flow '%s' has a null execution".formatted(flow.getAlias()));
        }
        if (execution.isAuthenticatorFlow()) {
          if (execution.getFlowAlias() == null || !flowAliases.contains(execution.getFlowAlias())) {
            throw new BadRequestException(
                "Flow '%s' references subflow '%s' which is not in the payload"
                    .formatted(flow.getAlias(), execution.getFlowAlias()));
          }
        } else if (execution.getAuthenticator() == null || execution.getAuthenticator().isBlank()) {
          throw new BadRequestException(
              "Flow '%s' has an execution without an authenticator".formatted(flow.getAlias()));
        }
        if (execution.getAuthenticatorConfig() != null
            && !configAliases.contains(execution.getAuthenticatorConfig())) {
          throw new BadRequestException(
              "Flow '%s' references authenticatorConfig '%s' which is not in the payload"
                  .formatted(flow.getAlias(), execution.getAuthenticatorConfig()));
        }
        if (execution.getRequirement() == null) {
          throw new BadRequestException(
              "Flow '%s' has an execution without a requirement".formatted(flow.getAlias()));
        }
        try {
          AuthenticationExecutionModel.Requirement.valueOf(execution.getRequirement());
        } catch (IllegalArgumentException e) {
          if (!"OPTIONAL".equals(execution.getRequirement())) {
            throw new BadRequestException(
                "Flow '%s' has an execution with unknown requirement '%s'"
                    .formatted(flow.getAlias(), execution.getRequirement()));
          }
        }
      }
    }
  }

  /** Replace mode never touches built-in flows; a payload naming one is rejected as a whole. */
  private static void rejectBuiltInFlows(RealmModel realm, AuthenticationFlowPayload payload) {
    for (AuthenticationFlowRepresentation flow : payload.getAuthenticationFlows()) {
      AuthenticationFlowModel existing = realm.getFlowByAlias(flow.getAlias());
      if (existing != null && existing.isBuiltIn()) {
        throw new BadRequestException("Built-in flow cannot be replaced: " + flow.getAlias());
      }
    }
  }

  /**
   * True when every flow and config in the payload exists and every flow was last written by a
   * payload with the same hash. Flows edited through other channels (console, admin API) are not
   * detected; re-posting after such an edit still reports {@code unchanged}.
   */
  private static boolean isAlreadyApplied(
      RealmModel realm, AuthenticationFlowPayload payload, String payloadHash) {
    if (payload.getAuthenticationFlows().isEmpty()) {
      return false;
    }
    boolean configsExist =
        payload.getAuthenticatorConfig().stream()
            .allMatch(config -> realm.getAuthenticatorConfigByAlias(config.getAlias()) != null);
    boolean flowsExist =
        payload.getAuthenticationFlows().stream()
            .allMatch(flow -> realm.getFlowByAlias(flow.getAlias()) != null);
    boolean hashesMatch =
        payload.getAuthenticationFlows().stream()
            .allMatch(
                flow -> payloadHash.equals(realm.getAttribute(hashAttributeKey(flow.getAlias()))));
    return configsExist && flowsExist && hashesMatch;
  }

  private static void recordPayloadHash(
      RealmModel realm, AuthenticationFlowPayload payload, String payloadHash) {
    for (AuthenticationFlowRepresentation flow : payload.getAuthenticationFlows()) {
      realm.setAttribute(hashAttributeKey(flow.getAlias()), payloadHash);
    }
  }

  /** Attribute names are capped at 255 characters and so are aliases, hence the alias is hashed. */
  static String hashAttributeKey(String flowAlias) {
    return HASH_ATTRIBUTE_PREFIX
        + UUID.nameUUIDFromBytes(flowAlias.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Upserts the configs by alias, then for every flow in the payload keeps (or creates) the flow
   * row and rebuilds its executions from the payload. Flow ids are stable across replaces, so
   * bindings made outside this payload keep resolving. Subflows that hung off a replaced flow but
   * are not in the payload are deleted; configs are never deleted because other flows may share
   * them.
   */
  private void replaceFlows(
      KeycloakSession session, RealmModel realm, AuthenticationFlowPayload payload) {
    for (AuthenticatorConfigRepresentation configRep : payload.getAuthenticatorConfig()) {
      AuthenticatorConfigModel existing = realm.getAuthenticatorConfigByAlias(configRep.getAlias());
      if (existing == null) {
        realm.addAuthenticatorConfig(RepresentationToModel.toModel(configRep));
      } else {
        existing.setConfig(
            configRep.getConfig() == null ? new HashMap<>() : new HashMap<>(configRep.getConfig()));
        realm.updateAuthenticatorConfig(existing);
      }
    }

    Set<String> payloadAliases = new HashSet<>();
    payload.getAuthenticationFlows().forEach(flow -> payloadAliases.add(flow.getAlias()));

    for (AuthenticationFlowRepresentation flowRep : payload.getAuthenticationFlows()) {
      AuthenticationFlowModel existing = realm.getFlowByAlias(flowRep.getAlias());
      if (existing == null) {
        AuthenticationFlowModel model = RepresentationToModel.toModel(flowRep);
        model.setBuiltIn(false);
        realm.addAuthenticationFlow(model);
      } else {
        clearFlow(realm, existing, payloadAliases);
        existing.setDescription(flowRep.getDescription());
        existing.setProviderId(flowRep.getProviderId());
        existing.setTopLevel(flowRep.isTopLevel());
        existing.setBuiltIn(false);
        realm.updateAuthenticationFlow(existing);
      }
    }

    for (AuthenticationFlowRepresentation flowRep : payload.getAuthenticationFlows()) {
      AuthenticationFlowModel model = realm.getFlowByAlias(flowRep.getAlias());
      for (AuthenticationExecutionExportRepresentation exeRep :
          flowRep.getAuthenticationExecutions()) {
        realm.addAuthenticatorExecution(toModel(session, realm, model, exeRep));
      }
    }
  }

  /**
   * Removes every execution of {@code flow}. A subflow reached through one of them is deleted
   * recursively unless its alias is in {@code keepAliases} (it is in the payload and will be
   * rebuilt under its own entry); the flow row itself is always kept.
   */
  private static void clearFlow(
      RealmModel realm, AuthenticationFlowModel flow, Set<String> keepAliases) {
    List<AuthenticationExecutionModel> executions =
        realm.getAuthenticationExecutionsStream(flow.getId()).toList();
    for (AuthenticationExecutionModel execution : executions) {
      if (execution.isAuthenticatorFlow() && execution.getFlowId() != null) {
        AuthenticationFlowModel subflow = realm.getAuthenticationFlowById(execution.getFlowId());
        if (subflow != null && !keepAliases.contains(subflow.getAlias())) {
          clearFlow(realm, subflow, keepAliases);
          realm.removeAuthenticationFlow(subflow);
        }
      }
      realm.removeAuthenticatorExecution(execution);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Versioned mode helpers
  // ---------------------------------------------------------------------------------------------

  /**
   * Performs a "fuzzy" search to determine if all authentication configurations and flows
   * specified in the {@code adaptedPayload} already exist within the provided {@code realm}.
   * This presumes the flow is no longer modified outside this request
   *
   * @param realm          - the keycloak realm
   * @param adaptedPayload The {@link AuthenticationFlowPayload} containing the authenticator configurations
   *                       and authentication flows with specific hash.
   */
  private boolean fuzzySearchByConfigs(RealmModel realm, AuthenticationFlowPayload adaptedPayload) {
    return adaptedPayload.getAuthenticatorConfig().stream()
            .allMatch(config -> realm.getAuthenticatorConfigByAlias(config.getAlias()) != null)
        && adaptedPayload.getAuthenticationFlows().stream()
            .allMatch(flow -> realm.getFlowByAlias(flow.getAlias()) != null);
  }

  private void importPayload(
      KeycloakSession session, RealmModel realm, AuthenticationFlowPayload payload) {

    if (payload.getAuthenticatorConfig() != null) {
      for (AuthenticatorConfigRepresentation configRep : payload.getAuthenticatorConfig()) {
        AuthenticatorConfigModel model = RepresentationToModel.toModel(configRep);
        realm.addAuthenticatorConfig(model);
      }
    }
    if (payload.getAuthenticationFlows() != null) {
      for (AuthenticationFlowRepresentation flowRep : payload.getAuthenticationFlows()) {
        AuthenticationFlowModel model = RepresentationToModel.toModel(flowRep);
        realm.addAuthenticationFlow(model);
      }
      for (AuthenticationFlowRepresentation flowRep : payload.getAuthenticationFlows()) {
        AuthenticationFlowModel model = realm.getFlowByAlias(flowRep.getAlias());
        for (AuthenticationExecutionExportRepresentation exeRep :
            flowRep.getAuthenticationExecutions()) {
          AuthenticationExecutionModel execution = toModel(session, realm, model, exeRep);
          realm.addAuthenticatorExecution(execution);
        }
      }
    }

    doBindings(session, realm, payload);
  }

  private static void doBindings(
      KeycloakSession session, RealmModel realm, AuthenticationFlowPayload payload) {
    if (payload.getBrowserFlowBinding() != null) {
      var model = realm.getFlowByAlias(payload.getBrowserFlowBinding());
      if (model == null) {
        log.debug("Missing flow with name: {}", payload.getBrowserFlowBinding());
        throw new BadRequestException("Missing flow with name: " + payload.getBrowserFlowBinding());
      }
      realm.setBrowserFlow(model);
    }

    if (payload.getIdpFlowBindings() != null) {
      payload
          .getIdpFlowBindings()
          .forEach(idpFlowPayload -> bindIdpFlows(session, realm, idpFlowPayload));
    }

    if (payload.getClientFlowBinding() != null
        && payload.getClientFlowBinding().getClientId() != null) {
      String clientId = payload.getClientFlowBinding().getClientId();
      ClientModel model = realm.getClientByClientId(clientId);
      if (model == null) {
        log.debug("Missing client with id: {}", clientId);
        throw new BadRequestException("Missing client with id: " + clientId);
      }

      String browserFlowBinding = payload.getClientFlowBinding().getBrowserFlowBinding();
      if (browserFlowBinding != null) {
        AuthenticationFlowModel browserAuthenticationFlowModel =
            realm.getFlowByAlias(browserFlowBinding);
        if (browserAuthenticationFlowModel == null) {
          log.debug("Missing client browserFlow binding: {}", browserFlowBinding);
          throw new BadRequestException(
              "Cannot find client browserFlow binding: " + browserFlowBinding);
        }
        model.setAuthenticationFlowBindingOverride(
            AuthenticationFlowBindings.BROWSER_BINDING, browserAuthenticationFlowModel.getId());
      }

      String directFlowBinding = payload.getClientFlowBinding().getDirectFlowBinding();
      if (directFlowBinding != null) {
        AuthenticationFlowModel directAuthenticationFlowModel =
            realm.getFlowByAlias(directFlowBinding);
        if (directAuthenticationFlowModel == null) {
          log.debug("Missing client directFlow binding: {}", directFlowBinding);
          throw new BadRequestException(
              "Cannot find client directFlow binding: " + directFlowBinding);
        }
        model.setAuthenticationFlowBindingOverride(
            AuthenticationFlowBindings.DIRECT_GRANT_BINDING, directAuthenticationFlowModel.getId());
      }
    }
  }

  private static void bindIdpFlows(
      KeycloakSession session, RealmModel realm, IdpFlowPayload idpFlowPayload) {
    String alias = idpFlowPayload.getAlias();
    IdentityProviderModel model = session.identityProviders().getByAlias(alias);
    if (model == null) {
      log.debug("Missing identity provider with alias: {}", alias);
      throw new BadRequestException("Missing identity provider with alias: " + alias);
    }

    String firstLoginFlowBinding = idpFlowPayload.getFirstLoginFlowBinding();
    if (firstLoginFlowBinding != null) {
      AuthenticationFlowModel firstBrokerAuthenticationFlowModel =
          realm.getFlowByAlias(firstLoginFlowBinding);
      if (firstBrokerAuthenticationFlowModel == null) {
        log.debug("Missing firstBrokerFlow binding: {}", firstLoginFlowBinding);
        throw new BadRequestException(
            "Cannot find firstBrokerFlow binding: " + firstLoginFlowBinding);
      }
      model.setFirstBrokerLoginFlowId(firstBrokerAuthenticationFlowModel.getId());
      session.identityProviders().update(model);
    }

    String postLoginFlowBinding = idpFlowPayload.getPostLoginFlowBinding();
    if (postLoginFlowBinding != null) {
      AuthenticationFlowModel postBrokerAuthenticationFlowModel =
          realm.getFlowByAlias(postLoginFlowBinding);
      if (postBrokerAuthenticationFlowModel == null) {
        log.debug("Missing postBrokerFlow binding: {}", postLoginFlowBinding);
        throw new BadRequestException(
            "Cannot find postBrokerFlow binding: " + postLoginFlowBinding);
      }
      model.setPostBrokerLoginFlowId(postBrokerAuthenticationFlowModel.getId());
      session.identityProviders().update(model);
    }
  }

  private AuthenticationExecutionModel toModel(
      KeycloakSession session,
      RealmModel realm,
      AuthenticationFlowModel parentFlow,
      AuthenticationExecutionExportRepresentation rep) {
    AuthenticationExecutionModel model = new AuthenticationExecutionModel();
    if (rep.getAuthenticatorConfig() != null) {
      AuthenticatorConfigModel config =
          new DeployedConfigurationsManager(session)
              .getAuthenticatorConfigByAlias(realm, rep.getAuthenticatorConfig());
      model.setAuthenticatorConfig(config.getId());
    }
    model.setAuthenticator(rep.getAuthenticator());
    model.setAuthenticatorFlow(rep.isAuthenticatorFlow());
    if (rep.getFlowAlias() != null) {
      AuthenticationFlowModel flow = realm.getFlowByAlias(rep.getFlowAlias());
      model.setFlowId(flow.getId());
    }
    if (rep.getPriority() != null) {
      model.setPriority(rep.getPriority());
    }
    try {
      model.setRequirement(AuthenticationExecutionModel.Requirement.valueOf(rep.getRequirement()));
      model.setParentFlow(parentFlow.getId());
    } catch (IllegalArgumentException iae) {
      // retro-compatible for previous OPTIONAL being changed to CONDITIONAL
      if ("OPTIONAL".equals(rep.getRequirement())) {
        MigrateTo8_0_0.migrateOptionalAuthenticationExecution(realm, parentFlow, model, false);
      }
    }
    return model;
  }

  public static String hashImportedFlows(AuthenticationFlowPayload payload) {
    Objects.requireNonNull(payload, "rawGeneratedCode cannot be null");

    //       //The hash will contain only the flows and the configs
    HashObject hashObject = new HashObject();
    hashObject.setAuthenticationFlows(payload.getAuthenticationFlows());
    hashObject.setAuthenticatorConfig(payload.getAuthenticatorConfig());

    String payloadJson;
    try {
      payloadJson = JsonSerialization.writeValueAsString(hashObject);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    // NOM_ALGORITHM_TO_HASH is already a JCA digest name ("SHA-512"), which HashUtils.hash
    // passes straight to MessageDigest.getInstance(...). Do NOT route it through
    // JavaAlgorithm.getJavaAlgorithmForHash(), which expects a JWS signature alg (RS512/HS512/…)
    // and throws "Unknown algorithm SHA-512" for a raw digest name.
    byte[] rawCodeHashedAsBytes =
        HashUtils.hash(NOM_ALGORITHM_TO_HASH, payloadJson.getBytes(StandardCharsets.UTF_8));

    var encodedString =
        Base64.encodeBytes(
            rawCodeHashedAsBytes,
            0,
            10); // we might get a error if the length is larger than the database field accepts
    var encodedStringWithoutPadding = encodedString.replaceAll("=+$", ""); // remove padding

    return encodedStringWithoutPadding + "-";
  }
}
