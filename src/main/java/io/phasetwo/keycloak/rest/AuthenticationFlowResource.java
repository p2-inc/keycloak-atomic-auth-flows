package io.phasetwo.keycloak.rest;

import io.phasetwo.keycloak.model.AuthenticationFlowPayload;
import io.phasetwo.keycloak.model.HashObject;
import io.phasetwo.keycloak.model.IdpFlowPayload;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.common.util.Base64;
import org.keycloak.deployment.DeployedConfigurationsManager;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.migration.migrators.MigrateTo8_0_0;
import org.keycloak.models.*;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.AuthenticationExecutionExportRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static org.keycloak.models.utils.RecoveryAuthnCodesUtils.NOM_ALGORITHM_TO_HASH;

@Slf4j
public class AuthenticationFlowResource {

    private final KeycloakSession session;
    private final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public AuthenticationFlowResource(KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth) {
        super();
        this.realm = realm;
        this.auth = auth;
        this.session = session;
    }

    @POST
    @Path("import")
    @Produces(MediaType.APPLICATION_JSON)
    public Response importAuthenticationFlows(AuthenticationFlowPayload payload,
                                              @QueryParam("force") Boolean force) {
        auth.realm().requireManageRealm();
        boolean forceBinding = force != null && force;
        String payloadHash = hashImportedFlows(payload);
        var adaptedPayload = AuthenticationFlowPayload.prefixFlows(payload, payloadHash);
        try {
            var exists = fuzzySearchByConfigs(realm, adaptedPayload);
            if (exists) {
                if (forceBinding) {
                    doBindings(session, realm, adaptedPayload);
                } else {
                    log.error("Flows with same configs already imported. Hash: {}", payloadHash);
                    return Response
                            .status(Response.Status.CONFLICT)
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

    /**
     * Performs a "fuzzy" search to determine if all authentication configurations and flows
     * specified in the {@code adaptedPayload} already exist within the provided {@code realm}.
     * This presumes the flow is no longer modified outside this request
     *
     * @param realm          - the keycloak realm
     * @param adaptedPayload The {@link AuthenticationFlowPayload} containing the authenticator configurations
     *                       and authentication flows with specific hash.
     */
    private boolean fuzzySearchByConfigs(RealmModel realm,
                                         AuthenticationFlowPayload adaptedPayload) {
        return adaptedPayload.getAuthenticatorConfig()
                .stream()
                .allMatch(config -> realm.getAuthenticatorConfigByAlias(config.getAlias()) != null)
                && adaptedPayload.getAuthenticationFlows()
                .stream()
                .allMatch(flow -> realm.getFlowByAlias(flow.getAlias()) != null);
    }

    private void importPayload(KeycloakSession session,
                               RealmModel realm,
                               AuthenticationFlowPayload payload) {

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
                for (AuthenticationExecutionExportRepresentation exeRep : flowRep.getAuthenticationExecutions()) {
                    AuthenticationExecutionModel execution = toModel(session, realm, model, exeRep);
                    realm.addAuthenticatorExecution(execution);
                }
            }
        }

        doBindings(session, realm, payload);
    }

    private static void doBindings(KeycloakSession session, RealmModel realm, AuthenticationFlowPayload payload) {
        if (payload.getBrowserFlowBinding() != null) {
            var model = realm.getFlowByAlias(payload.getBrowserFlowBinding());
            if (model == null) {
                log.debug("Missing flow with name: {}", payload.getBrowserFlowBinding());
                throw new BadRequestException("Missing flow with name: " + payload.getBrowserFlowBinding());
            }
            realm.setBrowserFlow(model);
        }

        if (payload.getIdpFlowBindings() != null) {
            payload.getIdpFlowBindings()
                    .forEach(idpFlowPayload -> bindIdpFlows(session, realm, idpFlowPayload));
        }

        if (payload.getClientFlowBinding() != null && payload.getClientFlowBinding().getClientId() != null) {
            String clientId = payload.getClientFlowBinding().getClientId();
            ClientModel model = realm.getClientByClientId(clientId);
            if (model == null) {
                log.debug("Missing client with id: {}", clientId);
                throw new BadRequestException("Missing client with id: " + clientId);
            }

            String browserFlowBinding = payload.getClientFlowBinding().getBrowserFlowBinding();
            if (browserFlowBinding != null) {
                AuthenticationFlowModel browserAuthenticationFlowModel = realm.getFlowByAlias(browserFlowBinding);
                if (browserAuthenticationFlowModel == null) {
                    log.debug("Missing client browserFlow binding: {}", browserFlowBinding);
                    throw new BadRequestException("Cannot find client browserFlow binding: " + browserFlowBinding);
                }
                model.setAuthenticationFlowBindingOverride(AuthenticationFlowBindings.BROWSER_BINDING, browserAuthenticationFlowModel.getId());
            }

            String directFlowBinding = payload.getClientFlowBinding().getDirectFlowBinding();
            if (directFlowBinding != null) {
                AuthenticationFlowModel directAuthenticationFlowModel = realm.getFlowByAlias(directFlowBinding);
                if (directAuthenticationFlowModel == null) {
                    log.debug("Missing client directFlow binding: {}", directFlowBinding);
                    throw new BadRequestException("Cannot find client directFlow binding: " + directFlowBinding);
                }
                model.setAuthenticationFlowBindingOverride(AuthenticationFlowBindings.DIRECT_GRANT_BINDING, directAuthenticationFlowModel.getId());
            }
        }
    }

    private static void bindIdpFlows(KeycloakSession session, RealmModel realm, IdpFlowPayload idpFlowPayload) {
        String alias = idpFlowPayload.getAlias();
        IdentityProviderModel model = session.identityProviders().getByAlias(alias);
        if (model == null) {
            log.debug("Missing identity provider with alias: {}", alias);
            throw new BadRequestException("Missing identity provider with alias: " + alias);
        }

        String firstLoginFlowBinding = idpFlowPayload.getFirstLoginFlowBinding();
        if (firstLoginFlowBinding != null) {
            AuthenticationFlowModel firstBrokerAuthenticationFlowModel = realm.getFlowByAlias(firstLoginFlowBinding);
            if (firstBrokerAuthenticationFlowModel == null) {
                log.debug("Missing firstBrokerFlow binding: {}", firstLoginFlowBinding);
                throw new BadRequestException("Cannot find firstBrokerFlow binding: " + firstLoginFlowBinding);
            }
            model.setFirstBrokerLoginFlowId(firstBrokerAuthenticationFlowModel.getId());
            session.identityProviders().update(model);
        }

        String postLoginFlowBinding = idpFlowPayload.getPostLoginFlowBinding();
        if (postLoginFlowBinding != null) {
            AuthenticationFlowModel postBrokerAuthenticationFlowModel = realm.getFlowByAlias(postLoginFlowBinding);
            if (postBrokerAuthenticationFlowModel == null) {
                log.debug("Missing postBrokerFlow binding: {}", postLoginFlowBinding);
                throw new BadRequestException("Cannot find postBrokerFlow binding: " + postLoginFlowBinding);
            }
            model.setPostBrokerLoginFlowId(postBrokerAuthenticationFlowModel.getId());
            session.identityProviders().update(model);
        }
    }


    private AuthenticationExecutionModel toModel(KeycloakSession session, RealmModel realm, AuthenticationFlowModel parentFlow, AuthenticationExecutionExportRepresentation rep) {
        AuthenticationExecutionModel model = new AuthenticationExecutionModel();
        if (rep.getAuthenticatorConfig() != null) {
            AuthenticatorConfigModel config = new DeployedConfigurationsManager(session).getAuthenticatorConfigByAlias(realm, rep.getAuthenticatorConfig());
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
            //retro-compatible for previous OPTIONAL being changed to CONDITIONAL
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
        byte[] rawCodeHashedAsBytes = HashUtils.hash(NOM_ALGORITHM_TO_HASH,
                payloadJson.getBytes(StandardCharsets.UTF_8));

        var encodedString = Base64.encodeBytes(rawCodeHashedAsBytes, 0, 10);// we might get a error if the length is larger than the database field accepts
        var encodedStringWithoutPadding = encodedString.replaceAll("=+$", "");//remove padding

        return encodedStringWithoutPadding + "-";
    }
}
