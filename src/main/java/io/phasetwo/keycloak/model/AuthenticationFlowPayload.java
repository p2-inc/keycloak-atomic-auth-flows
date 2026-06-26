package io.phasetwo.keycloak.model;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.keycloak.representations.idm.AuthenticationExecutionExportRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;

import javax.annotation.Nullable;
import java.util.List;

@Getter
@Setter
public class AuthenticationFlowPayload {

    @NotNull
    private List<AuthenticationFlowRepresentation> authenticationFlows;
    @NotNull
    private List<AuthenticatorConfigRepresentation> authenticatorConfig;

    @Nullable
    private String browserFlowBinding;
    @Nullable
    private ClientFlowPayload clientFlowBinding;
    @Nullable
    private List<IdpFlowPayload> idpFlowBindings;

    public static AuthenticationFlowPayload prefixFlows(AuthenticationFlowPayload requestPayload,
                                                        String prefix) {
        AuthenticationFlowPayload payload = new AuthenticationFlowPayload();
        //clone authentication flows
        var clonedAuthenticationFlows = requestPayload.getAuthenticationFlows()
                .stream()
                .map(authenticationFlowRepresentation -> {
                    var clone = new AuthenticationFlowRepresentation();
                    clone.setAlias(prefix + authenticationFlowRepresentation.getAlias());
                    clone.setDescription(authenticationFlowRepresentation.getDescription());
                    clone.setProviderId(authenticationFlowRepresentation.getProviderId());
                    clone.setBuiltIn(authenticationFlowRepresentation.isBuiltIn());
                    clone.setTopLevel(authenticationFlowRepresentation.isTopLevel());
                    var listExecutions = authenticationFlowRepresentation.getAuthenticationExecutions()
                            .stream()
                            .map(authenticationExecutionExportRepresentation ->
                            {
                                var cloneExecution = new AuthenticationExecutionExportRepresentation();
                                if (authenticationExecutionExportRepresentation != null && authenticationExecutionExportRepresentation.isAuthenticatorFlow()) {
                                    cloneExecution.setFlowAlias(prefix + authenticationExecutionExportRepresentation.getFlowAlias());
                                }
                                cloneExecution.setAuthenticator(authenticationExecutionExportRepresentation.getAuthenticator());
                                if (authenticationExecutionExportRepresentation.getAuthenticatorConfig() != null) {
                                    cloneExecution.setAuthenticatorConfig(prefix + authenticationExecutionExportRepresentation.getAuthenticatorConfig());
                                }
                                cloneExecution.setAuthenticatorFlow(authenticationExecutionExportRepresentation.isAuthenticatorFlow());
                                cloneExecution.setPriority(authenticationExecutionExportRepresentation.getPriority());
                                cloneExecution.setUserSetupAllowed(authenticationExecutionExportRepresentation.isUserSetupAllowed());
                                cloneExecution.setRequirement(authenticationExecutionExportRepresentation.getRequirement());

                                return cloneExecution;
                            })
                            .toList();
                    clone.setAuthenticationExecutions(listExecutions);
                    return clone;
                })
                .toList();
        payload.setAuthenticationFlows(clonedAuthenticationFlows);

        //clone config list
        var configList = requestPayload.getAuthenticatorConfig()
                .stream()
                .map(authenticatorConfigRepresentation -> {
                    var cloneAuthenticatorConfigRepresentation = new AuthenticatorConfigRepresentation();
                    cloneAuthenticatorConfigRepresentation.setAlias(prefix + authenticatorConfigRepresentation.getAlias());
                    cloneAuthenticatorConfigRepresentation.setConfig(authenticatorConfigRepresentation.getConfig());

                    return cloneAuthenticatorConfigRepresentation;
                })
                .toList();
        payload.setAuthenticatorConfig(configList);

        //clone flow binding if exists
        if (requestPayload.getBrowserFlowBinding() != null) {
            payload.setBrowserFlowBinding(prefix + requestPayload.getBrowserFlowBinding());
        }

        //clone client binding if exists
        if (requestPayload.getClientFlowBinding() != null) {
            var clientFlowPayloadClone = cloneClientFlowPayload(requestPayload, prefix);
            payload.setClientFlowBinding(clientFlowPayloadClone);
        }

        //clone idps binding if exists
        if (requestPayload.getIdpFlowBindings() != null) {
            var idpFlowPayloadsClone =
                    requestPayload.getIdpFlowBindings()
                            .stream()
                            .map(idpFlowPayload -> cloneIdpFlowPayloads(idpFlowPayload, prefix))
                            .toList();
            payload.setIdpFlowBindings(idpFlowPayloadsClone);
        }

        return payload;
    }

    @NotNull
    private static IdpFlowPayload cloneIdpFlowPayloads(IdpFlowPayload requestPayload, String prefix) {
        var idpFlowPayloadClone = new IdpFlowPayload();
        if (requestPayload.getAlias() != null) {
            idpFlowPayloadClone.setAlias(requestPayload.getAlias());
        }
        if (requestPayload.getFirstLoginFlowBinding() != null) {
            idpFlowPayloadClone.setFirstLoginFlowBinding(prefix + requestPayload.getFirstLoginFlowBinding());
        }
        if (requestPayload.getPostLoginFlowBinding() != null) {
            idpFlowPayloadClone.setPostLoginFlowBinding(prefix + requestPayload.getPostLoginFlowBinding());
        }
        return idpFlowPayloadClone;
    }

    @NotNull
    private static ClientFlowPayload cloneClientFlowPayload(AuthenticationFlowPayload requestPayload, String prefix) {
        var clientFlowPayloadClone = new ClientFlowPayload();
        if (requestPayload.getClientFlowBinding().getBrowserFlowBinding() != null) {
            clientFlowPayloadClone.setBrowserFlowBinding(prefix + requestPayload.getClientFlowBinding().getBrowserFlowBinding());
        }
        if (requestPayload.getClientFlowBinding().getDirectFlowBinding() != null) {
            clientFlowPayloadClone.setDirectFlowBinding(prefix + requestPayload.getClientFlowBinding().getDirectFlowBinding());
        }
        if (requestPayload.getClientFlowBinding().getClientId() != null) {
            clientFlowPayloadClone.setClientId(requestPayload.getClientFlowBinding().getClientId());
        }
        return clientFlowPayloadClone;
    }
}
