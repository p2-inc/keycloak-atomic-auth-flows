package io.phasetwo.keycloak.model;

import lombok.Getter;
import lombok.Setter;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;

import java.util.List;

@Getter
@Setter
public class HashObject {

    private List<AuthenticationFlowRepresentation> authenticationFlows;
    private List<AuthenticatorConfigRepresentation> authenticatorConfig;
}
