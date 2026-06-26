package io.phasetwo.keycloak.model;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class IdpFlowPayload {
    private String alias;
    private String firstLoginFlowBinding;
    private String postLoginFlowBinding;
}
