package io.phasetwo.keycloak.model;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class ClientFlowPayload {
    private String clientId;
    private String browserFlowBinding;
    private String directFlowBinding;
}
