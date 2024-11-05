package com.waggle.keycloak.opa.client;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class OpaPolicyQuery {

    private OpaSubject subject;

    private OpaResource resource;

    private OpaRequestContext context;

    private String action;
}
