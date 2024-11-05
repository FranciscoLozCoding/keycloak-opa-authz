package com.waggle.keycloak.opa.authzservices;

import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OpaPolicyRepresentation extends AbstractPolicyRepresentation {

    private String opaUrl; // URL of OPA Authz Server Resource
    private String policyPath; // Path of OPA policy relative to Authz Server URL
    private String requestHeaders;

    @Override
    public String getType() {
        return "opa-policy-provider";
    }
}
