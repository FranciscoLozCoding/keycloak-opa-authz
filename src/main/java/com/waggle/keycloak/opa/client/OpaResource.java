package com.waggle.keycloak.opa.client;

import lombok.Builder;
import lombok.Data;

import java.util.Map;
import java.util.Set;
import java.util.List;

@Data
@Builder
public class OpaResource {

    private String realm;

    private Map<String, Object> realmAttributes;

    private String clientId;

    private Map<String, Object> clientAttributes;

    private String RealmResourceId;

    private String RealmResourceType;

    private String RealmResourcePath;

    private String RealmResourceName;

    private Set<String> RealmResourceScopes;

    private Map<String, Object>  resourceAttributes;
}
