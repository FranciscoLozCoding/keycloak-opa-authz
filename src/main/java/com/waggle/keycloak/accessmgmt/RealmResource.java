package com.waggle.keycloak.accessmgmt;

import lombok.Builder;
import lombok.Data;

import java.util.Set;
import java.util.Map;

@Data
@Builder
public class RealmResource {

    private String id;

    private String type;

    private String path;

    private String name;

    private Set<String> scopes;

    private Map<String, Object> attributes;
}
