package com.waggle.keycloak.authz;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.policy.provider.PolicyProviderAdminService;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;


public interface PolicyProviderFactory<R extends AbstractPolicyRepresentation> extends ProviderFactory<AccessPolicyProvider> {
    String getName();

    String getGroup();

    default boolean isInternal() {
        return false;
    }

    AccessPolicyProvider create(AuthorizationProvider authorization);

    R toRepresentation(Policy policy, AuthorizationProvider authorization);

    Class<R> getRepresentationType();

    default void onCreate(Policy policy, R representation, AuthorizationProvider authorization) {

    }

    default void onUpdate(Policy policy, R representation, AuthorizationProvider authorization) {

    }

    default void onRemove(Policy policy, AuthorizationProvider authorization) {

    }

    default void onImport(Policy policy, PolicyRepresentation representation, AuthorizationProvider authorization) {

    }

    default void onExport(Policy policy, PolicyRepresentation representation, AuthorizationProvider authorizationProvider) {
    }

    default PolicyProviderAdminService getAdminResource(ResourceServer resourceServer, AuthorizationProvider authorization) {
        return null;
    }
}