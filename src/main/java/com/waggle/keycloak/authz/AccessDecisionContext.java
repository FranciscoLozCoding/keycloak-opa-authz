package com.waggle.keycloak.authz;

import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import com.waggle.keycloak.opa.config.ConfigWrapper;
import com.waggle.keycloak.accessmgmt.RealmResource;

public class AccessDecisionContext {

    public static final String ACTION_LOGIN = "login";

    public static final String ACTION_CHECK_ACCESS = "access";

    public static final String ACTION_MANAGE = "manage";

    private final KeycloakSession session;

    private final RealmModel realm;

    private final UserModel user;

    private final ClientModel client;

    private final RealmResource resource;

    private final String action;

    private final Policy policy;

    private final ResourcePermission resourcePermission;

    private final ConfigWrapper configOverride;

    public AccessDecisionContext(KeycloakSession session, Policy policy, ResourcePermission resourcePermission, RealmModel realm, ClientModel client, UserModel user, String action, RealmResource resource) {
        this(session, policy, resourcePermission, realm, client, user, resource, action, null);
    }

    public AccessDecisionContext(KeycloakSession session, Policy policy, ResourcePermission resourcePermission, RealmModel realm, ClientModel client, UserModel user, RealmResource resource, String action, ConfigWrapper configOverride) {
        this.session = session;
        this.realm = realm;
        this.user = user;
        this.client = client;
        this.resource = resource;
        this.action = action;
        this.configOverride = configOverride;
        this.policy = policy;
        this.resourcePermission = resourcePermission;
    }

    public RealmModel getRealm() {
        return realm;
    }

    public ClientModel getClient() {
        return client;
    }

    public UserModel getUser() {
        return user;
    }

    public KeycloakSession getSession() {
        return session;
    }

    public ConfigWrapper getConfigOverride() {
        return configOverride;
    }

    public RealmResource getResource() {
        return resource;
    }

    public String getAction() {
        return action;
    }

    public Policy getPolicy() {
        return policy;
    }

    public ResourcePermission getResourcePermission() {
        return resourcePermission;
    }
}
