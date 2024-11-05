package com.waggle.keycloak.opa.authzservices;

import java.util.HashMap;
import java.util.Map;

import org.keycloak.Config;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Policy;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;

import com.google.auto.service.AutoService;
import com.waggle.keycloak.authz.AccessPolicyProvider;
// import com.waggle.keycloak.authz.PolicyProviderFactory;
import org.keycloak.authorization.policy.provider.PolicyProviderFactory;
import org.keycloak.authorization.policy.provider.PolicyProvider;

@AutoService(PolicyProviderFactory.class)
public class OpaPolicyProviderFactory implements PolicyProviderFactory<OpaPolicyRepresentation> {

    // private Map<String, String> config;
    private OpaPolicyProvider provider = new OpaPolicyProvider(this::toRepresentation);

    @Override
    public String getId() {
        return OpaPolicyProvider.ID;
    }

    @Override
    public String getName() {
        return "Open Policy Agent";
    }

    @Override
    public String getGroup() {
        return "OPA Based";
    }

    @Override
    public PolicyProvider create(KeycloakSession session) {
        // return new OpaPolicyProvider(config);
        return null;
    }

    @Override
    public PolicyProvider create(AuthorizationProvider authorization) {
        // return new OpaPolicyProvider(config);
        return provider;
    }

    @Override
    public void init(Config.Scope scope) {
        // this.config = readConfig(scope);
    }

    protected Map<String, String> readConfig(Config.Scope scope) {
        Map<String, String> config = new HashMap<>();
        for (var option : OpaPolicyProvider.Option.values()) {
            config.put(option.getKey(), scope.get(option.getKey()));
        }
        return config;
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void onCreate(Policy policy, OpaPolicyRepresentation representation, AuthorizationProvider authorization) {
        updatePolicy(policy, representation);
    }

    @Override
    public void onUpdate(Policy policy, OpaPolicyRepresentation representation, AuthorizationProvider authorization) {
        updatePolicy(policy, representation);
    }

    @Override
    public void onRemove(Policy policy, AuthorizationProvider authorization) {
    }

    @Override
    public void onImport(Policy policy, PolicyRepresentation representation, AuthorizationProvider authorization) {
        policy.setConfig(representation.getConfig());
    }

    @Override
    public Class<OpaPolicyRepresentation> getRepresentationType() {
        return OpaPolicyRepresentation.class;
    }

    @Override
    public OpaPolicyRepresentation toRepresentation(Policy policy, AuthorizationProvider authorization) {
        OpaPolicyRepresentation representation = new OpaPolicyRepresentation();
        Map<String, String> config = policy.getConfig();

        representation.setOpaUrl(config.get("opaUrl"));
        representation.setPolicyPath(config.get("policyPath"));
        representation.setOpaUrl(config.get("requestHeaders"));
        
        return representation;
    }

    @Override
    public void close() {

    }

    private void updatePolicy(Policy policy, OpaPolicyRepresentation representation) {
        Map<String, String> config = new HashMap(policy.getConfig());

        config.compute("opaUrl", (s, s2) -> representation.getOpaUrl() != null ? representation.getOpaUrl() : null);
        config.compute("policyPath", (s, s2) -> representation.getPolicyPath() != null ? representation.getPolicyPath() : null);
        config.compute("requestHeaders", (s, s2) -> representation.getPolicyPath() != null ? representation.getPolicyPath() : null);

        policy.setConfig(config);
    }
}