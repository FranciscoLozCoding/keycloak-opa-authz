package com.waggle.keycloak.authz;

// import org.keycloak.provider.Provider;
import com.waggle.keycloak.accessmgmt.AccessDecision;
import org.keycloak.authorization.policy.provider.PolicyProvider;

public interface AccessPolicyProvider extends PolicyProvider {

    AccessDecision evaluate(AccessDecisionContext context);

    default void close() {
    }
}
