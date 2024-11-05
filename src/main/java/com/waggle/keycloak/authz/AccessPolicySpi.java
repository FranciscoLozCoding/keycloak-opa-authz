package com.waggle.keycloak.authz;

import com.google.auto.service.AutoService;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

@AutoService(Spi.class)
public class AccessPolicySpi implements Spi {

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "authzAccessPolicy";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return AccessPolicyProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory<?>> getProviderFactoryClass() {
        return AccessPolicyProviderFactory.class;
    }
}
