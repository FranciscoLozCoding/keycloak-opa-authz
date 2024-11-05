package com.waggle.keycloak.opa.authzservices;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.policy.evaluation.Evaluation;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.RoleUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.utils.StringUtil;

import com.waggle.keycloak.accessmgmt.AccessDecision;
import com.waggle.keycloak.accessmgmt.RealmResource;
import com.waggle.keycloak.authz.AccessDecisionContext;
import com.waggle.keycloak.authz.AccessPolicyProvider;
import com.waggle.keycloak.opa.client.OpaClient;
import com.waggle.keycloak.opa.client.OpaPolicyQuery;
import com.waggle.keycloak.opa.client.OpaRequestContext;
import com.waggle.keycloak.opa.client.OpaResource;
import com.waggle.keycloak.opa.client.OpaResponse;
import com.waggle.keycloak.opa.client.OpaSubject;
import com.waggle.keycloak.opa.config.ClientConfig;
import com.waggle.keycloak.opa.config.ConfigWrapper;
import com.waggle.keycloak.opa.config.RealmConfig;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriBuilder;
import lombok.Getter;

public class OpaPolicyProvider implements AccessPolicyProvider {

    public static final String ID = "opa-policy-provider";

    private static final Logger logger = Logger.getLogger(OpaPolicyProvider.class);
    
    private static final Pattern COMMA_PATTERN = Pattern.compile(",");
    
    // private final Map<String, String> providerConfig;

    private final BiFunction<Policy, AuthorizationProvider, OpaPolicyRepresentation> representationFunction;

    // public OpaPolicyProvider(Map<String, String> providerConfig) {
    //     this.providerConfig = providerConfig;
    // }

    public OpaPolicyProvider(BiFunction<Policy, AuthorizationProvider, OpaPolicyRepresentation> representationFunction) {
        this.representationFunction = representationFunction;
    }

    @Getter
    public enum Option {

        REQUEST_HEADERS("request-headers", ProviderConfigProperty.STRING_TYPE, "Request Headers", "Comma separated list of request headers to send with OPA requests.", null), //

        URL("opaUrl", ProviderConfigProperty.STRING_TYPE, "URL", "URL of OPA Authz Server Resource", null), //

        POLICY_PATH("policy-path", ProviderConfigProperty.STRING_TYPE, "Policy Path", "Path of OPA policy relative to Authz Server URL", null), //
        ;

        private final String key;

        private final String type;

        private final String label;

        private final String helpText;

        private final String defaultValue;

        Option(String key, String type, String label, String helpText, String defaultValue) {
            this.key = key;
            this.type = type;
            this.label = label;
            this.helpText = helpText;
            this.defaultValue = defaultValue;
        }
    }

    @Override
    public void evaluate(Evaluation evaluation) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public AccessDecision evaluate(AccessDecisionContext context) {

        Policy policy = context.getPolicy();
        logger.debugf("OPA policy %s evaluating", policy.getName());
        throw new UnsupportedOperationException("Not supported yet.");
        // try {
        //     String action = context.getAction();
        //     ConfigWrapper config = getConfig(context);
        //     OpaSubject subject = createSubject(context.getUser(), context.getClient(), config);
        //     ResourcePermission permission = context.getResourcePermission();
        //     OpaResource resource = createResource(context.getRealm(), context.getClient(), config, context.getResource(), permission.getResource());
        //     OpaRequestContext requestContext = createRequestContext(context.getSession(), config);

        //     String policyUrl = createPolicyUrl(context.getRealm(), context.getClient(), action, config);

        //     OpaPolicyQuery accessRequest = createAccessRequest(subject, resource, requestContext, action);

        //     OpaClient opaClient = createOpaClient(context);

        //     OpaResponse policyResponse = opaClient.evaluatePolicy(policyUrl, new OpaRequest(accessRequest));

        //     return toAccessDecision(policyResponse);

        // } catch (Exception e) {
        //     throw new RuntimeException("Could not evaluate opa-based policy [" + policy.getName() + "].", e);
        // }
    }

    // private ConfigWrapper getConfig(AccessDecisionContext context) {
    //     if (context.getConfigOverride() == null) {
    //         return new MapConfig(providerConfig);
    //     }
    //     return new CompositeConfig(Arrays.asList(context.getConfigOverride(), new MapConfig(providerConfig)));
    // }

    protected AccessDecision toAccessDecision(OpaResponse response) {
        return new AccessDecision(response.isAllowed(), response.getMetadata());
    }

    protected OpaPolicyQuery createAccessRequest(OpaSubject subject, OpaResource resource, OpaRequestContext requestContext, String action) {
        return OpaPolicyQuery.builder() //
                .subject(subject) //
                .resource(resource) //
                .context(requestContext) //
                .action(action) //
                .build();
    }

    protected OpaSubject createSubject(UserModel user, ClientModel client, ConfigWrapper config) {

        var subjectBuilder = OpaSubject.builder();
        subjectBuilder.id(user.getId());
        subjectBuilder.username(user.getUsername());
        subjectBuilder.realmRoles(fetchRealmRoles(user));
        subjectBuilder.clientRoles(fetchClientRoles(user, client));
        subjectBuilder.attributes(extractUserAttributes(user, config));
        subjectBuilder.groups(fetchGroupNames(user));

        return subjectBuilder.build();
    }

    protected OpaResource createResource(RealmModel realm, ClientModel client, ConfigWrapper config, RealmResource realmResource, Resource resource) {
        var opaResourceBuilder = OpaResource.builder();
        opaResourceBuilder.realm(realm.getName());
        opaResourceBuilder.clientId(client.getClientId());
        opaResourceBuilder.realmAttributes(extractRealmAttributes(realm, config));
        opaResourceBuilder.clientAttributes(extractClientAttributes(client, config));
        opaResourceBuilder.resourceAttributes(extractResourceAttributes(resource, config));
        opaResourceBuilder.RealmResourceType(realmResource.getType());
        opaResourceBuilder.RealmResourceId(realmResource.getId());
        opaResourceBuilder.RealmResourceName(realmResource.getName());
        opaResourceBuilder.RealmResourcePath(realmResource.getPath());
        opaResourceBuilder.RealmResourceScopes(realmResource.getScopes());
        return opaResourceBuilder.build();
    }

    protected OpaClient createOpaClient(AccessDecisionContext context) {
        return new OpaClient(context.getSession());
    }

    protected String createPolicyUrl(RealmModel realm, ClientModel client, String action, ConfigWrapper config) {

        String opaUrl = config.getString(Option.URL.key);

        if (opaUrl == null) {
            throw new RuntimeException("missing opaUrl");
        }

        String policyPath = createPolicyPath(realm, client, action, config);

        return opaUrl + policyPath;
    }

    protected String createPolicyPath(RealmModel realm, ClientModel client, String action, ConfigWrapper config) {
        String policyPathTemplate = config.getString(Option.POLICY_PATH.key);
        Map<String, String> params = new HashMap<>();
        params.put("realm", realm.getName());
        params.put("action", action);
        params.put("client", client.getClientId());
        return UriBuilder.fromPath(policyPathTemplate).buildFromMap(params).toString();
    }

    protected OpaRequestContext createRequestContext(KeycloakSession session, ConfigWrapper config) {
        var builder = OpaRequestContext.builder();
        builder.attributes(extractContextAttributes(session, config));
        builder.headers(extractRequestHeaders(session, config));
        return builder.build();
    }

    protected Map<String, Object> extractRequestHeaders(KeycloakSession session, ConfigWrapper config) {

        String headerNames = config.getValue(Option.REQUEST_HEADERS.key);
        if (headerNames == null || StringUtil.isBlank(headerNames)) {
            return null;
        }

        HttpHeaders requestHeaders = session.getContext().getRequestHeaders();
        Map<String, Object> headers = new HashMap<>();
        for (String header : COMMA_PATTERN.split(headerNames.trim())) {
            String value = requestHeaders.getHeaderString(header);
            headers.put(header, value);
        }

        if (headers.isEmpty()) {
            return null;
        }

        return headers;
    }

    protected Map<String, Object> extractContextAttributes(KeycloakSession session,  ConfigWrapper config) {
        Map<String, Object> attributes = new HashMap<>();
        KeycloakContext context = session.getContext();

        // Add the remote address
        attributes.put("remoteAddress", context.getConnection() != null ? context.getConnection().getRemoteAddr() : null);

        // Add the protocol
        attributes.put("protocol", context.getAuthenticationSession() != null ? context.getAuthenticationSession().getProtocol() : null);

        // Add the grant type
        attributes.put("grantType", context.getHttpRequest() != null ? context.getHttpRequest().getDecodedFormParameters().getFirst("grant_type") : null);

        return attributes;
    }


    protected <T> Map<String, Object> extractAttributes(T source, ConfigWrapper config, String attributesKey, BiFunction<T, String, Object> valueExtractor, Function<T, Map<String, Object>> defaultValuesExtractor) {

        if (config == null) {
            return defaultValuesExtractor.apply(source);
        }

        String attributeNames = config.getValue(attributesKey);
        if (attributeNames == null || StringUtil.isBlank(attributeNames)) {
            return defaultValuesExtractor.apply(source);
        }

        Map<String, Object> attributes = new HashMap<>();
        for (String attributeName : COMMA_PATTERN.split(attributeNames.trim())) {
            Object value = valueExtractor.apply(source, attributeName);
            attributes.put(attributeName, value);
        }

        return attributes;
    }

    protected Map<String, Object> extractUserAttributes(UserModel user, ConfigWrapper config) {
        Map<String, Object> attributes = new HashMap<>();

        // Add built-in attributes
        attributes.put("email", user.getEmail());
        attributes.put("emailVerified", user.isEmailVerified());
        attributes.put("createdTimestamp", user.getCreatedTimestamp());
        attributes.put("lastName", user.getLastName());
        attributes.put("firstName", user.getFirstName());
        attributes.put("federationLink", user.getFederationLink());
        attributes.put("serviceAccountLink", user.getServiceAccountClientLink());

        // Add custom attributes from UserModel as comma-separated strings
        Map<String, List<String>> customAttributes = user.getAttributes();
        for (Map.Entry<String, List<String>> entry : customAttributes.entrySet()) {
            // Join all values in the list with commas, or use null if the list is empty
            String commaSeparatedValues = entry.getValue().isEmpty() ? null : String.join(",", entry.getValue());
            attributes.put(entry.getKey(), commaSeparatedValues);
        }

        return attributes;
    }

    protected Map<String, Object> extractClientAttributes(ClientModel client, ConfigWrapper config) {
        Map<String, Object> attributes = new HashMap<>();
        ClientConfig clientConfig = new ClientConfig(client);

        // Retrieve each attribute from clientConfig and add it to the map
        for (String attributeName : client.getAttributes().keySet()) {
            String attributeValue = clientConfig.getValue(attributeName);
            attributes.put(attributeName, attributeValue != null ? attributeValue : null);
        }

        return attributes;
    }

    protected Map<String, Object> extractRealmAttributes(RealmModel realm, ConfigWrapper config) {
        Map<String, Object> attributes = new HashMap<>();
        RealmConfig realmConfig = new RealmConfig(realm);

       // Retrieve each attribute from realmConfig and add it to the map
        for (String attributeName : realm.getAttributes().keySet()) {
            String attributeValue = realmConfig.getValue(attributeName);
            attributes.put(attributeName, attributeValue != null ? attributeValue : null);
        }
        
        return attributes;
    }

    protected Map<String, Object> extractResourceAttributes(Resource resource, ConfigWrapper config) {
        Map<String, Object> attributes = new HashMap<>();

        Map<String, List<String>> resourceAttributes = resource.getAttributes();

        for (Map.Entry<String, List<String>> entry : resourceAttributes.entrySet()) {
            // Join all values in the list with commas, or use null if the list is empty
            String commaSeparatedValues = entry.getValue().isEmpty() ? null : String.join(",", entry.getValue());
            attributes.put(entry.getKey(), commaSeparatedValues);
        }

        return attributes;
    }

    protected List<String> fetchGroupNames(UserModel user) {
        List<String> groupNames = user.getGroupsStream().map(GroupModel::getName).collect(Collectors.toList());
        return groupNames.isEmpty() ? null : groupNames;
    }

    protected List<String> fetchClientRoles(UserModel user, ClientModel client) {
        Stream<RoleModel> explicitClientRoles = RoleUtils.expandCompositeRolesStream(user.getClientRoleMappingsStream(client));
        Stream<RoleModel> implicitClientRoles = RoleUtils.expandCompositeRolesStream(user.getRealmRoleMappingsStream());
        return Stream.concat(explicitClientRoles, implicitClientRoles) //
                .filter(RoleModel::isClientRole) //
                .map(this::normalizeRoleName) //
                .collect(Collectors.toList());
    }

    protected List<String> fetchRealmRoles(UserModel user) {
        return RoleUtils.expandCompositeRolesStream(user.getRealmRoleMappingsStream()) //
                .filter(r -> !r.isClientRole()).map(this::normalizeRoleName) //
                .collect(Collectors.toList());
    }

    protected String normalizeRoleName(RoleModel role) {
        if (role.isClientRole()) {
            return ((ClientModel) role.getContainer()).getClientId() + ":" + role.getName();
        }
        return role.getName();
    }
}
