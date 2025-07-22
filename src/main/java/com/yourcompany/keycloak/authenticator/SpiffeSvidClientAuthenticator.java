/*
 * Copyright 2024 Your Company
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yourcompany.keycloak.authenticator;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.core.Response;

import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.AbstractClientAuthenticator;
import org.keycloak.crypto.ClientSignatureVerifierProvider;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.keys.loader.PublicKeyStorageManager;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.Config;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.protocol.oidc.grants.ciba.CibaGrantType;
import org.keycloak.protocol.oidc.par.endpoints.ParEndpoint;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.Urls;

import static org.keycloak.models.TokenManager.DEFAULT_VALIDATOR;

/**
 * Client authentication based on SPIFFE SVID JWT signed by client private key.
 * This authenticator validates SPIFFE SVID JWTs for client authentication.
 *
 * This is server side, which verifies JWT from client_assertion parameter, where the assertion was created on adapter side by
 * a SPIFFE SVID JWT client credentials provider.
 *
 * @author Your Company
 */
public class SpiffeSvidClientAuthenticator extends AbstractClientAuthenticator {

    public static final String PROVIDER_ID = "client-spiffe-jwt";
    public static final String ATTR_PREFIX = "spiffe.credential";
    public static final String CERTIFICATE_ATTR = "spiffe.credential.certificate";
    
    // Configuration property constants
    public static final String CONFIG_PROPERTY_SPIFFE_ISSUER = "issuer";
    
    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();
    

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        ServicesLogger.LOGGER.infof("SpiffeSvidClientAuthenticator.authenticateClient() called for client: %s", 
            context.getClient().getClientId());

        SpiffeSvidClientValidator validator = new SpiffeSvidClientValidator(context, getId());

        if (!validator.clientAssertionParametersValidation()) return;

        try {
            validator.readJws();
            if (!validator.validateClient()) return;
            if (!validator.validateSignatureAlgorithm()) return;
            
            // Get custom configuration from client attributes
            ClientModel client = validator.getClient();
            String configuredSpiffeIssuer = client.getAttribute(CONFIG_PROPERTY_SPIFFE_ISSUER);
            
            // Log configuration for debugging
            ServicesLogger.LOGGER.debugf("SPIFFE SVID Client Authenticator configuration for client %s: spiffeIssuer=%s", 
                client.getClientId(), configuredSpiffeIssuer);

            RealmModel realm = validator.getRealm();
            JWSInput jws = validator.getJws();
            JsonWebToken token = validator.getToken();
            String clientAssertion = validator.getClientAssertion();

            // Get client key and validate signature
            PublicKey clientPublicKey = getSignatureValidationKey(client, context, jws);
            if (clientPublicKey == null) {
                // Error response already set to context
                return;
            }

            boolean signatureValid;
            try {
                JsonWebToken jwt = context.getSession().tokens().decodeClientJWT(clientAssertion, client, (jose, validatedClient) -> {
                    DEFAULT_VALIDATOR.accept(jose, validatedClient);
                    String signatureAlgorithm = jose.getHeader().getRawAlgorithm();
                    ClientSignatureVerifierProvider signatureProvider = context.getSession().getProvider(ClientSignatureVerifierProvider.class, signatureAlgorithm);
                    if (signatureProvider == null) {
                        throw new RuntimeException("Algorithm not supported");
                    }
                    if (!signatureProvider.isAsymmetricAlgorithm()) {
                        throw new RuntimeException("Algorithm is not asymmetric");
                    }
                }, JsonWebToken.class);
                signatureValid = jwt != null;
            } catch (RuntimeException e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                throw new RuntimeException("Signature on SPIFFE SVID JWT token failed validation", cause);
            }
            if (!signatureValid) {
                throw new RuntimeException("Signature on SPIFFE SVID JWT token failed validation");
            }

            // Use default expected audiences
            List<String> expectedAudiences = getExpectedAudiences(context, realm);

            if (!token.hasAnyAudience(expectedAudiences)) {
                throw new RuntimeException("Token audience doesn't match domain. Expected audiences are any of " + expectedAudiences
                        + " but audience from token is '" + Arrays.asList(token.getAudience()) + "'");
            }
            
            // SPIFFE Issuer validation is now handled in SpiffeSvidClientValidator.validateClient()

            validator.validateToken();
            validator.validateTokenReuse();

            context.success();
        } catch (Exception e) {
            ServicesLogger.LOGGER.errorValidatingAssertion(e);
            Response challengeResponse = SpiffeSvidClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), OAuthErrorException.INVALID_CLIENT, "Client authentication with SPIFFE SVID JWT failed: " + e.getMessage());
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, challengeResponse);
        }
    }

    protected PublicKey getSignatureValidationKey(ClientModel client, ClientAuthenticationFlowContext context, JWSInput jws) {
        PublicKey publicKey = PublicKeyStorageManager.getClientPublicKey(context.getSession(), client, jws);
        if (publicKey == null) {
            Response challengeResponse = SpiffeSvidClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), OAuthErrorException.INVALID_CLIENT, "Unable to load public key");
            context.failure(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED, challengeResponse);
            return null;
        } else {
            return publicKey;
        }
    }

    @Override
    public String getDisplayType() {
        return "SPIFFE SVID JWT";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getHelpText() {
        return "Validates client based on SPIFFE SVID JWT issued by client and signed with the Client private key";
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public int order() {
        return 10;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public List<ProviderConfigProperty> getConfigPropertiesPerClient() {
        // This is where you define the dynamic components that will appear in the admin console
        return CONFIG_PROPERTIES;
    }



    @Override
    public Map<String, Object> getAdapterConfiguration(ClientModel client) {
        Map<String, Object> props = new HashMap<>();
        
        // Get configuration values from client attributes
        String spiffeIssuer = client.getAttribute(CONFIG_PROPERTY_SPIFFE_ISSUER);

        // Set default values if not configured
        if (spiffeIssuer == null) spiffeIssuer = "http://spire-server:8443";

        props.put("issuer", spiffeIssuer);

        // Legacy properties for backward compatibility
        props.put("client-keystore-file", "REPLACE WITH THE LOCATION OF YOUR KEYSTORE FILE");
        props.put("client-keystore-type", "jks");
        props.put("client-keystore-password", "REPLACE WITH THE KEYSTORE PASSWORD");
        props.put("client-key-password", "REPLACE WITH THE KEY PASSWORD IN KEYSTORE");
        props.put("client-key-alias", client.getClientId());

        Map<String, Object> config = new HashMap<>();
        config.put("spiffe-jwt", props);
        return config;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Set<String> getProtocolAuthenticatorMethods(String loginProtocol) {
        ServicesLogger.LOGGER.infof("SpiffeSvidClientAuthenticator.getProtocolAuthenticatorMethods() called with protocol: %s", loginProtocol);
        
        if (loginProtocol.equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            Set<String> results = new HashSet<>();
            results.add("spiffe_svid_jwt");
            
            ServicesLogger.LOGGER.infof("Returning protocol methods: %s", results);
            return results;
        } else {
            ServicesLogger.LOGGER.infof("Protocol %s not supported, returning empty set", loginProtocol);
            return Collections.emptySet();
        }
    }

    private List<String> getExpectedAudiences(ClientAuthenticationFlowContext context, RealmModel realm) {
        String issuerUrl = Urls.realmIssuer(context.getUriInfo().getBaseUri(), realm.getName());
        String tokenUrl = OIDCLoginProtocolService.tokenUrl(context.getUriInfo().getBaseUriBuilder()).build(realm.getName()).toString();
        String tokenIntrospectUrl = OIDCLoginProtocolService.tokenIntrospectionUrl(context.getUriInfo().getBaseUriBuilder()).build(realm.getName()).toString();
        String parEndpointUrl = ParEndpoint.parUrl(context.getUriInfo().getBaseUriBuilder()).build(realm.getName()).toString();
        List<String> expectedAudiences = new ArrayList<>(Arrays.asList(issuerUrl, tokenUrl, tokenIntrospectUrl, parEndpointUrl));
        String backchannelAuthenticationUrl = CibaGrantType.authorizationUrl(context.getUriInfo().getBaseUriBuilder()).build(realm.getName()).toString();
        expectedAudiences.add(backchannelAuthenticationUrl);

        return expectedAudiences;
    }
} 