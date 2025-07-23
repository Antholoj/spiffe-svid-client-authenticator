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

import java.util.Optional;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.common.util.Time;
import org.keycloak.http.HttpRequest;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.representations.JsonWebToken;
import com.yourcompany.keycloak.authenticator.SpiffeSvidClientAuthenticator;

/**
 * Common validation for SPIFFE SVID JWT client authentication with spiffe_svid_jwt
 *
 * @author Your Company
 */
public class SpiffeSvidClientValidator {

    private static final Logger logger = Logger.getLogger(SpiffeSvidClientValidator.class);

    private final ClientAuthenticationFlowContext context;
    private final RealmModel realm;
    private final int currentTime;
    private final String clientAuthenticatorProviderId;

    private MultivaluedMap<String, String> params;
    private String clientAssertion;
    private JWSInput jws;
    private JsonWebToken token;
    private ClientModel client;

    private static final int ALLOWED_CLOCK_SKEW = 15; // sec

    public SpiffeSvidClientValidator(ClientAuthenticationFlowContext context, String clientAuthenticatorProviderId) {
        this.context = context;
        this.realm = context.getRealm();
        this.currentTime = Time.currentTime();
        this.clientAuthenticatorProviderId = clientAuthenticatorProviderId;
    }

    public boolean clientAssertionParametersValidation() {

        //KEYCLOAK-19461: Needed for quarkus resteasy implementation throws exception when called with mediaType authentication/json in OpenShiftTokenReviewEndpoint
        if(!isFormDataRequest(context.getHttpRequest())) {
            Response challengeResponse = SpiffeSvidClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "Parameter client_assertion_type is missing");
            context.challenge(challengeResponse);
            return false;
        }

        params = context.getHttpRequest().getDecodedFormParameters();

        String clientAssertionType = params.getFirst(OAuth2Constants.CLIENT_ASSERTION_TYPE);
        clientAssertion = params.getFirst(OAuth2Constants.CLIENT_ASSERTION);

        if (clientAssertionType == null) {
            Response challengeResponse = SpiffeSvidClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "Parameter client_assertion_type is missing");
            context.challenge(challengeResponse);
            return false;
        }

        // Accept both standard JWT bearer and custom SPIFFE SVID JWT assertion types
        if (!clientAssertionType.equals(OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT) && 
            !clientAssertionType.equals("urn:ietf:params:oauth:client-assertion-type:spiffe-svid-jwt")) {

            Response challengeResponse = SpiffeSvidClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "Parameter client_assertion_type has value '"
                    + clientAssertionType + "' but expected is '" + OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT + 
                    "' or 'urn:ietf:params:oauth:client-assertion-type:spiffe_svid_jwt'");
            context.challenge(challengeResponse);
            return false;
        }

        if (clientAssertion == null) {
            Response challengeResponse = SpiffeSvidClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "client_assertion parameter missing");
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, challengeResponse);
            return false;
        }

        return true;
    }

    public void readJws() throws JWSInputException {
        if (clientAssertion == null) throw new IllegalStateException("Incorrect usage. Variable 'clientAssertion' is null. Need to validate clientAssertion first before read JWS");

        jws = new JWSInput(clientAssertion);
        token = jws.readJsonContent(JsonWebToken.class);
    }

    public boolean validateClient() {
        logger.debugf("validateClient() called - starting client validation");
        
        if (token == null) throw new IllegalStateException("Incorrect usage. Variable 'token' is null. Need to read JWS first before validateClient");

        String clientId = token.getSubject();
        logger.debugf("Extracted client ID from token subject: %s", clientId);
        if (clientId == null) {
            throw new RuntimeException("Can't identify client. Subject missing on SPIFFE SVID JWT token");
        }

        String clientIdParam = params.getFirst(OAuth2Constants.CLIENT_ID);
        if (clientIdParam != null && !clientIdParam.equals(clientId)) {
            throw new RuntimeException("client_id parameter not matching with client from SPIFFE SVID JWT token");
        }

        context.getEvent().client(clientId);
        client = realm.getClientByClientId(clientId);
        if (client == null) {
            logger.warnf("Client not found for clientId: %s", clientId);
            context.failure(AuthenticationFlowError.CLIENT_NOT_FOUND, null);
            return false;
        } else {
            logger.debugf("Client found: %s, enabled: %s", client.getClientId(), client.isEnabled());
            context.setClient(client);
        }

        // For SPIFFE SVID JWT, the issuer should match the configured SPIFFE Issuer, not the client ID
        // The client ID is the subject, and the issuer is the SPIFFE identity
        String configuredSpiffeIssuer = client.getAttribute(SpiffeSvidClientAuthenticator.CONFIG_PROPERTY_SPIFFE_ISSUER);
        logger.infof("Configured SPIFFE issuer for client %s: %s", clientId, configuredSpiffeIssuer);
        if (configuredSpiffeIssuer != null && !configuredSpiffeIssuer.trim().isEmpty()) {
            if (!configuredSpiffeIssuer.equals(token.getIssuer())) {
                throw new RuntimeException("Issuer mismatch. The issuer should match the configured SPIFFE Issuer. Expected: " + configuredSpiffeIssuer + ", Got: " + token.getIssuer());
            }
        } else {
            // Fallback: if no SPIFFE Issuer is configured, issuer should match subject (client ID)
            if (!clientId.equals(token.getIssuer())) {
                throw new RuntimeException("Issuer mismatch. The issuer should match the subject");
            }
        }

        if (!client.isEnabled()) {
            context.failure(AuthenticationFlowError.CLIENT_DISABLED, null);
            return false;
        }

        if (!clientAuthenticatorProviderId.equals(client.getClientAuthenticatorType())) {
            logger.warnf("Client authenticator type mismatch for client %s. Expected: %s, Got: %s", 
                    clientId, clientAuthenticatorProviderId, client.getClientAuthenticatorType());
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, null);
            return false;
        }

        logger.debugf("validateClient() completed successfully for client: %s", clientId);
        return true;
    }

    public boolean validateSignatureAlgorithm() {
        if (jws == null) throw new IllegalStateException("Incorrect usage. Variable 'jws' is null. Need to read token first before validate signature algorithm");
        if (client == null) throw new IllegalStateException("Incorrect usage. Variable 'client' is null. Need to validate client first before validate signature algorithm");

        String expectedSignatureAlg = OIDCAdvancedConfigWrapper.fromClientModel(client).getTokenEndpointAuthSigningAlg();
        if (jws.getHeader().getAlgorithm() == null || jws.getHeader().getAlgorithm().name() == null) {
            Response challengeResponse = SpiffeSvidClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "invalid signature algorithm");
            context.challenge(challengeResponse);
            return false;
        }

        String actualSignatureAlg = jws.getHeader().getAlgorithm().name();
        if (expectedSignatureAlg != null && !expectedSignatureAlg.equals(actualSignatureAlg)) {
            Response challengeResponse = SpiffeSvidClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "invalid signature algorithm");
            context.challenge(challengeResponse);
            return false;
        }

        return true;
    }

    public void validateToken() {
        if (token == null) throw new IllegalStateException("Incorrect usage. Variable 'token' is null. Need to read token first before validateToken");

        if (!token.isActive(ALLOWED_CLOCK_SKEW)) {
            throw new RuntimeException("SPIFFE SVID JWT token is not active");
        }

        // KEYCLOAK-2986, token-timeout or token-expiration in keycloak.json might not be used
        if (token.getExp() == null || token.getExp() <= 0) { // in case of "exp" not exist
            if (token.getIat() + ALLOWED_CLOCK_SKEW + 10 < currentTime) { // consider "exp" = 10, client's clock delays from Keycloak's clock
                throw new RuntimeException("SPIFFE SVID JWT token is not active");
            }
        } else {
            if ((token.getIat() != null && token.getIat() > 0) && token.getIat() - ALLOWED_CLOCK_SKEW > currentTime) { // consider client's clock is ahead from Keycloak's clock
                throw new RuntimeException("SPIFFE SVID JWT token was issued in the future");
            }
        }

    }

    public void validateTokenReuse() {
        if (token == null) throw new IllegalStateException("Incorrect usage. Variable 'token' is null. Need to read token first before validateToken reuse");
        if (client == null) throw new IllegalStateException("Incorrect usage. Variable 'client' is null. Need to validate client first before validateToken reuse");
    
        SingleUseObjectProvider singleUseCache = context.getSession().singleUseObjects();
        long lifespanInSecs = Math.max(Optional.ofNullable(token.getExp()).orElse(0L) - currentTime, 10);
        
        // Handle missing JWT ID by generating a fallback key
        String tokenKey = token.getId();
        if (tokenKey == null || tokenKey.trim().isEmpty()) {
            // Generate unique key from other claims
            tokenKey = String.format("spiffe:%s:%s:%s", 
                token.getIssuer() != null ? token.getIssuer() : "unknown",
                token.getSubject() != null ? token.getSubject() : "unknown", 
                token.getIat() != null ? token.getIat().toString() : String.valueOf(currentTime));
        }
        
        if (singleUseCache.putIfAbsent(tokenKey, lifespanInSecs)) {
            logger.tracef("Added SPIFFE SVID JWT token '%s' to single-use cache. Lifespan: %d seconds, client: %s", tokenKey, lifespanInSecs, client.getClientId());
        } else {
            logger.warnf("SPIFFE SVID JWT token '%s' already used when authenticating client '%s'.", tokenKey, client.getClientId());
            throw new RuntimeException("SPIFFE SVID JWT token reuse detected");
        }
    }

    public ClientAuthenticationFlowContext getContext() {
        return context;
    }

    public RealmModel getRealm() {
        return realm;
    }

    public MultivaluedMap<String, String> getParams() {
        return params;
    }

    public String getClientAssertion() {
        return clientAssertion;
    }

    public JWSInput getJws() {
        return jws;
    }

    public JsonWebToken getToken() {
        return token;
    }

    public ClientModel getClient() {
        return client;
    }

    private boolean isFormDataRequest(HttpRequest request) {
        MediaType mediaType = request.getHttpHeaders().getMediaType();
        return mediaType != null && mediaType.isCompatible(MediaType.APPLICATION_FORM_URLENCODED_TYPE);
    }
} 