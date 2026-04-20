package org.keycloak.protocol.cas.endpoints;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.common.Profile;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.protocol.cas.CASLoginProtocol;
import org.keycloak.protocol.oidc.utils.AcrUtils;
import org.keycloak.protocol.oidc.utils.RedirectUtils;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.util.CacheControlUtil;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class AuthorizationEndpoint extends AuthorizationEndpointBase {
    private static final Logger logger = Logger.getLogger(AuthorizationEndpoint.class);

    private ClientModel client;
    private AuthenticationSessionModel authenticationSession;
    private String redirectUri;

    public AuthorizationEndpoint(KeycloakSession session, EventBuilder event) {
        super(session, event);
        event.event(EventType.LOGIN);
    }

    @GET
    public Response build() {
        MultivaluedMap<String, String> params = session.getContext().getUri().getQueryParameters();
        String service = params.getFirst(CASLoginProtocol.SERVICE_PARAM);

        boolean isSaml11Request = false;
        if (service == null && params.containsKey(CASLoginProtocol.TARGET_PARAM)) {
            // SAML 1.1 authorization uses the TARGET parameter instead of service
            service = params.getFirst(CASLoginProtocol.TARGET_PARAM);
            isSaml11Request = true;
        }
        boolean renew = params.containsKey(CASLoginProtocol.RENEW_PARAM);
        boolean gateway = params.containsKey(CASLoginProtocol.GATEWAY_PARAM);

        checkSsl();
        checkRealm();
        checkClient(service);

        authenticationSession = createAuthenticationSession(client, null);
        updateAuthenticationSession();

        // So back button doesn't work
        CacheControlUtil.noBackButtonCacheControlHeader(session);

        if (renew) {
            authenticationSession.setClientNote(CASLoginProtocol.RENEW_PARAM, "true");
        }
        if (gateway) {
            authenticationSession.setClientNote(CASLoginProtocol.GATEWAY_PARAM, "true");
        }
        if (isSaml11Request) {
            // Flag the session so we can return the ticket as "SAMLart" in the response
            authenticationSession.setClientNote(CASLoginProtocol.TARGET_PARAM, "true");
        }

        processStepUpAuthentication(params);

        this.event.event(EventType.LOGIN);
        return handleBrowserAuthenticationRequest(authenticationSession, new CASLoginProtocol(session, realm, session.getContext().getUri(), headers, event), gateway, false);
    }

    private void processStepUpAuthentication(MultivaluedMap<String, String> params) {
        if (!Profile.isFeatureEnabled(Profile.Feature.STEP_UP_AUTHENTICATION_SAML)) {
            return;
        }

        Map<String, Integer> acrLoaMap = AcrUtils.getUriLoaMap(client);
        if (acrLoaMap.isEmpty()) {
            return;
        }

        List<String> requestedAuthnContextClassRefs = getRequestedAuthnContextClassRefs(params);
        String authnContextClassRef;
        if (!requestedAuthnContextClassRefs.isEmpty()) {
            authnContextClassRef = getSelectedLoA(
                    requestedAuthnContextClassRefs,
                    getAuthnContextComparison(params),
                    acrLoaMap,
                    AcrUtils.getMinimumAcrValue(client));
            if (authnContextClassRef == null) {
                logger.debug("No AuthnContextClassRef is valid for the requested context.");
                event.detail(Details.REASON, "Invalid requested CAS authentication context");
                event.error(Errors.INVALID_REQUEST);
                throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
            }
        } else {
            authnContextClassRef = AcrUtils.getMinimumAcrValue(client);
        }

        if (authnContextClassRef != null) {
            Integer requestedLevel = acrLoaMap.get(authnContextClassRef);
            if (requestedLevel == null) {
                logger.warnf("AuthnContextClassRef '%s' is not mapped to a level of authentication.", authnContextClassRef);
                return;
            }

            logger.tracef("CAS step-up authentication set to force using context '%s'", authnContextClassRef);
            authenticationSession.setClientNote(Constants.FORCE_LEVEL_OF_AUTHENTICATION, "true");
            authenticationSession.setClientNote(CASLoginProtocol.SESSION_AUTHN_CONTEXT_CLASS_REF, authnContextClassRef);
            authenticationSession.setClientNote(Constants.REQUESTED_LEVEL_OF_AUTHENTICATION, String.valueOf(requestedLevel));
        }
    }

    private List<String> getRequestedAuthnContextClassRefs(MultivaluedMap<String, String> params) {
        List<String> requestedAuthnContextClassRefs = new ArrayList<>();
        addRequestedAuthnContextClassRefs(requestedAuthnContextClassRefs, params.get(CASLoginProtocol.AUTHN_CONTEXT_CLASS_REF_PARAM));
        addRequestedAuthnContextClassRefs(requestedAuthnContextClassRefs, params.get(CASLoginProtocol.AUTHN_CONTEXT_CLASS_REF_LEGACY_PARAM));
        return requestedAuthnContextClassRefs;
    }

    private void addRequestedAuthnContextClassRefs(List<String> requestedAuthnContextClassRefs, List<String> values) {
        if (values == null) {
            return;
        }
        for (String value : values) {
            if (value == null) {
                continue;
            }
            for (String authnContextClassRef : value.trim().split("\\s+")) {
                if (!authnContextClassRef.isEmpty()) {
                    requestedAuthnContextClassRefs.add(authnContextClassRef);
                }
            }
        }
    }

    private AuthnContextComparison getAuthnContextComparison(MultivaluedMap<String, String> params) {
        String comparison = params.getFirst(CASLoginProtocol.AUTHN_CONTEXT_COMPARISON_PARAM);
        if (comparison == null || comparison.isBlank()) {
            return AuthnContextComparison.EXACT;
        }
        try {
            return AuthnContextComparison.valueOf(comparison.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            event.detail(Details.REASON, "Invalid CAS authentication context comparison");
            event.error(Errors.INVALID_REQUEST);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }
    }

    private String getSelectedLoA(List<String> requestedAuthnContextClassRefs, AuthnContextComparison comparison,
                                  Map<String, Integer> acrLoaMap, String minimumAuthnContextClassRef) {
        Integer minimumLevel = minimumAuthnContextClassRef != null ? acrLoaMap.get(minimumAuthnContextClassRef) : null;
        int effectiveMinimumLevel = minimumLevel != null ? minimumLevel : Integer.MIN_VALUE;

        return requestedAuthnContextClassRefs.stream()
                .map(current -> checkLoA(comparison, current, acrLoaMap, minimumAuthnContextClassRef, effectiveMinimumLevel))
                .filter(value -> value != null)
                .findFirst()
                .orElse(null);
    }

    private String checkLoA(AuthnContextComparison comparison, String current, Map<String, Integer> acrLoaMap,
                            String minimumAuthnContextClassRef, int minimumLevel) {
        return switch (comparison) {
            case EXACT -> checkLoAExact(current, acrLoaMap, minimumLevel);
            case MINIMUM -> checkLoAMinimum(current, acrLoaMap, minimumAuthnContextClassRef, minimumLevel);
            case MAXIMUM -> checkLoAMaximum(current, acrLoaMap, minimumLevel);
            case BETTER -> checkLoABetter(current, acrLoaMap, minimumAuthnContextClassRef, minimumLevel);
        };
    }

    private String checkLoAExact(String current, Map<String, Integer> acrLoaMap, int minimumLevel) {
        Integer level = acrLoaMap.get(current);
        if (level == null) {
            return null;
        }
        return level >= minimumLevel ? current : null;
    }

    private String checkLoAMinimum(String current, Map<String, Integer> acrLoaMap,
                                   String minimumAuthnContextClassRef, int minimumLevel) {
        Integer level = acrLoaMap.get(current);
        if (level == null) {
            return null;
        }
        return level >= minimumLevel ? current : minimumAuthnContextClassRef;
    }

    private String checkLoAMaximum(String current, Map<String, Integer> acrLoaMap, int minimumLevel) {
        Integer level = acrLoaMap.get(current);
        if (level == null) {
            return null;
        }
        return level >= minimumLevel ? current : null;
    }

    private String checkLoABetter(String current, Map<String, Integer> acrLoaMap,
                                  String minimumAuthnContextClassRef, int minimumLevel) {
        Integer level = acrLoaMap.get(current);
        if (level == null) {
            return null;
        }
        if (minimumLevel > level) {
            return minimumAuthnContextClassRef;
        }
        return acrLoaMap.entrySet().stream()
                .filter(entry -> entry.getValue() > level)
                .min(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(null);
    }

    private enum AuthnContextComparison {
        EXACT,
        MINIMUM,
        MAXIMUM,
        BETTER
    }

    private void checkClient(String service) {
        if (service == null) {
            event.error(Errors.INVALID_REQUEST);
            throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.MISSING_PARAMETER, CASLoginProtocol.SERVICE_PARAM);
        }

        event.detail(Details.REDIRECT_URI, service);

        client = realm.getClientsStream()
                .filter(c -> CASLoginProtocol.LOGIN_PROTOCOL.equals(c.getProtocol()))
                .filter(c -> RedirectUtils.verifyRedirectUri(session, service, c) != null)
                .findFirst().orElse(null);
        if (client == null) {
            event.error(Errors.CLIENT_NOT_FOUND);
            throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.CLIENT_NOT_FOUND);
        }

        if (!client.isEnabled()) {
            event.error(Errors.CLIENT_DISABLED);
            throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.CLIENT_DISABLED);
        }

        redirectUri = RedirectUtils.verifyRedirectUri(session, service, client);

        event.client(client.getClientId());
        event.detail(Details.REDIRECT_URI, redirectUri);

        session.getContext().setClient(client);
    }

    private void updateAuthenticationSession() {
        authenticationSession.setProtocol(CASLoginProtocol.LOGIN_PROTOCOL);
        authenticationSession.setRedirectUri(redirectUri);
        authenticationSession.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());
    }
}
