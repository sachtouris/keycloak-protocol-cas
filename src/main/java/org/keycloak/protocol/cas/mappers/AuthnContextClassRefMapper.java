package org.keycloak.protocol.cas.mappers;

import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.util.LoAUtil;
import org.keycloak.common.Profile;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.cas.CASLoginProtocol;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.utils.AcrUtils;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AuthnContextClassRefMapper extends AbstractCASProtocolMapper implements EnvironmentDependentProviderFactory {
    public static final String PROVIDER_ID = "cas-authn-context-class-ref-mapper";
    public static final String AUTHN_CONTEXT_CLASS_REF_CATEGORY = "AuthnContextClassRef mapper";

    private static final Logger logger = Logger.getLogger(AuthnContextClassRefMapper.class);
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addJsonTypeConfig(configProperties);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return AUTHN_CONTEXT_CLASS_REF_CATEGORY;
    }

    @Override
    public String getDisplayCategory() {
        return AUTHN_CONTEXT_CLASS_REF_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Add the AuthnContextClassRef to the CAS validation attributes with the Level of Authentication if present.";
    }

    @Override
    public void setAttribute(Map<String, Object> attributes, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                             KeycloakSession session, ClientSessionContext clientSessionCtx) {
        int loa = LoAUtil.getCurrentLevelOfAuthentication(clientSessionCtx.getClientSession());
        String authnContextClassRef = clientSessionCtx.getClientSession().getNote(CASLoginProtocol.SESSION_AUTHN_CONTEXT_CLASS_REF);
        logger.tracef("Current level of authentication %d, requested AuthnContextClassRef %s", loa, authnContextClassRef);

        if (loa < Constants.MINIMUM_LOA) {
            return;
        }

        Map<String, Integer> acrLoaMap = AcrUtils.getUriLoaMap(clientSessionCtx.getClientSession().getClient());
        if (authnContextClassRef == null) {
            authnContextClassRef = acrLoaMap.entrySet().stream()
                    .filter(entry -> loa == entry.getValue())
                    .map(Map.Entry::getKey)
                    .findAny()
                    .orElse(null);
        } else {
            Integer requestedLevel = acrLoaMap.get(authnContextClassRef);
            if (requestedLevel == null || requestedLevel != loa) {
                logger.warnf("Requested AuthnContextClassRef '%s' (%d) was not reached after authentication flow, current level %d",
                        authnContextClassRef, requestedLevel, loa);
                authnContextClassRef = null;
            }
        }

        setMappedAttribute(attributes, mappingModel, authnContextClassRef);
    }

    @Override
    public boolean isSupported(org.keycloak.Config.Scope config) {
        return Profile.isFeatureEnabled(Profile.Feature.STEP_UP_AUTHENTICATION_SAML);
    }

    public static ProtocolMapperModel create(String name) {
        return CASAttributeMapperHelper.createClaimMapper(name, name, "String", PROVIDER_ID);
    }
}
