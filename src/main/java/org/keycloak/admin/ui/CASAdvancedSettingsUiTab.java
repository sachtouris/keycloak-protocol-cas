package org.keycloak.admin.ui;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.type.TypeReference;

import org.glassfish.jaxb.runtime.v2.runtime.reflect.opt.Const;
import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.cas.CASLoginProtocol;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.utils.AcrUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.ui.extend.UiTabProvider;
import org.keycloak.services.ui.extend.UiTabProviderFactory;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

public class CASAdvancedSettingsUiTab implements UiTabProvider, UiTabProviderFactory<ComponentModel> {
    private static final Logger logger = Logger.getLogger(CASAdvancedSettingsUiTab.class);

    private static final String MINIMUM_ACR_CONFIG = "minimumAcrValue";

    @Override
    public void init(Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "casAdvancedSettings";
    }

    @Override
    public String getPath() {
        return "/:realm/clients/:clientId/:tab";
    }

    @Override
    public Map<String, String> getParams() {
        Map<String, String> params = new HashMap<>();
        params.put("tab", "casAdvancedSettings");
        return params;
    }

    @Override
    public String getHelpText() {
        return "Configure advanced settings for this client";
    }

    @Override
    public void onCreate(KeycloakSession session, RealmModel realm, ComponentModel model) {
        logger.debugf("onCreate execution");
        // storeStepUpConfiguration(session, realm, null, model);
        ClientModel client = getCasClient(session, realm, model);
        if (client == null) {
            logger.warnf("CAS client not found for component '%s'", model.getId());
            return;
        }

        String minimumAcrValue = model.get(MINIMUM_ACR_CONFIG);
        if (StringUtil.isNotBlank(minimumAcrValue)) {
            logger.debugf("onUpdate: setting '%s' = '%s' on client '%s'", Constants.MINIMUM_ACR_VALUE, minimumAcrValue, client.getClientId());
            client.setAttribute(Constants.MINIMUM_ACR_VALUE, minimumAcrValue);
        } else {
            logger.debugf("onUpdate: removing '%s' from client '%s'", Constants.MINIMUM_ACR_VALUE, client.getClientId());
            client.removeAttribute(Constants.MINIMUM_ACR_VALUE);
        }
    }

    @Override
    public void onUpdate(KeycloakSession session, RealmModel realm, ComponentModel oldModel, ComponentModel newModel) {
        logger.debugf("onUpdate execution");
        // storeStepUpConfiguration(session, realm, oldModel, newModel);
        ClientModel client = getCasClient(session, realm, newModel);
        if (client == null) {
            logger.warnf("CAS client not found for component '%s'", newModel.getId());
            return;
        }

        String minimumAcrValue = newModel.get(MINIMUM_ACR_CONFIG);
        if (StringUtil.isNotBlank(minimumAcrValue)) {
            logger.debugf("onUpdate: setting '%s' = '%s' on client '%s'", Constants.MINIMUM_ACR_VALUE, minimumAcrValue, client.getClientId());
            client.setAttribute(Constants.MINIMUM_ACR_VALUE, minimumAcrValue);
            logger.debugf("New value of '%s' for client '%s' is '%s'", Constants.MINIMUM_ACR_VALUE, client.getClientId(), client.getAttribute(Constants.MINIMUM_ACR_VALUE));
        } else {
            logger.debugf("onUpdate: removing '%s' from client '%s'", Constants.MINIMUM_ACR_VALUE, client.getClientId());
            client.removeAttribute(Constants.MINIMUM_ACR_VALUE);
        }
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        logger.debugf("validateConfiguration execution");
        // Validate that client has protocol 'CAS'
        ClientModel client = getCasClient(session, realm, model);

        Set<String> possibleAcrValues = getPossibleAcrValues(client, model);
        String minimumAcrValue = model.get(MINIMUM_ACR_CONFIG);
        logger.debugf("Possible ACR values are %s, and minimum ACR value is set to '%s'", possibleAcrValues, minimumAcrValue);

        if (!possibleAcrValues.contains(minimumAcrValue)) {
            logger.warnf("Minimum ACR value '%s' is not configured for client '%s'", minimumAcrValue, client.getClientId());
            throw new ComponentValidationException("Minimum ACR value must be one of the configured ACR values");
        }

        // Load current client's attribute value into the model so the form reflects it on next load
        if (client != null) {
            String current = client.getAttribute(Constants.MINIMUM_ACR_VALUE);
            if (StringUtil.isNotBlank(current)) {
                if (model.get(MINIMUM_ACR_CONFIG) == null) {
                    model.getConfig().putSingle(MINIMUM_ACR_CONFIG, current);
                }
            }
        }
    }

    private ClientModel getCasClient(KeycloakSession session, RealmModel realm, ComponentModel model) {
        String clientId = model.get("clientId");
        if (StringUtil.isBlank(clientId)) {
            logger.warnf("No clientId in component model");
            return null;
        }

        ClientModel client = session.clients().getClientById(realm, clientId);
        String clientProtocol = client != null ? client.getProtocol() : null;
        if (!CASLoginProtocol.LOGIN_PROTOCOL.equals(clientProtocol)) {
            logger.warnf("Client '%s' has unsupported protocol '%s'", clientId, clientProtocol);
            return null;
        }

        return client;
    }

    private void storeStepUpConfiguration(KeycloakSession session, RealmModel realm, ComponentModel oldModel, ComponentModel newModel) {
        try {
            ClientModel client = getCasClient(session, realm, newModel);
            storeAcrLoaMap(client, oldModel, newModel);
            storeMinimumAcrValue(client, oldModel, newModel);
        } catch (ComponentValidationException e) {
            logger.warnf(e, "Unable to store CAS step-up authentication configuration");
            throw e;
        }
    }

    private void storeAcrLoaMap(ClientModel client, ComponentModel oldModel, ComponentModel newModel) {
        if (!newModel.contains(Constants.ACR_LOA_MAP)) {
            if (oldModel != null && oldModel.contains(Constants.ACR_LOA_MAP)) {
                client.removeAttribute(Constants.ACR_LOA_MAP);
            }
            return;
        }

        String acrLoaMap = newModel.get(Constants.ACR_LOA_MAP);
        if (StringUtil.isBlank(acrLoaMap)) {
            client.removeAttribute(Constants.ACR_LOA_MAP);
            return;
        }

        try {
            client.setAttribute(Constants.ACR_LOA_MAP, JsonSerialization.writeValueAsString(parseAcrLoaMap(acrLoaMap)));
        } catch (IOException e) {
            logger.warnf(e, "Unable to serialize CAS ACR-LOA map for client '%s'", client.getClientId());
            throw new ComponentValidationException("Invalid client ACR-LOA map");
        }
    }

    private void storeMinimumAcrValue(ClientModel client, ComponentModel oldModel, ComponentModel newModel) {
        if (!newModel.contains(MINIMUM_ACR_CONFIG)) {
            if (oldModel != null && oldModel.contains(MINIMUM_ACR_CONFIG)) {
                OIDCAdvancedConfigWrapper.fromClientModel(client).setMinimumAcrValue(null);
            }
            return;
        }

        String minimumAcrValue = newModel.get(MINIMUM_ACR_CONFIG);
        if (StringUtil.isBlank(minimumAcrValue)) {
            OIDCAdvancedConfigWrapper.fromClientModel(client).setMinimumAcrValue(null);
        } else {
            OIDCAdvancedConfigWrapper.fromClientModel(client).setMinimumAcrValue(minimumAcrValue);
        }
    }

    private Set<String> getPossibleAcrValues(ClientModel client, ComponentModel model) {
        Map<String, Integer> submittedAcrLoaMap = parseAcrLoaMap(model.get(Constants.ACR_LOA_MAP));
        if (!submittedAcrLoaMap.isEmpty()) {
            return submittedAcrLoaMap.keySet();
        }

        return new LinkedHashSet<>(AcrUtils.getUriLoaMap(client).keySet());
    }

    private Map<String, Integer> parseAcrLoaMap(String value) {
        if (StringUtil.isBlank(value)) {
            return new LinkedHashMap<>();
        }

        try {
            String trimmed = value.trim();
            if (trimmed.startsWith("[")) {
                return parseDeclarativeUiMap(trimmed);
            }
            return new LinkedHashMap<>(AcrUtils.parseAcrLoaMap(trimmed));
        } catch (IOException | IllegalArgumentException e) {
            logger.warnf(e, "Invalid ACR-LOA map");
            throw new ComponentValidationException("Invalid client ACR-LOA map");
        }
    }

    private Map<String, Integer> parseDeclarativeUiMap(String value) throws IOException {
        List<Map<String, Object>> entries = JsonSerialization.readValue(value, new TypeReference<List<Map<String, Object>>>() {
        });
        Map<String, Integer> acrLoaMap = new LinkedHashMap<>();
        for (Map<String, Object> entry : entries) {
            String key = toString(entry.get("key"));
            if (StringUtil.isBlank(key)) {
                continue;
            }
            if (acrLoaMap.containsKey(key)) {
                throw new ComponentValidationException("Duplicate ACR value in ACR-LOA map");
            }
            acrLoaMap.put(key, parseLoa(entry.get("value"), key));
        }
        return acrLoaMap;
    }

    private int parseLoa(Object value, String key) {
        if (value instanceof Number number) {
            return number.intValue();
        }

        String loa = toString(value);
        if (StringUtil.isBlank(loa)) {
            throw new ComponentValidationException("LoA value is required for ACR '" + key + "'");
        }

        try {
            int parsedLoa = Integer.parseInt(loa);
            if (parsedLoa < Constants.MINIMUM_LOA) {
                throw new ComponentValidationException("LoA value must be greater than or equal to " + Constants.MINIMUM_LOA + " for ACR '" + key + "'");
            }
            return parsedLoa;
        } catch (NumberFormatException e) {
            throw new ComponentValidationException("LoA value must be an integer for ACR '" + key + "'");
        }
    }

    private String toString(Object value) {
        return value != null ? value.toString().trim() : null;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(Constants.ACR_LOA_MAP)
                .label("ACR to LoA Map")
                .helpText("Maps CAS AuthnContextClassRef values to Keycloak levels of authentication.")
                .type(ProviderConfigProperty.MAP_TYPE)
                .add()
                .property()
                .name(MINIMUM_ACR_CONFIG)
                .label("Minimum ACR Value")
                .helpText("Minimum ACR to be enforced by Keycloak for CAS requests.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()
                .build();
    }
}
