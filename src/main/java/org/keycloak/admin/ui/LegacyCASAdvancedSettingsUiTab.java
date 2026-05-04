package org.keycloak.admin.ui;

import java.util.Collections;
import java.util.Map;

public class LegacyCASAdvancedSettingsUiTab extends CASAdvancedSettingsUiTab {

    @Override
    public String getId() {
        return "CAS Advanced settings";
    }

    @Override
    public String getPath() {
        return "/__legacy-cas-advanced-settings";
    }

    @Override
    public Map<String, String> getParams() {
        return Collections.emptyMap();
    }
}
