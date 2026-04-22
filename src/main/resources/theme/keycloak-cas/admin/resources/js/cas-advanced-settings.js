const CAS_PROTOCOL = "cas";
const ACR_LOA_MAP = "acr.loa.map";
const ACR_URI_MAP = "acr.uri.map";
const MINIMUM_ACR_VALUE = "minimum.acr.value";
const FIELD_ID = "kc-cas-minimum-acr-value";
const CONTAINER_ID = "kc-cas-minimum-acr-value-field";

const state = {
    client: undefined,
    realm: undefined,
    minimumAcrValue: "",
};
const originalFetch = window.fetch.bind(window);

window.fetch = async (input, init = {}) => {
    const requestUrl = getRequestUrl(input);
    const method = getRequestMethod(input, init);
    const clientMatch = matchClientEndpoint(requestUrl);


    if (method === "PUT" && clientMatch) {
        init = applyMinimumAcrToClientUpdate(input, init);
    }

    const response = await originalFetch(input, init);

    if (method === "GET" && response.ok) {
        if (clientMatch) {
            response
                .clone()
                .json()
                .then((client) => {
                    if (client?.protocol === CAS_PROTOCOL) {
                        state.client = client;
                        state.minimumAcrValue =
                            client.attributes?.[MINIMUM_ACR_VALUE] ?? "";
                        scheduleRender();
                    }
                })
                .catch(() => undefined);
        }

        if (matchRealmEndpoint(requestUrl)) {
            response
                .clone()
                .json()
                .then((realm) => {
                    state.realm = realm;
                    scheduleRender();
                })
                .catch(() => undefined);
        }
    }

    return response;
};

function getRequestUrl(input) {
    return typeof input === "string" ? input : input?.href ?? "";
}

function getRequestMethod(input, init) {
    return (
        init?.method ??
        (typeof input !== "string" ? input?.method : undefined) ??
        "GET"
    ).toUpperCase();
}

function matchClientEndpoint(url) {
    return toPathname(url).match(/\/admin\/realms\/([^/]+)\/clients\/([^/]+)$/);
}

function matchRealmEndpoint(url) {
    return toPathname(url).match(/\/admin\/realms\/([^/]+)$/);
}

function toPathname(url) {
    try {
        return new URL(url, window.location.origin).pathname;
    } catch {
        return "";
    }
}

function applyMinimumAcrToClientUpdate(input, init) {
    const body = init.body ?? (typeof input !== "string" ? input?.body : null);
    if (typeof body !== "string") {
        return init;
    }

    try {
        const client = JSON.parse(body);
        if ((client.protocol ?? state.client?.protocol) !== CAS_PROTOCOL) {
            return init;
        }

        client.attributes = client.attributes ?? {};
        const value = getMinimumAcrValue();
        if (value) {
            client.attributes[MINIMUM_ACR_VALUE] = value;
        } else {
            delete client.attributes[MINIMUM_ACR_VALUE];
        }

        state.client = client;
        state.minimumAcrValue = value;
        return { ...init, body: JSON.stringify(client) };
    } catch {
        return init;
    }
}

function getMinimumAcrValue() {
    return document.getElementById(FIELD_ID)?.value ?? state.minimumAcrValue ?? "";
}

function scheduleRender() {
    window.requestAnimationFrame(renderMinimumAcrField);
}

function renderMinimumAcrField() {
    const existing = document.getElementById(CONTAINER_ID);

    if (!isCasAdvancedTab()) {
        existing?.remove();
        return;
    }

    const description = Array.from(document.querySelectorAll("p"))
        .find(el => el.textContent.includes("advancedSettingsCas"));

    if (!description) {
        return;
    }

    let form = description.closest("form");
    if (!form) {
        const next = description.nextElementSibling;
        if (next && next.tagName === "FORM") {
            form = next;
        }
    }
    if (!form) {
        const parent = description.parentElement;
        if (parent) {
            form = parent.querySelector("form");
        }
    }
    if (!form) {
        return;
    }
    description.textContent = description.textContent.replace("advancedSettingsCas", "This section is used to configure advanced settings of this client.");
    const container = existing ?? createMinimumAcrField();
    const select = container.querySelector("select");

    const options = getAcrOptions();


    setOptions(select, options);
    select.value = state.minimumAcrValue;

    if (!existing) {
        form.insertBefore(container, form.firstChild);
    }
}

function isCasAdvancedTab() {
    const path = window.location.pathname;
    const hash = window.location.hash;

    const result =
        state.client?.protocol === CAS_PROTOCOL &&
        hash.includes("/clients/") &&
        hash.includes("/advanced");

    return result;
}

function createMinimumAcrField() {
    const container = document.createElement("div");
    container.id = CONTAINER_ID;
    container.className = "pf-v5-c-form__group";
    container.innerHTML = `
    <div class="pf-v5-c-form__group-label">
      <label class="pf-v5-c-form__label" for="${FIELD_ID}">
        <span class="pf-v5-c-form__label-text">Minimum ACR Value</span>
      </label>
      <button class="pf-v5-c-form__group-label-help" type="button" aria-label="Minimum ACR Value help" title="Minimum ACR to be enforced by Keycloak for CAS requests.">
        <span class="pf-v5-c-form__group-label-help-icon">?</span>
      </button>
    </div>
    <div class="pf-v5-c-form__group-control">
      <select class="pf-v5-c-form-control" id="${FIELD_ID}" aria-label="Minimum ACR Value"></select>
    </div>
  `;

    container.querySelector("select").addEventListener("change", (event) => {
        state.minimumAcrValue = event.target.value;
    });

    return container;
}

function getAcrOptions() {
    const clientAcrLoa = parseJsonAttribute(
        state.client?.attributes?.[ACR_LOA_MAP],
    );
    if (clientAcrLoa && Object.keys(clientAcrLoa).length > 0) {
        return Object.keys(clientAcrLoa);
    }

    const realmAcrUriMap = parseJsonAttribute(
        state.realm?.attributes?.[ACR_URI_MAP],
    );
    if (realmAcrUriMap && Object.keys(realmAcrUriMap).length > 0) {
        return Object.values(realmAcrUriMap);
    }

    return state.minimumAcrValue ? [state.minimumAcrValue] : [];
}

function parseJsonAttribute(value) {
    if (!value) {
        return undefined;
    }

    try {
        return JSON.parse(value);
    } catch {
        return undefined;
    }
}

function setOptions(select, values) {
    const previousValue = select.value || state.minimumAcrValue;
    const uniqueValues = [...new Set(values.filter(Boolean))];
    if (previousValue && !uniqueValues.includes(previousValue)) {
        uniqueValues.push(previousValue);
    }

    select.replaceChildren(
        createOption("", "Choose"),
        ...uniqueValues.map((value) => createOption(value, value)),
    );
}

function createOption(value, label) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    return option;
}

window.addEventListener("popstate", scheduleRender);
window.addEventListener("hashchange", scheduleRender);

for (const method of ["pushState", "replaceState"]) {
    const original = window.history[method];
    window.history[method] = function patchedHistoryMethod(...args) {
        const result = original.apply(this, args);
        scheduleRender();
        return result;
    };
}
