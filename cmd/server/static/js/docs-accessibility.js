(function () {
    'use strict';

    // RapiDoc's request fields live inside nested shadow roots. Add accessible
    // names without modifying the vendor bundle or triggering component renders.
    const observedRoots = new WeakSet();
    const pendingHosts = new WeakSet();
    const targets = 'api-request,input[id^="input-request-param-"],textarea';

    function labelField(field) {
        if (field.hasAttribute('aria-label') || field.hasAttribute('aria-labelledby') ||
            field.labels?.length) return;
        const name = field.localName === 'textarea'
            ? 'Request body'
            : 'Parameter: ' + field.id.slice('input-request-param-'.length);
        field.setAttribute('aria-label', name);
    }

    function inspect(node) {
        if (node.nodeType !== Node.ELEMENT_NODE) return;
        if (node.localName === 'api-request') attach(node);
        else if (node.matches('input[id^="input-request-param-"],textarea')) labelField(node);
        node.querySelectorAll(targets).forEach(child => {
            if (child.localName === 'api-request') attach(child);
            else labelField(child);
        });
    }

    async function attach(host) {
        if (pendingHosts.has(host)) return;
        pendingHosts.add(host);
        await customElements.whenDefined(host.localName);
        await host.updateComplete;
        const root = host.shadowRoot;
        if (!root || observedRoots.has(root)) return;
        observedRoots.add(root);
        // Observe additions only: our aria-label writes cannot feed this observer
        // back into itself, and no scroll position/style is ever changed.
        new MutationObserver(records => {
            for (const record of records) record.addedNodes.forEach(inspect);
        }).observe(root, {childList: true, subtree: true});
        root.querySelectorAll(targets).forEach(inspect);
    }

    document.querySelectorAll('rapi-doc').forEach(attach);
}());
