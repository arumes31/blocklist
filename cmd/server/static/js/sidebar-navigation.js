(() => {
    const storageKey = 'blocklist.sidebar.navigation';
    const openAttribute = 'data-sidebar-navigation-open';
    const root = document.documentElement;
    const desktop = window.matchMedia('(min-width: 992px)');
    let pending = false;
    let carried = null;

    // Run before the sidebar markup so a new page starts open, not mid-transition.
    try {
        const stored = sessionStorage.getItem(storageKey);
        sessionStorage.removeItem(storageKey);
        const saved = JSON.parse(stored);
        const age = Date.now() - saved?.time;
        if (desktop.matches && saved?.path === location.pathname + location.search && age >= 0 && age < 60000) {
            carried = saved;
            root.setAttribute(openAttribute, '');
        }
    } catch {
        // Storage may be disabled. CSS hover/focus and ordinary links still work.
    }

    function release() {
        root.removeAttribute(openAttribute);
        if (pending) {
            try { sessionStorage.removeItem(storageKey); } catch {}
            pending = false;
        }
    }

    function releaseOutside(event) {
        if (root.hasAttribute(openAttribute) && !event.target.closest('.app-sidebar')) release();
    }

    document.addEventListener('pointermove', releaseOutside, { passive: true });
    document.addEventListener('pointerdown', releaseOutside, { passive: true });
    document.addEventListener('focusin', releaseOutside);
    desktop.addEventListener('change', () => { if (!desktop.matches) release(); });

    document.addEventListener('click', event => {
        const link = event.target.closest('.app-sidebar a');
        if (!link || event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
        if (!desktop.matches || !link.matches('.nav-link, .app-brand') || link.hasAttribute('download') || (link.target && link.target !== '_self')) return;
        const url = new URL(link.href);
        if (url.origin !== location.origin || url.hash) return;

        const sidebar = link.closest('.app-sidebar');
        const handoff = {
            path: url.pathname + url.search,
            time: Date.now(),
            keyboard: event.detail === 0,
            scrollTop: sidebar.querySelector('.sidebar-inner').scrollTop,
        };
        try {
            sessionStorage.setItem(storageKey, JSON.stringify(handoff));
            pending = true;
            root.setAttribute(openAttribute, '');
        } catch {}
        // Keep normal navigation, browser history, and modified/new-tab clicks.
    });

    document.addEventListener('DOMContentLoaded', () => {
        if (!carried || !desktop.matches || !root.hasAttribute(openAttribute)) return;
        const sidebar = document.querySelector('.app-sidebar');
        if (!sidebar) { release(); return; }
        const inner = sidebar.querySelector('.sidebar-inner');
        if (Number.isFinite(carried.scrollTop)) inner.scrollTop = carried.scrollTop;
        if (carried.keyboard) {
            const current = [...sidebar.querySelectorAll('.nav-link')].find(link => {
                const url = new URL(link.href);
                return url.pathname + url.search === carried.path;
            });
            current?.focus({ preventScroll: true });
            release(); // :focus-within now owns keyboard expansion.
        }
        carried = null;
    }, { once: true });
})();
