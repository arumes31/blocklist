const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const template = fs.readFileSync(path.join(__dirname, '../cmd/server/templates/dashboard.html'), 'utf8');

// Execute the shipped handlers, not copied implementations. Browser tests cover
// their actual DOM wiring; these fast tests cover API contracts and error paths.
function handlerSource(start, end) {
    const first = template.indexOf(start);
    assert.notEqual(first, -1, `Missing handler: ${start}`);
    const last = template.indexOf(end, first);
    assert.notEqual(last, -1, `Missing handler boundary: ${end}`);
    return template.slice(first, last);
}

test('Clear All empties every search control, country selection and saved view before searching once', async () => {
    const ids = ['filterInput', 'addedByFilter', 'fromDateFilter', 'toDateFilter', 'countrySearch', 'savedViews'];
    const fields = Object.fromEntries(ids.map(id => [id, {value: `selected-${id}`}]));
    const countries = [{checked: true}, {checked: true}, {checked: false}];
    const clearedTimers = [];
    let countryRefreshes = 0;
    let searches = 0;
    const context = vm.createContext({
        document: {
            getElementById: id => fields[id],
            querySelectorAll: selector => {
                assert.equal(selector, '#countryList input[type="checkbox"]');
                return countries;
            },
        },
        debounceTimeout: 17,
        clearTimeout: timer => clearedTimers.push(timer),
        filterCountryList: () => countryRefreshes++,
        applyServerSearch: async () => {
            searches++;
            for (const field of Object.values(fields)) assert.equal(field.value, '');
            for (const country of countries) assert.equal(country.checked, false);
        },
    });
    vm.runInContext(handlerSource('function clearFilters()', 'function updateURL()'), context);
    await context.clearFilters();
    assert.deepEqual(clearedTimers, [17]);
    assert.equal(countryRefreshes, 1);
    assert.equal(searches, 1);
});

for (const format of ['csv', 'ndjson']) {
    test(`${format} export uses server filter names and preserves encoded values and dates`, () => {
        const filters = {
            query: 'brute force & test + /', country: 'AT,DE', addedBy: 'operator (192.0.2.1)',
            from: '2026-01-01T03:15:00+02:00', to: '2026-10-01T22:00:00Z', empty: '',
        };
        const context = vm.createContext({window: {location: {}}, currentFilters: filters, URLSearchParams});
        vm.runInContext(handlerSource('window.exportData = function', '// UI Helpers'), context);
        context.window.exportData(format);
        const url = new URL(context.window.location.href, 'https://blocklist.invalid');
        assert.equal(url.pathname, '/api/v1/ips/export');
        assert.deepEqual(Object.fromEntries(url.searchParams), {
            format, query: filters.query, country: filters.country, added_by: filters.addedBy,
            from: '2026-01-01T01:15:00.000Z', to: '2026-10-01T22:00:00.000Z',
        });
    });
}

function blockHarness(response) {
    const fields = {
        ipToBlock: {value: '192.0.2.4'}, blockReason: {value: 'UI regression fixture'},
        blockTTL: {value: '3600'}, persistCheckbox: {checked: true},
    };
    const requests = [];
    const closed = [];
    const messages = [];
    const context = vm.createContext({
        document: {getElementById: id => fields[id]},
        fetch: async (url, options) => {
            requests.push({url, method: options.method, body: JSON.parse(options.body)});
            if (response instanceof Error) throw response;
            return response;
        },
        closeModal: id => closed.push(id),
        showToast: (text, kind) => messages.push({text, kind}),
    });
    vm.runInContext(handlerSource('function confirmBlock()', '</script>'), context);
    return {context, fields, requests, closed, messages};
}

for (const status of ['blocked', 'success']) {
    test(`block dialog recognizes the ${status} success response and resets only after success`, async () => {
        const state = blockHarness({ok: true, json: async () => ({status})});
        await state.context.confirmBlock();
        assert.deepEqual(state.requests, [{
            url: '/block', method: 'POST',
            body: {ip: '192.0.2.4', reason: 'UI regression fixture', persist: true, ttl: 3600},
        }]);
        assert.deepEqual(state.closed, ['blockModal']);
        for (const id of ['ipToBlock', 'blockReason', 'blockTTL']) assert.equal(state.fields[id].value, '');
        assert.equal(state.messages.length, 0);
    });
}

test('block failure preserves the form and reports the server validation error', async () => {
    const state = blockHarness({ok: false, json: async () => ({error: 'Invalid IP address'})});
    await state.context.confirmBlock();
    assert.equal(state.fields.ipToBlock.value, '192.0.2.4');
    assert.equal(state.fields.blockReason.value, 'UI regression fixture');
    assert.deepEqual(state.closed, []);
    assert.deepEqual(state.messages, [{text: 'Invalid IP address', kind: 'danger'}]);
});

test('block network failure preserves input and gives a retryable error without rejection', async () => {
    const state = blockHarness(new Error('offline'));
    await state.context.confirmBlock();
    assert.equal(state.fields.ipToBlock.value, '192.0.2.4');
    assert.deepEqual(state.closed, []);
    assert.deepEqual(state.messages, [{text: 'Could not block the IP. Please try again.', kind: 'danger'}]);
});

test('block validation prevents an empty IP from creating a request', async () => {
    const state = blockHarness({ok: true, json: async () => ({status: 'blocked'})});
    state.fields.ipToBlock.value = '';
    await state.context.confirmBlock();
    assert.deepEqual(state.requests, []);
    assert.deepEqual(state.closed, []);
    assert.deepEqual(state.messages, [{text: 'Enter an IP', kind: 'danger'}]);
});

/**
 * Execute the shipped stats renderer in a VM with controlled health/stats fetches.
 * Returns mutable payload/failure state, DOM stubs, and request/error recordings
 * so refresh behavior can be tested without a browser or live server.
 */
function statsHarness() {
    const fields = Object.fromEntries(['stat-countries', 'stat-asns', 'stat-reasons'].map(id => [id, {innerHTML: 'previous entries'}]));
    fields['health-dot'] = {style: {}, title: ''};
    const requests = [];
    const errors = [];
    const state = {payload: {}, failure: null};
    const context = vm.createContext({
        document: {getElementById: id => fields[id]},
        fetch: async url => {
            requests.push(url);
            if (url === '/health') return {ok: true, json: async () => ({status: 'UP'})};
            assert.equal(url, '/api/v1/stats');
            if (state.failure) throw state.failure;
            return {ok: true, json: async () => state.payload};
        },
        updateLastBlockDisplay: () => {},
        syncInsightFilters: () => {},
        console: {error: (...args) => errors.push(args)},
    });
    vm.runInContext(handlerSource('function escapeHTML(str)', '// UI Event Listeners'), context);
    vm.runInContext(handlerSource('let statsLoading = false;', 'setInterval('), context);
    return {state, context, fields, requests, errors};
}

test('each stats refresh retains every top entry and the initial chip presentation', async () => {
    const {state, context, fields, errors} = statsHarness();
    for (const increment of [0, 1, 2]) {
        state.payload = {
            top_countries: Array.from({length: 10}, (_, i) => ({country: `C${i}`, count: 100 - i + increment})),
            top_asns: Array.from({length: 10}, (_, i) => ({asn: 64000 + i, asn_org: `Network ${i}`, count: 100 - i + increment})),
            top_reasons: Array.from({length: 10}, (_, i) => ({reason: `Long reason ${i}`, count: 100 - i + increment})),
        };
        await context.refreshStats();
        assert.deepEqual(errors, []);
        for (const id of ['stat-countries', 'stat-asns', 'stat-reasons']) {
            const html = fields[id].innerHTML;
            assert.equal((html.match(/title="/g) || []).length, 10, 'No client-only top-three limit');
            assert.equal((html.match(/class="insight-chip"/g) || []).length, 10, id);
            assert.equal((html.match(/<button type="button"/g) || []).length, 10, 'Native keyboard controls');
            assert.equal((html.match(/data-insight-value="/g) || []).length, 10, 'Refreshed chips keep their filter value');
            assert.equal((html.match(/class="insight-count"/g) || []).length, 10, id);
            assert.ok(html.includes(`>${91 + increment}</span>`), 'The tenth entry updates too');
            assert.doesNotMatch(html, /style=/, 'Use the same shared classes as initial rendering');
        }
    }
});

test('stats labels, tooltips and counts remain HTML escaped', async () => {
    const {state, context, fields, errors} = statsHarness();
    const hostile = '\"><img src=x onerror="alert(1)"> & \'text\'';
    state.payload = {
        top_countries: [{country: hostile, count: hostile}],
        top_asns: [{asn: hostile, asn_org: hostile, count: hostile}],
        top_reasons: [{reason: hostile, count: hostile}],
    };
    await context.refreshStats();
    assert.deepEqual(errors, []);
    for (const id of ['stat-countries', 'stat-asns', 'stat-reasons']) {
        assert.doesNotMatch(fields[id].innerHTML, /<img|onerror="/);
        assert.match(fields[id].innerHTML, /&quot;&gt;&lt;img/);
        assert.match(fields[id].innerHTML, /&amp; &#039;text&#039;/);
    }
});

test('stats preserve previous entries on absent fields or failure, clear empty lists, and recover', async () => {
    const {state, context, fields, requests, errors} = statsHarness();
    await context.refreshStats(false);
    assert.deepEqual(requests, ['/health']);
    await context.refreshStats();
    for (const id of ['stat-countries', 'stat-asns', 'stat-reasons']) assert.equal(fields[id].innerHTML, 'previous entries');
    state.failure = new Error('offline');
    await context.refreshStats();
    assert.equal(errors.length, 1);
    for (const id of ['stat-countries', 'stat-asns', 'stat-reasons']) assert.equal(fields[id].innerHTML, 'previous entries');
    state.failure = null;
    state.payload = {top_countries: [], top_asns: [], top_reasons: []};
    await context.refreshStats();
    for (const id of ['stat-countries', 'stat-asns', 'stat-reasons']) assert.equal(fields[id].innerHTML, '');
    assert.equal(fields['health-dot'].title, 'System Health: OK');
});

/**
 * Execute the shipped insight-filter handlers against stubbed controls and chips.
 * Returns the VM, mutable form state, and recorded searches/messages; its search
 * stub synchronizes pressed states so tests can check filter preservation.
 */
function insightHarness() {
    const input = {value: ''};
    const countries = ['US', 'AT', 'DE'].map(value => ({value, checked: false}));
    const chips = [['country', 'US'], ['asn', '396982'], ['reason', 'ISDB-*-Scanner']].map(([field, value]) => ({
        dataset: {insightFilter: field, insightValue: value},
        setAttribute(name, value) { this[name] = value; },
    }));
    const filters = {query: '', country: '', addedBy: 'operator', from: '2026-01-01T00:00', to: '2026-10-01T00:00'};
    const searches = [];
    const messages = [];
    const context = vm.createContext({
        currentFilters: filters,
        document: {
            getElementById: id => {
                assert.equal(id, 'filterInput');
                return input;
            },
            querySelectorAll: selector => selector === '.insight-chip' ? chips : countries,
        },
        showToast: (...args) => messages.push(args),
        applyServerSearch: async () => {
            filters.query = input.value.trim();
            filters.country = countries.filter(cb => cb.checked).map(cb => cb.value).join(',');
            searches.push({...filters});
            context.syncInsightFilters();
        },
    });
    vm.runInContext(handlerSource('function normalizeInsightQuery(', 'function clearFilters()'), context);
    return {context, input, countries, chips, filters, searches, messages};
}

test('country ranking selects one country, toggles off, and preserves the other search fields', async () => {
    const state = insightHarness();
    state.input.value = 'asn:396982';
    state.countries[1].checked = true;
    state.countries[2].checked = true;
    await state.context.applyInsightFilter('country', 'US');
    assert.deepEqual(state.searches[0], {
        query: 'asn:396982', country: 'US', addedBy: 'operator', from: '2026-01-01T00:00', to: '2026-10-01T00:00',
    });
    assert.deepEqual(state.countries.map(cb => cb.checked), [true, false, false]);
    assert.equal(state.chips[0]['aria-pressed'], 'true');
    await state.context.applyInsightFilter('country', 'us');
    assert.equal(state.searches[1].country, '');
    assert.equal(state.searches[1].query, 'asn:396982');
    assert.equal(state.chips[0]['aria-pressed'], 'false');
    await state.context.applyInsightFilter('country', 'unknown');
    assert.equal(state.searches.length, 2, 'Unknown country does not clear existing filters');
    assert.equal(state.messages.length, 1);
});

test('ASN and reason rankings set literal exact-field queries and toggle without clearing country', async () => {
    const state = insightHarness();
    state.countries[0].checked = true;
    await state.context.applyInsightFilter('asn', '396982');
    assert.equal(state.input.value, 'asn:396982');
    assert.equal(state.chips[1]['aria-pressed'], 'true');
    await state.context.applyInsightFilter('reason', 'ISDB-*-Scanner');
    assert.equal(state.input.value, 'reason:ISDB-*-Scanner');
    assert.equal(state.chips[1]['aria-pressed'], 'false');
    assert.equal(state.chips[2]['aria-pressed'], 'true');
    await state.context.applyInsightFilter('reason', 'isdb-*-scanner');
    assert.equal(state.input.value, '');
    assert.equal(state.chips[2]['aria-pressed'], 'false');
    await state.context.applyInsightFilter('reason', 'A:"B" & <test> / + *');
    assert.equal(state.input.value, 'reason:A:"B" & <test> / + *');
    assert.ok(state.searches.every(filters => filters.country === 'US' && filters.addedBy === 'operator'));
    await state.context.applyInsightFilter('unexpected', 'value');
    assert.equal(state.searches.length, 4);
});

test('ranking selection can be restored from saved or URL filters and cleared', () => {
    const {context, filters, chips} = insightHarness();
    filters.country = 'US,DE';
    filters.query = 'ASN:396982';
    context.syncInsightFilters();
    assert.deepEqual(chips.map(chip => chip['aria-pressed']), ['true', 'true', 'false']);
    filters.country = '';
    filters.query = '';
    context.syncInsightFilters();
    assert.deepEqual(chips.map(chip => chip['aria-pressed']), ['false', 'false', 'false']);
});

for (const [field, value, query] of [
    ['asn', '396982', 'ASN: 396982'],
    ['asn', '396982', ' \tAsN \t: 00396982 \n'],
    ['reason', 'ISDB-*-Scanner', ' REASON:  isdb-*-SCANNER '],
    ['reason', 'ISDB-*-Scanner', '\tReason \t: ISDB-*-Scanner\n'],
    ['reason', 'A:"B" & <test> / + *', ' REASON : a:"b" & <TEST> / + * '],
]) {
    test(`qualified insight filter normalizes and toggles off ${JSON.stringify(query)}`, async () => {
        const state = insightHarness();
        const chip = state.chips.find(chip => chip.dataset.insightFilter === field);
        chip.dataset.insightValue = value;
        state.filters.query = query;
        state.input.value = query;
        state.context.syncInsightFilters();
        assert.equal(chip['aria-pressed'], 'true');
        await state.context.applyInsightFilter(field, value);
        assert.equal(state.input.value, '');
        assert.equal(chip['aria-pressed'], 'false');
        assert.equal(state.searches.length, 1);
    });
}

test('insight comparison preserves literal reason spacing, punctuation and ordinary searches', async () => {
    for (const query of ['ISDB-*-Scanner', 'reason:ISDB-*-Scanner-extra', 'reason:ISDB-*- Scanner', 'asn:3969820', '2001:db8::1']) {
        const state = insightHarness();
        state.filters.query = query;
        state.input.value = query;
        state.context.syncInsightFilters();
        assert.ok(state.chips.every(chip => chip['aria-pressed'] === 'false'), query);
        await state.context.applyInsightFilter('reason', 'ISDB-*-Scanner');
        assert.equal(state.input.value, 'reason:ISDB-*-Scanner');
    }
});

for (const kind of ['same chip', 'same list', 'empty list']) {
    test(`stats refresh restores focused insight to ${kind}`, async () => {
        const {state, context, errors} = statsHarness();
        const focused = [];
        const makeChip = value => ({
            dataset: {insightFilter: 'reason', insightValue: value},
            focus: options => { assert.equal(options.preventScroll, true); focused.push(value); },
        });
        const original = makeChip('Original');
        const next = makeChip('Next');
        const replacement = makeChip('Original');
        const chips = kind === 'empty list' ? [] : kind === 'same chip' ? [next, replacement] : [next];
        original.parentElement = {querySelectorAll: () => chips};
        context.document.activeElement = {closest: () => original};
        context.document.querySelectorAll = () => chips;
        const getElement = context.document.getElementById;
        context.document.getElementById = id => id === 'filterInput' ? {focus: () => focused.push('search')} : getElement(id);
        state.payload = {top_reasons: chips.map(chip => ({reason: chip.dataset.insightValue, count: 1}))};
        await context.refreshStats();
        assert.deepEqual(errors, []);
        assert.deepEqual(focused, [kind === 'empty list' ? 'search' : kind === 'same chip' ? 'Original' : 'Next']);
    });
}
