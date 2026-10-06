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
