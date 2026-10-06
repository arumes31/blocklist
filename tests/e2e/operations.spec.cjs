const { test, expect, unique } = require('./fixtures.cjs');

// These addresses belong to RFC 5737 documentation ranges, never real hosts.
// Each project has its own addresses, and every test removes its own fixtures.
function testIP(info, offset) {
    const project = [...info.project.name].reduce((sum, character) => sum + character.charCodeAt(0), 0);
    return `198.51.100.${20 + ((project + offset) % 210)}`;
}

function responseFor(page, path, method = 'POST') {
    return page.waitForResponse(response => new URL(response.url()).pathname === path &&
        response.request().method() === method);
}

async function perform(page, path, action, method = 'POST') {
    const response = responseFor(page, path, method);
    await action();
    return response;
}

async function seedBlock(api, ip, reason) {
    const response = await api.post('/block', { data: { ip, reason, persist: true } });
    expect(response.ok(), await response.text()).toBeTruthy();
}

async function dashboardReady(page, query = '') {
    await page.goto(`/dashboard${query}`);
    await expect(page.locator('#pageStatus')).toContainText('Page 1');
}

function blockRow(page, ip) {
    return page.locator('#ipTableBody tr').filter({ has: page.getByText(ip, { exact: true }) });
}

function listRow(page, table, value) {
    return page.locator(`${table} tbody tr`).filter({ has: page.getByText(value, { exact: true }) });
}

function futureLocalDate() {
    return new Date(Date.now() + 2 * 86400000).toISOString().slice(0, 16);
}

test('dashboard block modal validates, submits, inspects, and unblocks the real record', async ({ page, api }, info) => {
    const ip = testIP(info, 1);
    const reason = unique('block-ui');
    try {
        await dashboardReady(page);
        const opener = page.locator('.page-actions').getByRole('button', { name: 'Block IP', exact: true });
        const modal = page.locator('#blockModal');
        await opener.click();
        await expect(modal).toBeVisible();
        await modal.getByRole('button', { name: 'Cancel', exact: true }).click();
        await expect(modal).toBeHidden();
        await opener.click();
        await page.keyboard.press('Escape');
        await expect(modal).toBeHidden();
        await opener.click();
        await modal.getByRole('button', { name: 'Block IP', exact: true }).click();
        await expect(page.locator('#toast-container')).toContainText('Enter an IP');
        for (const preset of ['Brute Force', 'Scraping', 'DDoS', 'Vulnerability Scan', 'Spam']) {
            await modal.getByRole('button', { name: preset, exact: true }).click();
            await expect(page.locator('#blockReason')).toHaveValue(preset);
        }
        await page.locator('#ipToBlock').fill(ip);
        await page.locator('#blockReason').fill(reason);
        await page.locator('#blockTTL').fill('3600');
        await page.locator('#persistCheckbox').check();
        const blocked = await perform(page, '/block', () => modal.getByRole('button', { name: 'Block IP', exact: true }).click());
        expect(blocked.ok()).toBeTruthy();
        expect(blocked.request().postDataJSON()).toEqual({ ip, reason, persist: true, ttl: 3600 });
        await expect(modal).toBeHidden();
        await expect(page.locator('#ipToBlock')).toHaveValue('');
        await page.locator('#refreshPage').click();
        const row = blockRow(page, ip);
        await expect(row).toContainText(reason);
        await row.locator('.ip-details-link').click();
        await expect(page.locator('#sidePanel')).toHaveClass(/active/);
        await expect(page.locator('#sidePanelContent')).toContainText(reason);
        await page.getByRole('button', { name: 'Close IP details' }).click();
        await expect(page.locator('#sidePanel')).not.toHaveClass(/active/);
        const unblocked = await perform(page, '/unblock', () => row.getByRole('button', { name: 'Unblock', exact: true }).click());
        expect(unblocked.ok()).toBeTruthy();
        expect(unblocked.request().postDataJSON().ip).toBe(ip);
        await expect(row).toHaveCount(0);
        await page.reload();
        await expect(blockRow(page, ip)).toHaveCount(0);
    } finally {
        await api.post('/unblock', { data: { ip } });
    }
});

test('dashboard selection, cancel, live pause, and bulk unblock preserve the selected records', async ({ page, api }, info) => {
    const ips = [testIP(info, 11), testIP(info, 12)];
    const reason = unique('bulk-ui');
    try {
        for (const ip of ips) await seedBlock(api, ip, reason);
        await dashboardReady(page, `?query=${encodeURIComponent(reason)}`);
        await expect(page.locator('#ipTableBody tr')).toHaveCount(2);
        await page.locator('#togglePause').click();
        await expect(page.locator('#togglePause')).toHaveText('Resume');
        await expect(page.locator('#live-status')).toHaveText('PAUSED');
        await page.locator('#togglePause').click();
        await expect(page.locator('#togglePause')).toHaveText('Pause');
        await page.locator('#selectAll').check();
        await expect(page.locator('#selectedCount')).toHaveText('2');
        await page.locator('#bulkActionBar').getByRole('button', { name: 'Cancel', exact: true }).click();
        await expect(page.locator('#bulkActionBar')).toBeHidden();
        for (const ip of ips) await expect(blockRow(page, ip).locator('.ip-checkbox')).not.toBeChecked();
        await blockRow(page, ips[0]).locator('.ip-checkbox').check();
        await expect(page.locator('#selectedCount')).toHaveText('1');
        await page.locator('#selectAll').check();
        page.once('dialog', dialog => dialog.dismiss());
        await page.getByRole('button', { name: 'Unblock All', exact: true }).click();
        await expect(page.locator('#selectedCount')).toHaveText('2');
        for (const ip of ips) await expect(blockRow(page, ip)).toBeVisible();
        page.once('dialog', dialog => dialog.accept());
        const response = await perform(page, '/bulk_unblock', () => page.getByRole('button', { name: 'Unblock All', exact: true }).click());
        expect(response.ok()).toBeTruthy();
        expect(response.request().postDataJSON().ips.sort()).toEqual([...ips].sort());
        await expect(page.locator('#bulkActionBar')).toBeHidden();
        await expect(page.locator('#ipTableBody tr')).toHaveCount(0);
    } finally {
        for (const ip of ips) await api.post('/unblock', { data: { ip } });
    }
});

test('dashboard country, text, actor, and date filters, chips, and Clear All work together', async ({ page, api }, info) => {
    const ip = testIP(info, 21);
    const reason = unique('filter-ui');
    try {
        await seedBlock(api, ip, reason);
        await dashboardReady(page);
        await page.locator('#filterInput').fill(reason);
        await expect(page).toHaveURL(new RegExp(`query=${reason}`));
        await expect(blockRow(page, ip)).toBeVisible();
        await page.locator('#addedByFilter').fill('missing-actor');
        await expect(page.locator('#ipTableBody tr')).toHaveCount(0);
        await page.locator('#filter-chips [data-filter-key="addedBy"]').click();
        await expect(page.locator('#addedByFilter')).toHaveValue('');
        await expect(blockRow(page, ip)).toBeVisible();
        await page.locator('#countryLabel').click();
        await page.locator('#countrySearch').fill('Austria');
        await expect(page.locator('#countryList label').filter({ hasText: 'Austria' })).toBeVisible();
        await page.locator('#countryList input[value="AT"]').check();
        await expect(page.locator('#countryLabel')).toHaveText('1 Countries Selected');
        await page.getByRole('heading', { name: 'Dashboard', exact: true }).click();
        await page.locator('#filter-chips [data-country="AT"]').click();
        await expect(page.locator('#countryLabel')).toHaveText('All Countries');
        await page.locator('#addedByFilter').fill('missing-actor');
        await page.locator('#fromDateFilter').fill('2020-01-01T00:00');
        await page.locator('#toDateFilter').fill('2090-01-01T00:00');
        await page.locator('#countryLabel').click();
        await page.locator('#countryList input[value="AT"]').check();
        await page.locator('#clearFilter').click();
        for (const selector of ['#filterInput', '#addedByFilter', '#fromDateFilter', '#toDateFilter']) {
            await expect(page.locator(selector)).toHaveValue('');
        }
        await expect(page.locator('#countryLabel')).toHaveText('All Countries');
        await expect(page.locator('#filter-chips')).toBeEmpty();
        await expect(blockRow(page, ip)).toBeVisible();
        expect(new URL(page.url()).searchParams.size).toBe(0);
    } finally {
        await api.post('/unblock', { data: { ip } });
    }
});

test('dashboard saved views, density, column controls, and filtered exports retain their behavior', async ({ page, api }, info) => {
    const ip = testIP(info, 31);
    const name = unique('saved-view');
    try {
        await seedBlock(api, ip, name);
        await dashboardReady(page, `?query=${name}`);
        const owner = (await blockRow(page, ip).locator('.col-by').innerText()).trim();
        await page.locator('#addedByFilter').fill(owner);
        await expect.poll(() => new URL(page.url()).searchParams.get('addedBy')).toBe(owner);
        await page.getByRole('button', { name: 'View Options', exact: true }).click();
        const options = page.locator('#viewOptionsPopup');
        await expect(options).toBeVisible();
        await options.getByLabel('Compact', { exact: true }).check();
        await expect(page.locator('#ipTable')).toHaveClass(/compact/);
        await options.getByLabel('Comfortable', { exact: true }).check();
        await expect(page.locator('#ipTable')).not.toHaveClass(/compact/);
        await options.getByLabel('Score', { exact: true }).uncheck();
        await expect(page.locator('#ipTable thead .col-score')).toBeHidden();
        await options.getByLabel('Score', { exact: true }).check();
        await expect(page.locator('#ipTable thead .col-score')).toBeVisible();
        await page.getByRole('button', { name: 'View Options', exact: true }).click();
        page.once('dialog', dialog => dialog.accept(name));
        const saved = await perform(page, '/api/v1/views', () => page.getByRole('button', { name: 'Save View', exact: true }).click());
        expect(saved.ok()).toBeTruthy();
        expect(saved.request().postDataJSON().name).toBe(name);
        expect(JSON.parse(saved.request().postDataJSON().filters).query).toBe(name);
        await expect(page.locator('#savedViews option').filter({ hasText: name })).toHaveCount(1);
        await page.locator('#clearFilter').click();
        await expect(page.locator('#filterInput')).toHaveValue('');
        await page.locator('#savedViews').selectOption({ label: name });
        await expect(page.locator('#filterInput')).toHaveValue(name);
        await expect(blockRow(page, ip)).toBeVisible();
        for (const label of ['CSV', 'JSON']) {
            const downloadPromise = page.waitForEvent('download');
            const exportRequest = page.waitForRequest(request => new URL(request.url()).pathname === '/api/v1/ips/export');
            await page.getByRole('button', { name: label, exact: true }).click();
            const parameters = new URL((await exportRequest).url()).searchParams;
            expect(parameters.get('format')).toBe(label === 'CSV' ? 'csv' : 'ndjson');
            expect(parameters.get('query')).toBe(name);
            expect(parameters.get('added_by')).toBe(owner);
            const download = await downloadPromise;
            expect(await download.failure()).toBeNull();
            const stream = await download.createReadStream();
            const chunks = [];
            for await (const chunk of stream) chunks.push(chunk);
            expect(Buffer.concat(chunks).toString('utf8')).toContain(ip);
        }
    } finally {
        const response = await api.get('/api/v1/views');
        if (response.ok()) {
            for (const view of (await response.json()) || []) {
                if (view.name === name) await api.delete(`/api/v1/views/${view.id}`);
            }
        }
        await api.post('/unblock', { data: { ip } });
    }
});

test('whitelist validates required fields and expiry, filters the created entry, and deletes it', async ({ page, api }, info) => {
    const ip = testIP(info, 41);
    const reason = unique('whitelist-ui');
    try {
        await page.goto('/whitelist');
        const add = page.getByRole('button', { name: 'Add to Whitelist', exact: true });
        await add.click();
        await expect(page.locator('#toast-container')).toContainText('Please enter an IP address');
        await page.locator('#whitelistIP').fill(ip);
        await add.click();
        await expect(page.locator('#toast-container')).toContainText('Reason is required');
        await page.locator('#whitelistReason').fill(reason);
        await page.locator('#expiryType').selectOption('custom');
        await expect(page.locator('#expiryDate')).toBeVisible();
        await add.click();
        await expect(page.locator('#toast-container')).toContainText('Please select an expiry date');
        const expiry = futureLocalDate();
        await page.locator('#expiryDate').fill(expiry);
        const expiresAt = await page.locator('#expiryDate').evaluate(input => new Date(input.value).toISOString());
        const created = await perform(page, '/add_whitelist', () => add.click());
        expect(created.ok()).toBeTruthy();
        expect(created.request().postDataJSON()).toEqual({ ip, reason, persist: true, expires_at: expiresAt });
        const row = listRow(page, '#whitelistTable', ip);
        await expect(row).toContainText(reason);
        await expect(row).not.toContainText('NEVER');
        await page.locator('#filterInput').pressSequentially('does-not-match');
        await expect(row).toBeHidden();
        await page.locator('#filterInput').fill('');
        await page.locator('#filterInput').pressSequentially(reason);
        await expect(row).toBeVisible();
        page.once('dialog', dialog => dialog.dismiss());
        await row.getByRole('button', { name: 'Delete', exact: true }).click();
        await expect(row).toBeVisible();
        page.once('dialog', dialog => dialog.accept());
        const deleted = await perform(page, '/remove_whitelist', () => row.getByRole('button', { name: 'Delete', exact: true }).click());
        expect(deleted.ok()).toBeTruthy();
        expect(deleted.request().postDataJSON()).toEqual({ ip });
        await expect(row).toHaveCount(0);
        await page.locator('#expiryType').selectOption('custom');
        await page.locator('#expiryType').selectOption('never');
        await expect(page.locator('#expiryDate')).toBeHidden();
    } finally {
        await api.post('/remove_whitelist', { data: { ip } });
    }
});

test('excluded entries validate, preserve alert and expiry settings, filter, and delete', async ({ page, api }, info) => {
    const value = testIP(info, 51);
    const reason = unique('excluded-ui');
    try {
        await page.goto('/excluded');
        const add = page.getByRole('button', { name: 'Add to Excluded', exact: true });
        await add.click();
        await expect(page.locator('#toast-container')).toContainText('Please enter an IP, subnet, or FQDN');
        await page.locator('#excludedValue').fill(` ${value} `);
        await add.click();
        await expect(page.locator('#toast-container')).toContainText('Description is required');
        await page.locator('#excludedReason').fill(` ${reason} `);
        await page.locator('#alertEnabled').check();
        await page.locator('#expiryType').selectOption('custom');
        await expect(page.locator('#expiryDate')).toBeVisible();
        await add.click();
        await expect(page.locator('#toast-container')).toContainText('Please select an expiry date');
        const expiry = futureLocalDate();
        await page.locator('#expiryDate').fill(expiry);
        const expiresAt = await page.locator('#expiryDate').evaluate(input => new Date(input.value).toISOString());
        const added = await perform(page, '/add_excluded', () => add.click());
        expect(added.ok()).toBeTruthy();
        expect(added.request().postDataJSON()).toEqual({ value, reason, alert_enabled: true, confirm: false, expires_at: expiresAt });
        const row = listRow(page, '#excludedTable', value);
        await expect(row).toContainText(reason);
        await expect(row).toContainText('ENABLED');
        await expect(row).not.toContainText('NEVER');
        await page.locator('#filterInput').pressSequentially('does-not-match');
        await expect(row).toBeHidden();
        await page.locator('#filterInput').fill('');
        await page.locator('#filterInput').pressSequentially(reason);
        await expect(row).toBeVisible();
        page.once('dialog', dialog => dialog.accept());
        const deleted = await perform(page, '/remove_excluded', () => row.getByRole('button', { name: 'Delete', exact: true }).click());
        expect(deleted.ok()).toBeTruthy();
        expect(deleted.request().postDataJSON()).toEqual({ value });
        await expect(row).toHaveCount(0);
    } finally {
        await api.post('/remove_excluded', { data: { value } });
    }
});

test('excluded conflict dialog can cancel safely or explicitly confirm a blocked address', async ({ page, api }, info) => {
    const value = testIP(info, 61);
    const reason = unique('conflict-ui');
    try {
        await seedBlock(api, value, reason);
        await page.goto('/excluded');
        await page.locator('#excludedValue').fill(value);
        await page.locator('#excludedReason').fill(reason);
        const add = page.getByRole('button', { name: 'Add to Excluded', exact: true });
        const first = await perform(page, '/add_excluded', () => add.click());
        expect(first.status()).toBe(409);
        const modal = page.locator('#conflictModal');
        await expect(modal).toBeVisible();
        await expect(page.locator('#conflictWarnings')).toContainText('currently blocked');
        await modal.getByRole('button', { name: 'Cancel', exact: true }).click();
        await expect(modal).toBeHidden();
        await expect(listRow(page, '#excludedTable', value)).toHaveCount(0);
        const second = await perform(page, '/add_excluded', () => add.click());
        expect(second.status()).toBe(409);
        const confirmed = await perform(page, '/add_excluded', () => modal.getByRole('button', { name: 'Proceed', exact: true }).click());
        expect(confirmed.ok()).toBeTruthy();
        expect(confirmed.request().postDataJSON().confirm).toBe(true);
        await expect(modal).toBeHidden();
        await expect(listRow(page, '#excludedTable', value)).toContainText(reason);
        // The warning promises no automatic unblock: verify that contract too.
        const blocked = await api.get('/api/v1/ips_list');
        expect((await blocked.json())[value]).toBeTruthy();
    } finally {
        await api.post('/remove_excluded', { data: { value } });
        await api.post('/unblock', { data: { ip: value } });
    }
});

test('external-source add and remove are real, while Refresh never contacts an outbound service', async ({ page, api }) => {
    const name = unique('source-ui');
    // Creation validates this public IP literal but does not fetch it. The isolated
    // harness disables workers; manual refresh is intercepted before reaching Go.
    const url = `https://1.1.1.1/${name}.txt`;
    let sourceID;
    try {
        await page.goto('/excluded');
        const add = page.getByRole('button', { name: 'Add Source', exact: true });
        await add.click();
        await expect(page.locator('#toast-container')).toContainText('Name and URL are required');
        await page.locator('#sourceName').fill(name);
        await page.locator('#sourceURL').fill(url);
        await page.locator('#sourceType').selectOption('json_cidr');
        const added = await perform(page, '/api/v1/excluded/sources', () => add.click());
        expect(added.ok()).toBeTruthy();
        expect(added.request().postDataJSON()).toEqual({ name, url, source_type: 'json_cidr' });
        const row = page.locator('tbody tr').filter({ has: page.getByText(name, { exact: true }) });
        await expect(row).toContainText(url);
        const remove = row.getByRole('button', { name: 'Remove', exact: true });
        sourceID = (await remove.getAttribute('onclick')).match(/deleteExternalSource\(\s*(\d+)\s*\)/)[1];
        let refreshes = 0;
        await page.route('**/api/v1/excluded/sources/refresh', async route => {
            expect(route.request().method()).toBe('POST');
            refreshes++;
            await route.fulfill({ status: 200, contentType: 'application/json', body: '{"status":"success"}' });
        });
        const refreshed = page.waitForEvent('load');
        await perform(page, '/api/v1/excluded/sources/refresh', () => page.getByRole('button', { name: 'Refresh All Now', exact: true }).click());
        expect(refreshes).toBe(1);
        await expect(page.locator('#toast-container')).toContainText('Refresh started');
        // Complete the scheduled page reload before interacting with its rows.
        await refreshed;
        await expect(row).toBeVisible();
        page.once('dialog', dialog => dialog.dismiss());
        await remove.click();
        await expect(row).toBeVisible();
        page.once('dialog', dialog => dialog.accept());
        const removed = await perform(page, `/api/v1/excluded/sources/${sourceID}`, () => remove.click(), 'DELETE');
        expect(removed.ok()).toBeTruthy();
        await expect(row).toHaveCount(0);
    } finally {
        if (!sourceID) {
            const html = await (await api.get('/excluded')).text();
            const row = (html.match(/<tr>[\s\S]*?<\/tr>/g) || []).find(value => value.includes(name));
            sourceID = row?.match(/deleteExternalSource\(\s*(\d+)\s*\)/)?.[1];
        }
        if (sourceID) await api.delete(`/api/v1/excluded/sources/${sourceID}`);
    }
});

test('dashboard keeps visible records on a failed refresh and Retry loads real data again', async ({ page, api }, info) => {
    const ip = testIP(info, 71);
    const reason = unique('retry-ui');
    try {
        await seedBlock(api, ip, reason);
        await dashboardReady(page, `?query=${reason}`);
        await expect(blockRow(page, ip)).toBeVisible();
        await page.route('**/api/v1/ips?*', route => route.fulfill({
            status: 503, contentType: 'application/json', body: '{"error":"controlled browser-test failure"}',
        }), { times: 1 });
        await page.locator('#refreshPage').click();
        await expect(page.locator('#pageStatus')).toContainText('Could not load results');
        await expect(page.locator('#refreshPage')).toHaveText('Retry');
        await expect(blockRow(page, ip)).toContainText(reason);
        await page.locator('#refreshPage').click();
        await expect(page.locator('#pageStatus')).toContainText('Page 1');
        await expect(page.locator('#refreshPage')).toHaveText('Refresh');
        await expect(blockRow(page, ip)).toContainText(reason);
    } finally {
        await api.post('/unblock', { data: { ip } });
    }
});

test('dashboard Next, Previous, and Refresh traverse actual server-side pages without losing rows', async ({ page, api }, info) => {
    const subnet = info.project.name === 'mobile' ? '203.0.113' : '192.0.2';
    const ips = Array.from({ length: 101 }, (_, index) => `${subnet}.${index + 10}`);
    const reason = unique('paging-ui');
    try {
        const seeded = await api.post('/bulk_block', { data: { ips, reason, persist: true } });
        expect(seeded.ok(), await seeded.text()).toBeTruthy();
        await dashboardReady(page, `?query=${reason}`);
        await expect(page.locator('#ipTableBody tr')).toHaveCount(100);
        await expect(page.locator('#previousPage')).toBeDisabled();
        await expect(page.locator('#nextPage')).toBeEnabled();
        const firstPage = await page.locator('#ipTableBody .ip-details-link').allTextContents();
        await page.locator('#nextPage').click();
        await expect(page.locator('#pageStatus')).toContainText('Page 2');
        await expect(page.locator('#ipTableBody tr')).toHaveCount(1);
        await expect(page.locator('#nextPage')).toBeDisabled();
        const secondPage = await page.locator('#ipTableBody .ip-details-link').allTextContents();
        expect([...firstPage, ...secondPage].sort()).toEqual([...ips].sort());
        await page.locator('#refreshPage').click();
        await expect(page.locator('#pageStatus')).toContainText('Page 2');
        await expect(page.locator('#ipTableBody .ip-details-link')).toHaveText(secondPage);
        await page.locator('#previousPage').click();
        await expect(page.locator('#pageStatus')).toContainText('Page 1');
        await expect(page.locator('#ipTableBody .ip-details-link')).toHaveText(firstPage);
    } finally {
        await api.post('/bulk_unblock', { data: { ips } });
    }
});
