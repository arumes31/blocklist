const {test} = require('node:test');
const assert = require('node:assert/strict');
const BlocklistPager = require('../cmd/server/static/js/blocklist-pager.js');

test('all 20k results remain reachable with only one page retained', () => {
    const pager = new BlocklistPager();
    const seen = new Set();
    for (let page = 0; page < 200; page++) {
        const request = pager.begin(page);
        assert.equal(request.cursor, page ? `cursor-${page}` : null);
        const items = Array.from({length: 100}, (_, i) => ({ip: `ip-${page * 100 + i}`}));
        assert.equal(pager.accept(request, {items, next: page === 199 ? null : `cursor-${page + 1}`}), true);
        assert.equal(pager.items.length, 100);
        pager.items.forEach(item => {assert.equal(seen.has(item.ip), false); seen.add(item.ip);});
    }
    assert.equal(seen.size, 20000);
    assert.equal(pager.begin(200), null);
    assert.equal(pager.starts.length, 200);
});

test('failed navigation preserves the current page and can be retried', () => {
    const pager = new BlocklistPager();
    pager.accept(pager.begin(0), {items: [{ip: 'first'}], next: 'next'});
    pager.begin(1); // A failed fetch is never accepted.
    assert.equal(pager.index, 0);
    assert.equal(pager.items[0].ip, 'first');
    assert.equal(pager.begin(1).cursor, 'next');
});

test('previous pages reuse their starting cursor and replace the visible rows', () => {
    const pager = new BlocklistPager();
    pager.accept(pager.begin(0), {items: [{ip: 'first'}], next: 'next'});
    pager.accept(pager.begin(1), {items: [{ip: 'second'}], next: null});
    const back = pager.begin(0);
    assert.equal(back.cursor, null);
    pager.accept(back, {items: [{ip: 'first'}], next: 'new-next'});
    assert.deepEqual(pager.items, [{ip: 'first'}]);
    assert.equal(pager.begin(1).cursor, 'new-next');
});

test('filter reset and newer requests reject stale responses', () => {
    const pager = new BlocklistPager();
    const stale = pager.begin(0);
    pager.reset();
    const current = pager.begin(0);
    assert.equal(pager.accept(stale, {items: [{ip: 'old'}], next: 'old'}), false);
    pager.accept(current, {items: [], next: null});
    assert.deepEqual(pager.items, []);
    assert.equal(pager.begin(-1), null);
    assert.equal(pager.begin(1), null);
});
