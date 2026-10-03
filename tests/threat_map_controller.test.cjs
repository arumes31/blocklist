const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const data = require('../cmd/server/static/js/threat-map-data.js');

const controller = fs.readFileSync(path.join(__dirname, '../cmd/server/static/js/threat-map.js'), 'utf8');
const template = fs.readFileSync(path.join(__dirname, '../cmd/server/templates/threat_map.html'), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));
const item = ip => ({ip, data:{geolocation:{latitude:48, longitude:16}, reason:'Scanner'}});

// Only the browser surfaces used by the controller are modeled here. Geography,
// layout and painting remain covered by the renderer and real-browser checks.
function harness({statsAllowed = false, showWhitelist = false} = {}) {
    class Element {
        constructor() {
            this.children = [];
            this.events = new Map();
            this.attributes = new Map();
            this.dataset = {};
            this.style = {};
            this.className = '';
            this.classList = {toggle() {}};
            this.hidden = false;
        }
        set textContent(value) { this.text = String(value); this.children = []; }
        get textContent() { return (this.text || '') + this.children.map(child => child.textContent).join(''); }
        append(...nodes) { nodes.forEach(node => { node.parent = this; this.children.push(node); }); }
        prepend(node) { node.parent = this; this.children.unshift(node); }
        replaceChildren(...nodes) { this.children = []; this.text = ''; this.append(...nodes); }
        remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); }
        get lastElementChild() { return this.children.at(-1); }
        querySelector(selector) { return this.children.find(child => `.${child.className}` === selector) || null; }
        setAttribute(name, value) { this.attributes.set(name, value); }
        addEventListener(name, callback) { this.events.set(name, callback); }
        emit(name, event = {}) { return this.events.get(name)?.(event); }
    }

    const elements = new Map(Array.from(template.matchAll(/\bid="([^"]+)"/g), match => [match[1], new Element()]));
    const get = id => { assert.ok(elements.has(id), `template must contain #${id}`); return elements.get(id); };
    get('threat-map-bootstrap').textContent = JSON.stringify({stats_allowed:statsAllowed, trend_available:false});
    get('toggle-blocked').checked = true;
    get('toggle-whitelist').checked = showWhitelist;
    get('toggle-paths').checked = true;
    get('toggle-cluster').checked = true;
    get('region').value = 'global';
    const placeholder = new Element();
    placeholder.className = 'empty-state';
    placeholder.textContent = 'Awaiting events…';
    get('event-stream').append(placeholder);
    const buttons = (key, values) => values.map(value => { const button = new Element(); button.dataset[key] = value; return button; });
    const views = buttons('view', ['globe', 'flat']);
    const layers = buttons('layer', ['routes', 'density']);
    const document = new Element();
    document.body = new Element();
    document.hidden = false;
    document.getElementById = get;
    document.createElement = () => new Element();
    document.querySelectorAll = selector => {
        if (selector === '[data-view]') return views;
        if (selector === '[data-layer]') return layers;
        if (selector === '.origin-row') return get('origin-list').children.filter(child => child.className === 'origin-row');
        throw new Error(`Unexpected selector: ${selector}`);
    };

    let clock = 0, timerID = 0;
    const timers = new Map();
    function timer(callback, delay, interval = false) {
        const id = ++timerID;
        timers.set(id, {callback, at:clock + delay, delay, interval});
        return id;
    }
    async function advance(milliseconds) {
        const end = clock + milliseconds;
        for (;;) {
            const next = [...timers].filter(([, task]) => task.at <= end).sort((a,b) => a[1].at - b[1].at)[0];
            if (!next) break;
            const [id, task] = next;
            clock = task.at;
            if (task.interval) task.at += task.delay;
            else timers.delete(id);
            task.callback();
            await flush();
        }
        clock = end;
        await flush();
    }

    const requests = [];
    function fetch(url, {signal} = {}) {
        return new Promise((resolve, reject) => {
            const request = {url, signal, respond(payload, status = 200) {
                resolve({ok:status >= 200 && status < 300, status, redirected:false, json:async () => payload});
            }};
            signal?.addEventListener('abort', () => reject(new Error('Aborted')));
            requests.push(request);
        });
    }
    const sockets = [];
    class Socket {
        constructor() { sockets.push(this); }
        open() { this.onopen?.(); }
        send(action, payload) { this.onmessage?.({data:JSON.stringify({action, data:payload})}); }
        close() { this.closed = true; this.onclose?.(); }
    }
    let scene;
    class Scene {
        constructor(canvas, options) { scene = this; this.options = options; this.points = []; this.retryResult = true; this.retries = 0; }
        setPoints(points) { this.points = points; }
        setPaths(paths) { this.paths = paths; }
        setPaused(paused) { this.paused = paused; }
        setLayer() {}
        setRegion() {}
        focusPoint() {}
        reset() {}
        zoomBy() {}
        destroy() { this.destroyed = true; }
        retryGeography() { this.retries++; return Promise.resolve(this.retryResult); }
    }
    const media = new Element();
    media.matches = false;
    const window = new Element();
    window.ThreatMapData = data;
    vm.runInNewContext(controller, {
        window, document, matchMedia:() => media, ThreatMapScene:Scene, WebSocket:Socket,
        location:{protocol:'https:', host:'blocklist.test'}, fetch, AbortController,
        setTimeout:(callback, delay) => timer(callback, delay), clearTimeout:id => timers.delete(id),
        setInterval:(callback, delay) => timer(callback, delay, true), clearInterval:id => timers.delete(id),
    }, {filename:'threat-map.js'});
    return {get, document, window, requests, sockets, scene, advance,
        points:() => Array.from(scene.points, point => point.ip),
        stop:() => window.emit('pagehide', {persisted:false}),
    };
}

test('delayed snapshots preserve newer block, unblock and whitelist events', async t => {
    const h = harness({showWhitelist:true});
    t.after(h.stop);
    h.sockets[0].send('unblock', {ip:'192.0.2.1'});
    h.sockets[0].send('block', item('192.0.2.2'));
    h.sockets[0].send('whitelist', item('192.0.2.3'));
    h.requests.find(request => request.url.startsWith('/api/v1/ips?')).respond({items:[item('192.0.2.1')], total:1, next:''});
    h.requests.find(request => request.url === '/api/v1/whitelists').respond([]);
    await flush();
    assert.deepEqual(h.points().sort(), ['192.0.2.2', '192.0.2.3']);
    assert.equal(h.get('event-stream').children.length, 3);
    assert.equal(h.get('event-stream').querySelector('.empty-state'), null);
    assert.match(h.get('data-status').textContent, /Data current/);
});

test('background refresh waits for a slow active request and schedules the next refresh', async t => {
    const h = harness();
    t.after(h.stop);
    const initial = h.requests[0];
    h.sockets[0].open();
    h.sockets[0].send('block', item('192.0.2.2'));
    await h.advance(6500);
    assert.equal(initial.signal.aborted, false, 'the five-second event timer must not cancel the snapshot');
    assert.equal(h.requests.length, 1);
    initial.respond({items:[item('192.0.2.1')], total:1, next:''});
    await flush();
    assert.deepEqual(h.points(), ['192.0.2.2', '192.0.2.1']);
    await h.advance(5000);
    assert.equal(h.requests.length, 2, 'the queued refresh must run after the first completes');
    assert.equal(initial.signal.aborted, false);
});

test('restricted users never fetch statistics, including retries and reconnect refreshes', async t => {
    const h = harness({statsAllowed:false});
    t.after(h.stop);
    h.requests[0].respond({items:[], total:0, next:''});
    await flush();
    h.get('retry-data').emit('click');
    h.requests.at(-1).respond({items:[], total:0, next:''});
    await flush();
    h.sockets[0].close();
    await h.advance(3000);
    h.sockets[1].open();
    await h.advance(5000);
    assert.ok(h.requests.length >= 3);
    assert.ok(h.requests.every(request => request.url !== '/api/v1/stats'));
    assert.equal(h.get('stat-total').textContent, '—');
    assert.match(h.get('country-list').textContent, /Requires statistics permission/);
});

test('failed snapshots retain data and explicit refresh recovers', async t => {
    const h = harness();
    t.after(h.stop);
    h.requests[0].respond({items:[item('192.0.2.1')], total:1, next:''});
    await flush();
    h.get('retry-data').emit('click');
    h.requests.at(-1).respond({}, 503);
    await flush();
    assert.deepEqual(h.points(), ['192.0.2.1']);
    assert.match(h.get('data-status').textContent, /previous data retained/);
    assert.equal(h.get('retry-data').hidden, false);
    h.get('retry-data').emit('click');
    h.requests.at(-1).respond({items:[item('192.0.2.2')], total:1, next:''});
    await flush();
    assert.deepEqual(h.points(), ['192.0.2.2']);
    assert.match(h.get('data-status').textContent, /Data current/);
});

test('explicit refresh supersedes old requests without applying their queued events again', async t => {
    const h = harness();
    t.after(h.stop);
    const old = h.requests[0];
    h.sockets[0].send('block', item('192.0.2.1'));
    h.get('retry-data').emit('click');
    assert.equal(old.signal.aborted, true);
    h.requests[1].respond({items:[item('192.0.2.2')], total:1, next:''});
    await flush();
    assert.deepEqual(h.points(), ['192.0.2.2']);
});

test('globe retry keeps its error until the renderer confirms recovery', async t => {
    const h = harness();
    t.after(h.stop);
    h.scene.options.onError('World map unavailable');
    h.scene.retryResult = false;
    h.get('retry-data').emit('click');
    h.requests.at(-1).respond({items:[], total:0, next:''});
    await flush();
    assert.match(h.get('data-status').textContent, /World map unavailable/);
    assert.equal(h.get('retry-data').hidden, false);
    h.scene.retryResult = true;
    h.get('retry-data').emit('click');
    h.requests.at(-1).respond({items:[], total:0, next:''});
    await flush();
    assert.equal(h.scene.retries, 2);
    assert.doesNotMatch(h.get('data-status').textContent, /World map unavailable/);
});

test('suspension aborts work and returning resumes one socket and a fresh snapshot', async t => {
    const h = harness();
    t.after(h.stop);
    const initial = h.requests[0];
    h.document.hidden = true;
    h.document.emit('visibilitychange');
    assert.equal(initial.signal.aborted, true);
    assert.equal(h.sockets[0].closed, true);
    await h.advance(30000);
    assert.equal(h.requests.length, 1);
    h.document.hidden = false;
    h.document.emit('visibilitychange');
    assert.equal(h.sockets.length, 2);
    assert.equal(h.requests.length, 2);
    h.requests[1].respond({items:[item('192.0.2.2')], total:1, next:''});
    await flush();
    assert.deepEqual(h.points(), ['192.0.2.2']);
});
