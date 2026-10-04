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
const blocklist = items => Object.fromEntries(items.map(({ip, data}) => [ip, data]));

// Only the browser surfaces used by the controller are modeled here. Geography,
// layout and painting remain covered by the renderer and real-browser checks.
function harness({statsAllowed = false, showWhitelist = false, showAllBlocks = false, reducedMotion = false} = {}) {
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
    get('toggle-all-blocked').checked = showAllBlocks;
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
        constructor(canvas, options) { scene = this; this.options = options; this.points = []; this.pointUpdates = 0; this.retryResult = true; this.retries = 0; }
        setPoints(points) { this.points = points; this.pointUpdates++; }
        setPaths(paths) { this.paths = paths; }
        setPaused(paused) { this.paused = paused; }
        setMotionOverride(allowMotion) { this.allowMotion = allowMotion; }
        setLayer() {}
        setRegion() {}
        focusPoint() {}
        reset() {}
        zoomBy() {}
        destroy() { this.destroyed = true; }
        retryGeography() { this.retries++; return Promise.resolve(this.retryResult); }
    }
    const media = new Element();
    media.matches = reducedMotion;
    const window = new Element();
    window.ThreatMapData = data;
    const epoch = Date.parse('2026-10-04T00:00:00Z');
    class ClockDate extends Date {
        constructor(...args) { super(...(args.length ? args : [epoch + clock])); }
        static now() { return epoch + clock; }
    }
    vm.runInNewContext(controller, {
        window, document, matchMedia:() => media, ThreatMapScene:Scene, WebSocket:Socket,
        location:{protocol:'https:', host:'blocklist.test'}, fetch, AbortController, Date:ClockDate,
        setTimeout:(callback, delay) => timer(callback, delay), clearTimeout:id => timers.delete(id),
        setInterval:(callback, delay) => timer(callback, delay, true), clearInterval:id => timers.delete(id),
    }, {filename:'threat-map.js'});
    return {get, document, window, requests, sockets, scene, advance,
        points:() => Array.from(scene.points, point => point.ip),
        stop:() => window.emit('pagehide', {persisted:false}),
    };
}

test('reduced motion starts still but can be explicitly enabled, paused and resumed', t => {
    const h = harness({reducedMotion:true});
    t.after(h.stop);
    assert.equal(h.scene.paused,true);
    assert.equal(h.scene.allowMotion,false);
    assert.equal(h.get('pause-motion').textContent,'Enable motion');
    assert.notEqual(h.get('pause-motion').disabled,true);
    h.get('pause-motion').emit('click');
    assert.equal(h.scene.allowMotion,true);
    assert.equal(h.scene.paused,false);
    assert.equal(h.get('pause-motion').textContent,'Pause motion');
    h.get('pause-motion').emit('click');
    assert.equal(h.scene.paused,true);
    assert.equal(h.get('pause-motion').textContent,'Resume motion');
    h.get('pause-motion').emit('click');
    assert.equal(h.scene.paused,false);
    assert.equal(h.scene.allowMotion,true);
});

test('reset leaves IP inspection so the global globe can rotate again', async t => {
    const h = harness();
    t.after(h.stop);
    h.sockets[0].send('block',item('192.0.2.1'));
    await h.advance(200);
    h.get('origin-list').children[0].emit('click');
    assert.equal(h.get('detail-content').hidden,false);
    h.get('reset-view').emit('click');
    assert.equal(h.get('detail-content').hidden,true);
    assert.equal(h.get('detail-empty').hidden,false);
    assert.equal(h.get('origin-list').children[0].attributes.get('aria-pressed'),'false');
});

test('live blocks expire after eight seconds without loading historical block snapshots', async t => {
    const h = harness({statsAllowed:true});
    t.after(h.stop);
    h.requests[0].respond({active_blocks:20000});
    await flush();
    assert.deepEqual(h.points(), []);
    h.sockets[0].send('block', {...item('192.0.2.1'),source_geo:{latitude:47,longitude:13,city:'Salzburg'}});
    await h.advance(200);
    assert.deepEqual(h.points(), ['192.0.2.1']);
    assert.equal(h.scene.paths[0].destinationKind,'target');
    h.get('origin-list').children[0].emit('click');
    assert.equal(h.get('selected-target').textContent,'Reporting server · Salzburg');
    h.get('pause-motion').emit('click');
    await h.advance(7799);
    assert.deepEqual(h.points(), ['192.0.2.1']);
    await h.advance(1);
    assert.deepEqual(h.points(), []);
    assert.equal(h.scene.paths.length,1,'paths outlive their eight-second origin markers');
    assert.equal(h.get('detail-content').hidden,true);
    assert.equal(h.get('event-stream').children.length,1);
    assert.ok(h.get('event-stream').querySelector('.empty-state'));
    assert.ok(h.requests.every(request=>!request.url.startsWith('/api/v1/ips')));
    await h.advance(1999);
    assert.equal(h.scene.paths.length,1);
    await h.advance(1);
    assert.equal(h.scene.paths.length,0,'paths expire at ten seconds even when motion is paused');
});

test('delayed whitelist snapshots preserve newer live block and whitelist events', async t => {
    const h = harness({showWhitelist:true});
    t.after(h.stop);
    h.sockets[0].send('unblock', {ip:'192.0.2.1'});
    h.sockets[0].send('block', item('192.0.2.2'));
    h.sockets[0].send('whitelist', item('192.0.2.3'));
    h.requests.find(request => request.url === '/api/v1/whitelists').respond([]);
    await flush();
    assert.deepEqual(h.points().sort(), ['192.0.2.2', '192.0.2.3']);
    assert.equal(h.get('event-stream').children.length, 3);
    assert.equal(h.get('event-stream').querySelector('.empty-state'), null);
    assert.match(h.get('data-status').textContent, /Data current/);
});

test('background refresh waits for a slow active request and schedules the next refresh', async t => {
    const h = harness({showWhitelist:true});
    t.after(h.stop);
    const initial = h.requests[0];
    h.sockets[0].open();
    h.sockets[0].send('block', item('192.0.2.2'));
    await h.advance(6500);
    assert.equal(initial.signal.aborted, false, 'the five-second event timer must not cancel the snapshot');
    assert.equal(h.requests.length, 1);
    initial.respond([item('192.0.2.1')]);
    await flush();
    assert.deepEqual(h.points(), ['192.0.2.2', '192.0.2.1']);
    await h.advance(5000);
    assert.equal(h.requests.length, 2, 'the queued refresh must run after the first completes');
    assert.equal(initial.signal.aborted, false);
});

test('restricted users never fetch statistics, including retries and reconnect refreshes', async t => {
    const h = harness({statsAllowed:false,showWhitelist:true});
    t.after(h.stop);
    h.requests[0].respond([]);
    await flush();
    h.get('retry-data').emit('click');
    h.requests.at(-1).respond([]);
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

test('failed whitelist snapshots retain data and explicit refresh recovers', async t => {
    const h = harness({showWhitelist:true});
    t.after(h.stop);
    h.requests[0].respond([item('192.0.2.1')]);
    await flush();
    h.get('retry-data').emit('click');
    h.requests.at(-1).respond({}, 503);
    await flush();
    assert.deepEqual(h.points(), ['192.0.2.1']);
    assert.match(h.get('data-status').textContent, /previous data retained/);
    assert.equal(h.get('retry-data').hidden, false);
    h.get('retry-data').emit('click');
    h.requests.at(-1).respond([item('192.0.2.2')]);
    await flush();
    assert.deepEqual(h.points(), ['192.0.2.2']);
    assert.match(h.get('data-status').textContent, /Data current/);
});

test('refreshes never resurrect expired block events or replay old whitelist requests', async t => {
    const h = harness({showWhitelist:true});
    t.after(h.stop);
    const old = h.requests[0];
    h.sockets[0].send('block', item('192.0.2.1'));
    h.sockets[0].send('whitelist', item('192.0.2.99'));
    h.get('retry-data').emit('click');
    assert.equal(old.signal.aborted, true);
    h.requests[1].respond([item('192.0.2.2')]);
    await flush();
    assert.deepEqual(h.points(), ['192.0.2.1','192.0.2.2']);
    await h.advance(8000);
    assert.deepEqual(h.points(), ['192.0.2.2']);
});

test('globe retry keeps its error until the renderer confirms recovery', async t => {
    const h = harness({showWhitelist:true});
    t.after(h.stop);
    h.scene.options.onError('World map unavailable');
    h.scene.retryResult = false;
    h.get('retry-data').emit('click');
    h.requests.at(-1).respond([]);
    await flush();
    assert.match(h.get('data-status').textContent, /World map unavailable/);
    assert.equal(h.get('retry-data').hidden, false);
    h.scene.retryResult = true;
    h.get('retry-data').emit('click');
    h.requests.at(-1).respond([]);
    await flush();
    assert.equal(h.scene.retries, 2);
    assert.doesNotMatch(h.get('data-status').textContent, /World map unavailable/);
});

test('suspension aborts work and returning resumes one socket and a fresh snapshot', async t => {
    const h = harness({showWhitelist:true});
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
    h.requests[1].respond([item('192.0.2.2')]);
    await flush();
    assert.deepEqual(h.points(), ['192.0.2.2']);
});

test('all blocked loads the canonical complete object beyond 20000 and stays visible after live TTL', async t => {
    const h = harness({showAllBlocks:true});
    t.after(h.stop);
    const blocks = Array.from({length:20001},(_,i)=>item(`198.18.${Math.floor(i / 256)}.${i % 256}`));
    assert.equal(h.requests[0].url,'/api/v1/ips_list','the sorted timestamp index may omit older blocks');
    assert.match(h.get('data-status').textContent,/Loading blocked IPs/);
    h.requests[0].respond(blocklist(blocks));
    await flush();
    assert.equal(h.points().length,20001);
    assert.ok(h.points().includes(blocks.at(-1).ip));
    assert.ok(h.get('coverage-status').textContent.includes(`${(20001).toLocaleString()} loaded / ${(20001).toLocaleString()} reported`));
    assert.equal(h.get('origin-page').textContent,'1 / 3334');
    await h.advance(10000);
    assert.equal(h.points().length,20001);
    assert.equal(h.requests.length,1,'live event/stat timers must not reload the complete blocklist');
});

test('slow complete snapshots replay newer block changes after live marker expiry', async t => {
    const h = harness({showAllBlocks:true});
    t.after(h.stop);
    const first = h.requests[0];
    h.sockets[0].open();
    h.sockets[0].send('unblock',{ip:'removed'});
    h.sockets[0].send('block',item('new'));
    await h.advance(9500);
    assert.equal(first.signal.aborted,false);
    first.respond(blocklist([item('removed'),item('kept'),item('last')]));
    await flush();
    assert.deepEqual(h.points(),['new','kept','last']);
    assert.ok(h.scene.points.every(point=>point.visibleUntil === undefined),'all-mode records must not fade as live markers');
});

test('disabling all cancels its snapshot and immediately returns only unexpired live events', async t => {
    const h = harness({showAllBlocks:true});
    t.after(h.stop);
    h.sockets[0].send('block',item('live'));
    h.get('toggle-all-blocked').checked = false;
    h.get('toggle-all-blocked').emit('change');
    assert.equal(h.requests[0].signal.aborted,true);
    h.requests[0].respond(blocklist([item('late')]));
    await flush();
    assert.deepEqual(h.points(),['live']);
    await h.advance(8000);
    assert.deepEqual(h.points(),[]);
    assert.equal(h.requests.length,1);
});

test('failed snapshots preserve the previous complete list and disclose the HTTP status', async t => {
    const h = harness({showAllBlocks:true});
    t.after(h.stop);
    h.requests[0].respond(blocklist([item('previous')]));
    await flush();
    h.get('retry-data').emit('click');
    h.requests[1].respond({},503);
    await flush();
    assert.deepEqual(h.points(),['previous']);
    assert.match(h.get('data-status').textContent,/previous data retained/);
    assert.match(h.get('data-status').textContent,/503/);
    assert.match(h.get('coverage-status').textContent,/Refresh incomplete/);
    assert.equal(h.get('retry-data').hidden,false);
});

test('invalid full-list payloads retain data instead of silently replacing the list', async t => {
    const h = harness({showAllBlocks:true});
    t.after(h.stop);
    h.requests[0].respond(blocklist([item('previous')]));
    await flush();
    for (const invalid of [null,[],{items:[item('indexed-only')],total:1,next:''},{'192.0.2.1':null},{'192.0.2.1':'invalid'}]) {
        h.get('retry-data').emit('click');
        h.requests.at(-1).respond(invalid);
        await flush();
        assert.deepEqual(h.points(),['previous']);
        assert.match(h.get('data-status').textContent,/Invalid blocklist response/);
    }
    h.get('retry-data').emit('click');
    h.requests.at(-1).respond({});
    await flush();
    assert.deepEqual(h.points(),[]);
    assert.match(h.get('data-status').textContent,/Data current/);
});

test('enabling Include existing immediately shows loading and restores the complete list', async t => {
    const h = harness();
    t.after(h.stop);
    await flush();
    h.get('toggle-all-blocked').checked = true;
    h.get('toggle-all-blocked').emit('change');
    assert.match(h.get('data-status').textContent,/Loading blocked IPs/);
    assert.match(h.get('origin-list').textContent,/Loading blocked IPs/);
    h.requests[0].respond(blocklist([item('historical')]));
    await flush();
    assert.deepEqual(h.points(),['historical']);
    assert.match(h.get('data-status').textContent,/Data current/);
});

test('full snapshots sync at sixty seconds and reconnect while statistics remain independent', async t => {
    const h = harness({showAllBlocks:true,statsAllowed:true});
    t.after(h.stop);
    const blockRequests = () => h.requests.filter(request=>request.url === '/api/v1/ips_list');
    const statsRequests = () => h.requests.filter(request=>request.url === '/api/v1/stats');
    statsRequests()[0].respond({active_blocks:1});
    blockRequests()[0].respond(blocklist([item('old')]));
    h.sockets[0].open();
    await flush();
    await h.advance(30000);
    assert.equal(blockRequests().length,1);
    assert.ok(statsRequests().length >= 2);
    await h.advance(30000);
    assert.equal(blockRequests().length,2);
    blockRequests()[1].respond(blocklist([item('new')]));
    await flush();
    assert.deepEqual(h.points(),['new']);
    h.sockets[0].close();
    await h.advance(3000);
    h.sockets[1].open();
    assert.equal(blockRequests().length,3);
});

test('blocked filter disables the all control and cancels its active load', async t => {
    const h = harness({showAllBlocks:true});
    t.after(h.stop);
    h.get('toggle-blocked').checked = false;
    h.get('toggle-blocked').emit('change');
    await flush();
    assert.equal(h.get('toggle-all-blocked').disabled,true);
    assert.equal(h.requests[0].signal.aborted,true);
    h.get('toggle-blocked').checked = true;
    h.get('toggle-blocked').emit('change');
    assert.equal(h.get('toggle-all-blocked').disabled,false);
    assert.equal(h.requests.length,2);
});

test('a stalled complete snapshot times out and exposes retry without discarding live events', async t => {
    const h = harness({showAllBlocks:true});
    t.after(h.stop);
    await h.advance(5000);
    h.sockets[0].send('block',item('current'));
    await h.advance(7000);
    assert.equal(h.requests[0].signal.aborted,true);
    assert.deepEqual(h.points(),['current']);
    assert.match(h.get('data-status').textContent,/Blocked IPs unavailable/);
    assert.equal(h.get('retry-data').hidden,false);
});

test('live-only mode removes blocks when their actual expiry precedes the display deadline', async t => {
    const h = harness();
    t.after(h.stop);
    const expiring = item('temporary');
    expiring.data.expires_at = '2026-10-04T00:00:02Z';
    h.sockets[0].send('block',expiring);
    await h.advance(200);
    assert.deepEqual(h.points(),['temporary']);
    await h.advance(1800);
    assert.deepEqual(h.points(),[]);
});

test('all mode honors actual block expiry without using the live marker deadline', async t => {
    const h = harness({showAllBlocks:true});
    t.after(h.stop);
    const expiring = item('temporary');
    expiring.data.expires_at = '2026-10-04T00:00:01Z';
    h.requests[0].respond(blocklist([expiring,item('persistent')]));
    await flush();
    assert.equal(h.points().length,2);
    await h.advance(1000);
    assert.deepEqual(h.points(),['persistent']);
    await h.advance(9000);
    assert.deepEqual(h.points(),['persistent']);
});

test('all-mode events coalesce for one second and live-buffer expiry does not redraw static records', async t => {
    const h = harness({showAllBlocks:true});
    t.after(h.stop);
    h.requests[0].respond(blocklist([item('static')]));
    await flush();
    const initialUpdates = h.scene.pointUpdates;
    h.sockets[0].send('block',item('first'));
    h.sockets[0].send('block',item('second'));
    await h.advance(999);
    assert.equal(h.scene.pointUpdates,initialUpdates);
    await h.advance(1);
    assert.equal(h.scene.pointUpdates,initialUpdates + 1);
    assert.equal(h.points().length,3);
    await h.advance(7000);
    assert.equal(h.scene.pointUpdates,initialUpdates + 1,'statistics refresh and live TTL must not rebuild the full map');
    assert.equal(h.points().length,3);
});
