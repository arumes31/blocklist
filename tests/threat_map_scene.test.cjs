const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function harness({reduced = false, failMap = false} = {}) {
    const frames = new Map();
    const requests = [];
    const draws = [];
    let frameID = 0;
    let mapFailures = failMap === 'once' ? 1 : failMap ? Infinity : 0;
    class Element {
        constructor() { this.attributes = new Map(); this.events = new Map(); this.style = {}; }
        setAttribute(name, value) { this.attributes.set(name, value); }
        getAttribute(name) { return this.attributes.get(name) ?? null; }
        removeAttribute(name) { this.attributes.delete(name); }
        addEventListener(name, callback) { this.events.set(name, callback); }
        removeEventListener(name) { this.events.delete(name); }
        insertAdjacentElement() {}
        remove() { this.removed = true; }
        getBoundingClientRect() { return {width: 900, height: 650, left: 0, top: 0}; }
        setPointerCapture() {}
        hasPointerCapture() { return false; }
        focus() {}
    }
    const ctx = new Proxy({}, {get(target, key) {
        if (key in target) return target[key];
        if (key === 'measureText') return text => ({width: text.length * 6});
        if (key === 'createRadialGradient' || key === 'createLinearGradient') return () => ({addColorStop() {}});
        return (...args) => { draws.push({method: key, args}); };
    }});
    class Canvas extends Element { getContext() { return ctx; } }
    const document = new Element();
    document.currentScript = {src: 'https://example.test/js/threat-map-scene.js'};
    document.hidden = false;
    document.createElement = name => name === 'canvas' ? new Canvas() : new Element();
    const media = new Element();
    media.matches = reduced;
    const window = {devicePixelRatio: 3};
    const context = {window, document, HTMLCanvasElement: Canvas, URL, Math, console,
        location: {href: 'https://example.test/threat-map'}, matchMedia: () => media,
        ResizeObserver: class { observe() {} disconnect() { this.disconnected = true; } },
        requestAnimationFrame: callback => { frames.set(++frameID, callback); return frameID; },
        cancelAnimationFrame: id => frames.delete(id),
        fetch: async url => {
            requests.push(url);
            if (mapFailures > 0) { mapFailures -= 1; throw new Error('offline'); }
            return {ok: true, json: async () => ({features: [{geometry: {type: 'Polygon', coordinates: [
                [[0, 0], [20, 0], [20, 20], [0, 0]],
            ]}}]})};
        },
    };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../cmd/server/static/js/threat-map-scene.js'), 'utf8'), context);
    const canvas = new Canvas();
    const selections = [];
    const errors = [];
    const scene = new window.ThreatMapScene(canvas, {onSelect: p => selections.push(p), onError: e => errors.push(e)});
    return {scene, canvas, document, media, frames, requests, draws, selections, errors};
}

const east = {id: 'east', ip: '192.0.2.1', name: 'East', lat: 30, lon: 150, kind: 'block', count: 1};
const west = {id: 'west', ip: '192.0.2.2', name: 'West', lat: 30, lon: -80, kind: 'whitelist', count: 1};
function key(canvas, name) { canvas.events.get('keydown')({key: name, preventDefault() {}}); }

test('starts empty, fetches only local geography, and caps retina rendering', async () => {
    const {scene, requests, canvas} = harness();
    await scene.ready;
    assert.equal(scene.points.length, 0);
    assert.equal(scene.paths.length, 0);
    assert.deepEqual(requests, ['https://example.test/js/world.json']);
    assert.equal(canvas.width, 1800);
    scene.destroy();
});

test('rejects invalid coordinates and kinds without fabricating a destination', async () => {
    const {scene} = harness();
    await scene.ready;
    scene.setPoints([east, west, {...east, lat: NaN}, {...east, lon: 181}, {...east, lat: null}, {...east, kind: 'unknown'}]);
    assert.equal(scene.points.length, 2);
    assert.equal(scene.paths.length, 0);
    scene.setPaths([{from: east, to: west, kind: 'block'}, {from: east, to: {lat: null, lon: 0}}, {from: east}]);
    assert.equal(scene.paths.length, 1);
    scene.setPaths([]);
    assert.equal(scene.paths.length, 0);
    scene.destroy();
});

test('keyboard can inspect the far hemisphere and announces whitelist state', async () => {
    const {scene, canvas, selections} = harness({reduced: true});
    await scene.ready;
    scene.setPoints([east, west]);
    key(canvas, 'Home');
    assert.equal(selections.at(-1).id, 'east');
    assert.ok(scene.hitPoints.some(entry => entry.point.id === 'east'));
    key(canvas, 'End');
    assert.equal(selections.at(-1).id, 'west');
    assert.match(scene.selectionStatus.textContent, /whitelisted/i);
    scene.setRegion('asia');
    key(canvas, 'End');
    assert.equal(selections.at(-1).id, 'east');
    scene.destroy();
});

test('pause, reduced motion, hidden state and destroy stop scheduling without blocking fresh data', async () => {
    const {scene, canvas, frames, document, draws} = harness();
    await scene.ready;
    scene.setPaused(true);
    assert.equal(frames.size, 0);
    const count = draws.length;
    scene.setPoints([west]);
    assert.ok(draws.length > count);
    scene.setPaused(false);
    assert.equal(frames.size, 1);
    document.hidden = true;
    document.events.get('visibilitychange')();
    assert.equal(frames.size, 0);
    scene.destroy();
    assert.equal(canvas.events.size, 0);
    assert.equal(document.events.size, 0);
    const still = harness({reduced: true});
    await still.scene.ready;
    assert.equal(still.frames.size, 0);
    still.scene.destroy();
});

test('zoom stays bounded and map failure is accessible while points remain selectable', async () => {
    const {scene, canvas, errors, selections} = harness({failMap: true});
    await scene.ready;
    assert.equal(errors.length, 1);
    assert.match(scene.selectionStatus.textContent, /unavailable/i);
    scene.zoomBy(100);
    assert.equal(scene.zoom, 3);
    scene.zoomBy(0.001);
    assert.equal(scene.zoom, 0.8);
    scene.setPoints([east]);
    key(canvas, 'Home');
    assert.equal(selections.at(-1).ip, east.ip);
    scene.reset();
    assert.equal(scene.zoom, 1);
    scene.destroy();
});

test('drag rotates without selecting and a stationary pointer selects a visible origin', async () => {
    const {scene, canvas, selections} = harness({reduced: true});
    await scene.ready;
    scene.setPoints([east]);
    scene.focusPoint(east);
    const origin = scene.hitPoints[0];
    const pointer = {button: 0, pointerId: 1, clientX: origin.x, clientY: origin.y};
    canvas.events.get('pointerdown')(pointer);
    canvas.events.get('pointermove')({...pointer, clientX: pointer.clientX + 100});
    canvas.events.get('pointerup')({...pointer, clientX: pointer.clientX + 100});
    assert.equal(selections.length, 0);
    assert.notEqual(scene.center.lon, east.lon);
    scene.focusPoint(east);
    canvas.events.get('pointerdown')(pointer);
    canvas.events.get('pointerup')(pointer);
    assert.equal(selections.at(-1).id, 'east');
    scene.destroy();
});

test('refresh preserves real record metadata and external focus does not loop through onSelect', async () => {
    const {scene, selections} = harness({reduced: true});
    await scene.ready;
    const input = {...east, reason: '<img src=x onerror=alert(1)>', asn: 64500, addedBy: 'admin'};
    scene.setPoints([input]);
    scene.focusPoint(input);
    assert.equal(selections.length, 0);
    assert.match(scene.selectionStatus.textContent, /<img src=x/);
    assert.equal(scene.selectedPoint.asn, 64500);
    scene.setPoints([{...input, reason: 'updated'}]);
    assert.equal(scene.selectedPoint.reason, 'updated');
    assert.equal(input.reason, '<img src=x onerror=alert(1)>');
    scene.setPoints([]);
    assert.equal(scene.selectedPoint, null);
    assert.equal(scene.hitPoints.length, 0);
    scene.destroy();
});

test('geography retry recovers without resetting records, selection, region or motion controls', async () => {
    const {scene, requests, errors} = harness({failMap: 'once'});
    assert.equal(await scene.ready, false);
    scene.setPoints([east]);
    scene.setRegion('asia');
    scene.setLayer('density');
    scene.setPaused(true);
    scene.zoomBy(1.5);
    scene.focusPoint(east);
    assert.equal(await scene.retryGeography(), true);
    assert.equal(requests.length, 2);
    assert.equal(errors.length, 1);
    assert.equal(scene.error, false);
    assert.equal(scene.points[0].id, 'east');
    assert.equal(scene.selectedPoint.id, 'east');
    assert.equal(scene.region, 'asia');
    assert.equal(scene.layer, 'density');
    assert.equal(scene.paused, true);
    assert.equal(scene.zoom, 1.5);
    scene.destroy();
});

test('ambient animation reuses geography until the view changes', async () => {
    const {scene} = harness();
    await scene.ready;
    let rebuilds = 0;
    const original = scene.drawBase.bind(scene);
    scene.drawBase = () => { rebuilds += 1; original(); };
    for (let i = 0; i < 30; i += 1) { scene.elapsed += 0.04; scene.draw(); }
    assert.equal(rebuilds, 0);
    scene.zoomBy(1.2);
    assert.equal(rebuilds, 1);
    scene.setLayer('density');
    scene.setPoints([east]);
    const updated = rebuilds;
    for (let i = 0; i < 30; i += 1) { scene.elapsed += 0.04; scene.draw(); }
    assert.equal(rebuilds, updated);
    scene.setPoints([]);
    assert.equal(rebuilds, updated + 1);
    scene.destroy();
});
