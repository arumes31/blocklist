const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function harness({reduced = false, failMap = false, now = Date.now()} = {}) {
    const startTime = now;
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
        return (...args) => { draws.push({method: key, args, alpha: target.globalAlpha}); };
    }});
    class Canvas extends Element { getContext() { return ctx; } }
    const document = new Element();
    document.currentScript = {src: 'https://example.test/js/threat-map-scene.js'};
    document.hidden = false;
    document.createElement = name => name === 'canvas' ? new Canvas() : new Element();
    const media = new Element();
    media.matches = reduced;
    const window = {devicePixelRatio: 3};
    const context = {window, document, HTMLCanvasElement: Canvas, URL, Math, console, Date: {now: () => now},
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
    const groups = [];
    const zoomChanges = [];
    const errors = [];
    const scene = new window.ThreatMapScene(canvas, {onSelect: p => selections.push(p), onCluster: p => groups.push(p), onZoomChange: () => zoomChanges.push(scene.zoom), onError: e => errors.push(e)});
    const frame = time => {
        now = startTime + time;
        const queued = Array.from(frames.entries());
        queued.forEach(([id, callback]) => { frames.delete(id); callback(time); });
    };
    return {scene, canvas, document, media, frames, requests, draws, selections, groups, zoomChanges, errors, frame, setNow: value => { now = value; }};
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
    scene.zoomBy(1000);
    assert.equal(scene.zoom, 128);
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

test('ambient animation reuses geography while inspecting a fixed view', async () => {
    const {scene} = harness();
    await scene.ready;
    scene.setPoints([east]);
    scene.focusPoint(east);
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

test('a hidden origin still has a clipped visible route to its actual destination', async () => {
    const {scene, draws} = harness({now: 1000});
    await scene.ready;
    const destination = {lat: 48, lon: 16};
    scene.setPaths([{from: {lat: 0, lon: -160}, to: destination, kind: 'block', createdAt: 1000, durationMs: 8000, destinationKind: 'target'}]);
    const path = scene.paths[0];
    assert.ok(scene.project(path.fromVector).z < 0);
    assert.ok(scene.project(path.toVector).z > 0);
    const segments = scene.routeSegments(path);
    assert.ok(segments.length > 0);
    assert.ok(segments.every(segment => segment.start.z >= 0 && segment.end.z >= 0));
    assert.equal(segments.at(-1).end.t, 1);
    assert.ok(draws.some(draw => draw.method === 'fillText' && draw.args[0] === 'TARGET'));
    assert.equal(path.to.lat, destination.lat);
    assert.equal(path.to.lon, destination.lon);
    scene.destroy();
});

test('reporter destinations are labelled honestly and path fading respects the event lifetime', async () => {
    const {scene, draws, setNow} = harness({now: 1000});
    await scene.ready;
    scene.setPaths([{from: {lat: 30, lon: 10}, to: {lat: 48, lon: 16}, kind: 'block', createdAt: 1000, durationMs: 8000, destinationKind: 'reporter'}]);
    assert.ok(draws.some(draw => draw.method === 'fillText' && draw.args[0] === 'REPORTER'));
    assert.equal(scene.pathOpacity(scene.paths[0], 1000), 1);
    assert.ok(scene.pathOpacity(scene.paths[0], 8000) < 1);
    assert.equal(scene.pathOpacity(scene.paths[0], 9000), 0);
    setNow(9000);
    draws.length = 0;
    scene.draw();
    assert.equal(draws.some(draw => draw.method === 'fillText' && draw.args[0] === 'REPORTER'), false);
    scene.destroy();
});

test('antipodal and identical locations produce finite route geometry without a guessed destination', async () => {
    const {scene} = harness({now: 1000});
    await scene.ready;
    scene.setPaths([
        {from: {lat: 0, lon: 0}, to: {lat: 0, lon: 180}, kind: 'block'},
        {from: {lat: 48, lon: 16}, to: {lat: 48, lon: 16}, kind: 'block'},
    ]);
    for (const path of scene.paths) assert.ok(path.samples.every(point => point.every(Number.isFinite)));
    assert.equal(scene.paths.length, 2);
    scene.destroy();
});

test('default paths last ten seconds while explicit shorter lifetimes stay supported', async () => {
    const {scene} = harness({now: 1000});
    await scene.ready;
    scene.setPaths([{from: {lat: 30, lon: 10}, to: {lat: 48, lon: 16}, kind: 'block', createdAt: 1000}]);
    assert.equal(scene.paths[0].durationMs, 10000);
    assert.ok(scene.pathOpacity(scene.paths[0], 10000) > 0);
    assert.equal(scene.pathOpacity(scene.paths[0], 11000), 0);
    scene.destroy();
});

test('all twenty thousand records remain selectable while dense markers retain exact counts by status', async () => {
    const {scene, canvas, selections} = harness({reduced: true});
    await scene.ready;
    const points = Array.from({length: 20000}, (_, index) => ({
        id: 'record-' + index, ip: 'record-' + index,
        lat: -75 + (index * 0.61803398875 % 1) * 150,
        lon: -180 + (index * 0.41421356237 % 1) * 360,
        kind: index % 4 ? 'block' : 'whitelist',
    }));
    scene.setPoints(points);
    const visible = scene.entries.map(entry => ({point: entry.point, position: scene.project(entry.vector)}))
        .filter(({position: p}) => p.z >= 0.03 && p.x >= -10 && p.x <= scene.width + 10 && p.y >= -10 && p.y <= scene.height + 10);
    assert.equal(scene.points.length, 20000);
    assert.ok(scene.markers.length < 1000);
    assert.equal(scene.markers.reduce((sum, marker) => sum + marker.count, 0), visible.length);
    for (const kind of ['block', 'whitelist']) {
        assert.equal(scene.markers.filter(marker => marker.point.kind === kind).reduce((sum, marker) => sum + marker.count, 0),
            visible.filter(({point}) => point.kind === kind).length);
    }
    key(canvas, 'End');
    assert.equal(selections.at(-1).id, 'record-19999');
    assert.ok(scene.hitPoints.some(point => point.point.id === 'record-19999'));
    key(canvas, 'Home');
    assert.equal(selections.at(-1).id, 'record-0');
    const retainedMarkers = scene.markers;
    scene.elapsed += 1;
    scene.draw();
    assert.equal(scene.markers, retainedMarkers);
    scene.setPoints([east]);
    assert.equal(scene.markers.length <= 1, true);
    scene.destroy();
});

test('wheel and keyboard reach local zoom without allocating larger bitmaps and reject invalid factors', async () => {
    const {scene, canvas} = harness();
    await scene.ready;
    canvas.events.get('wheel')({deltaY: -10000, preventDefault() {}});
    assert.equal(scene.zoom, 128);
    assert.equal(scene.radius, scene.baseRadius * 128);
    assert.equal(canvas.width, 1800, 'zoom enlarges the projection without allocating a larger bitmap');
    key(canvas, '-');
    assert.equal(scene.zoom, 128 / 1.2);
    key(canvas, '+');
    assert.equal(scene.zoom, 128);
    for (const factor of [NaN, Infinity, -1, 0]) scene.zoomBy(factor);
    assert.equal(scene.zoom, 128);
    canvas.events.get('wheel')({deltaY: 10000, preventDefault() {}});
    assert.equal(scene.zoom, 0.8);
    scene.reset();
    assert.equal(scene.zoom, 1);
    scene.destroy();
});

test('29 co-located IPs stay counted and all members can be inspected even at maximum zoom', async () => {
    const {scene, canvas, groups, selections, zoomChanges} = harness({reduced: true});
    await scene.ready;
    const points = Array.from({length:29}, (_, i) => ({...east, id:`at-${i}`, ip:`192.0.2.${i + 1}`, lat:47, lon:17}));
    scene.setRegion('europe');
    scene.setPoints(points);
    const clickGroup = () => {
        const marker = scene.hitPoints.find(point => point.count === 29);
        assert.ok(marker);
        const pointer = {button:0, pointerId:1, clientX:marker.x, clientY:marker.y};
        canvas.events.get('pointerdown')(pointer);
        canvas.events.get('pointerup')(pointer);
    };
    clickGroup();
    assert.equal(groups[0].length, 29);
    assert.equal(selections.length, 0, 'clicking a count does not arbitrarily select its first IP');
    assert.equal(scene.zoom, 2);
    assert.equal(scene.groupSelected, true);
    scene.zoomBy(1000);
    assert.equal(scene.getZoomState().max, 128);
    clickGroup();
    assert.equal(groups.at(-1).length, 29);
    assert.ok(groups.at(-1).every(point => point.lat === 47 && point.lon === 17));
    key(canvas, 'End');
    assert.equal(selections.at(-1).id, 'at-28');
    clickGroup();
    assert.equal(groups.length, 3, 'selected marker overlay must not hide its group');
    scene.setPoints(points.map(point => ({...point, reason:'Updated'})));
    clickGroup();
    assert.ok(groups.at(-1).every(point => point.reason === 'Updated'));
    scene.reset();
    assert.equal(scene.groupSelected, false);
    assert.equal(zoomChanges.at(-1), 1);
    scene.destroy();
});

test('nearby coordinates separate at deep zoom and group inspection prevents ambient drift', async () => {
    const {scene, frame} = harness();
    await scene.ready;
    scene.setPoints([{...east, id:'a', lat:22, lon:21}, {...east, id:'b', lat:22, lon:21.1}]);
    const marker = scene.markerPositions()[0];
    assert.equal(marker.count, 2);
    scene.activateMarker(marker);
    frame(0);
    frame(9000);
    frame(10000);
    assert.equal(scene.center.lon, 21);
    scene.zoomBy(1000);
    assert.equal(scene.markerPositions().length, 2);
    assert.ok(scene.markerPositions().every(point => point.count === 1));
    scene.clearGroup();
    assert.equal(scene.groupSelected, false);
    scene.destroy();
});

test('the planet rotates by elapsed frame time, wraps longitude, and limits geography redraws', async () => {
    for (const interval of [40, 50]) {
        const {scene, frame, frames} = harness();
        await scene.ready;
        scene.center.lon = 179.5;
        scene.invalidate();
        let rebuilds = 0;
        const original = scene.drawBase.bind(scene);
        scene.drawBase = () => { rebuilds += 1; original(); };
        frame(0);
        for (let time = interval; time <= 1200; time += interval) frame(time);
        assert.ok(Math.abs(scene.center.lon - -179.3) < 0.000001);
        assert.ok(rebuilds <= 6, 'geography updates at most five times a second');
        assert.equal(frames.size, 1, 'rotation shares the existing animation loop');
        scene.destroy();
    }
});

test('zoom and drag hold rotation for eight seconds then resume at a readable zoom-scaled speed', async () => {
    const {scene, canvas, frame} = harness();
    await scene.ready;
    scene.zoomBy(4);
    const start = scene.center.lon;
    frame(0);
    for (let time = 40; time <= 7960; time += 40) frame(time);
    assert.equal(scene.center.lon, start);
    for (let time = 8000; time <= 9200; time += 40) frame(time);
    const rotation = scene.center.lon - start;
    assert.ok(rotation > 0.25 && rotation < 0.35);
    const pointer = {button: 0, pointerId: 1, clientX: 450, clientY: 325};
    canvas.events.get('pointerdown')(pointer);
    canvas.events.get('pointermove')({...pointer, clientX: 550});
    const dragged = scene.center.lon;
    for (let time = 9240; time <= 10000; time += 40) frame(time);
    assert.equal(scene.center.lon, dragged);
    canvas.events.get('pointerup')({...pointer, clientX: 550});
    for (let time = 10040; time <= 17960; time += 40) frame(time);
    assert.equal(scene.center.lon, dragged);
    for (let time = 18000; time <= 18320; time += 40) frame(time);
    assert.ok(scene.center.lon > dragged);
    scene.destroy();
});

test('inspection and regional views stay stationary until reset restores global rotation', async () => {
    const {scene, frame} = harness();
    await scene.ready;
    scene.setPoints([east]);
    scene.focusPoint(east);
    frame(0);
    for (let time = 40; time <= 1000; time += 40) frame(time);
    assert.equal(scene.center.lon, east.lon);
    scene.setRegion('europe');
    const regionLon = scene.center.lon;
    for (let time = 1040; time <= 2000; time += 40) frame(time);
    assert.equal(scene.center.lon, regionLon);
    scene.zoomBy(2);
    scene.reset();
    for (let time = 2040; time <= 3000; time += 40) frame(time);
    assert.ok(scene.center.lon > 21);
    assert.equal(scene.selectedPoint, null);
    assert.equal(scene.zoom, 1);
    scene.destroy();
});

test('cancelled pointer drags release rotation after the same interaction hold', async () => {
    for (const event of ['pointercancel', 'lostpointercapture']) {
        const {scene, canvas, frame} = harness();
        await scene.ready;
        frame(0);
        canvas.events.get('pointerdown')({button: 0, pointerId: 1, clientX: 450, clientY: 325});
        canvas.events.get(event)();
        assert.equal(scene.drag, null);
        assert.equal(canvas.style.cursor, 'grab');
        for (let time = 40; time <= 7960; time += 40) frame(time);
        assert.equal(scene.center.lon, 21);
        for (let time = 8000; time <= 8400; time += 40) frame(time);
        assert.ok(scene.center.lon > 21);
        scene.destroy();
    }
});

test('motion and visibility changes freeze rotation without catch-up or duplicate animation loops', async () => {
    const {scene, media, document, frames, frame} = harness();
    await scene.ready;
    frame(0);
    frame(200);
    const initial = scene.center.lon;
    scene.setPaused(true);
    frame(10000);
    assert.equal(scene.center.lon, initial);
    assert.equal(frames.size, 0);
    scene.setPaused(false);
    scene.setPaused(false);
    assert.equal(frames.size, 1);
    frame(10040);
    assert.equal(scene.center.lon, initial);
    frame(10140);
    frame(10240);
    assert.ok(scene.center.lon > initial && scene.center.lon < initial + 0.3);
    media.events.get('change')({matches: true});
    const stopped = scene.center.lon;
    frame(20000);
    assert.equal(scene.center.lon, stopped);
    assert.equal(frames.size, 0);
    media.events.get('change')({matches: false});
    assert.equal(frames.size, 1);
    document.hidden = true;
    document.events.get('visibilitychange')();
    frame(30000);
    assert.equal(scene.center.lon, stopped);
    assert.equal(frames.size, 0);
    document.hidden = false;
    document.events.get('visibilitychange')();
    frame(40000);
    assert.equal(scene.center.lon, stopped);
    frame(40100);
    frame(40200);
    assert.ok(scene.center.lon > stopped && scene.center.lon < stopped + 0.3);
    scene.destroy();
    assert.equal(frames.size, 0);
    frame(50000);
    assert.equal(frames.size, 0);
});

test('an explicit motion override enables rotation while reduced motion remains the default', async () => {
    const {scene, media, frames, frame} = harness({reduced: true});
    await scene.ready;
    assert.equal(frames.size, 0);
    assert.equal(scene.reducedMotion, true);
    scene.setMotionOverride(true);
    assert.equal(scene.reducedMotion, false);
    assert.equal(frames.size, 1);
    frame(0);
    frame(100);
    frame(200);
    assert.ok(scene.center.lon > 21);
    media.events.get('change')({matches: true});
    assert.equal(scene.reducedMotion, false);
    assert.equal(frames.size, 1);
    scene.setMotionOverride(false);
    assert.equal(scene.reducedMotion, true);
    assert.equal(frames.size, 0);
    scene.destroy();
});
