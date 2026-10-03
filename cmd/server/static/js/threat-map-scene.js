/* Dependency-free globe artwork. All activity comes from the caller's real data. */
(function () {
    'use strict';

    const TAU = Math.PI * 2;
    const RAD = Math.PI / 180;
    const scriptURL = document.currentScript ? document.currentScript.src : new URL('/js/threat-map-scene.js', location.href).href;
    const worldURL = new URL('world.json', scriptURL).href;
    const REGIONS = {
        global: {lon: 21, lat: 22}, europe: {lon: 17, lat: 47},
        asia: {lon: 92, lat: 26}, americas: {lon: -76, lat: 23},
    };
    let geographyPromise;
    let sceneCount = 0;

    function validLocation(point) {
        return point && Number.isFinite(point.lat) && Number.isFinite(point.lon) &&
            Math.abs(point.lat) <= 90 && Math.abs(point.lon) <= 180;
    }

    function vector(lon, lat) {
        const cosLat = Math.cos(lat * RAD);
        return [cosLat * Math.cos(lon * RAD), cosLat * Math.sin(lon * RAD), Math.sin(lat * RAD)];
    }

    function inRegion(point, region) {
        if (region === 'europe') return point.lon > -15 && point.lon < 50 && point.lat > 35;
        if (region === 'asia') return point.lon >= 50 && point.lat > -15;
        if (region === 'americas') return point.lon < -25;
        return true;
    }

    function getGeography() {
        if (!geographyPromise) {
            geographyPromise = fetch(worldURL).then(response => {
                if (!response.ok) throw new Error('Map request failed');
                return response.json();
            }).then(data => {
                if (!Array.isArray(data.features)) throw new Error('Invalid map data');
                const rings = [];
                data.features.forEach(feature => {
                    const geometry = feature.geometry;
                    if (!geometry) return;
                    const polygons = geometry.type === 'Polygon' ? [geometry.coordinates] :
                        geometry.type === 'MultiPolygon' ? geometry.coordinates : [];
                    polygons.forEach(polygon => polygon.forEach(ring => {
                        if (!Array.isArray(ring) || ring.length < 3) return;
                        if (!ring.every(c => Array.isArray(c) && validLocation({lon: c[0], lat: c[1]}))) return;
                        rings.push(ring.map(c => vector(c[0], c[1])));
                    }));
                });
                if (!rings.length) throw new Error('Empty map data');
                return rings;
            }).catch(error => {
                geographyPromise = null;
                throw error;
            });
        }
        return geographyPromise;
    }

    // Coordinates are immutable artwork, so calculate trigonometry only once.
    const GRID = [];
    const TEXTURE = [];
    for (let lat = -75; lat <= 75; lat += 15) {
        const points = [];
        for (let lon = -180; lon <= 180; lon += 3) points.push(vector(lon, lat));
        GRID.push({points, major: lat === 0});
    }
    for (let lon = -180; lon < 180; lon += 15) {
        const points = [];
        for (let lat = -90; lat <= 90; lat += 3) points.push(vector(lon, lat));
        GRID.push({points, major: lon === 0});
    }
    for (let lat = -65; lat < 75; lat += 5) {
        for (let lon = -175; lon < 180; lon += 5) TEXTURE.push(vector(lon, lat));
    }
    const TICKS = Array.from({length: 120}, (_, i) => ({cos: Math.cos(i / 120 * TAU), sin: Math.sin(i / 120 * TAU)}));

    function circle(ctx, x, y, radius) {
        ctx.beginPath();
        ctx.arc(x, y, Math.max(0, radius), 0, TAU);
    }

    function line(ctx, x1, y1, x2, y2) {
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.stroke();
    }

    function bezier(start, control, end, t) {
        const u = 1 - t;
        return {x: u * u * start.x + 2 * u * t * control.x + t * t * end.x,
            y: u * u * start.y + 2 * u * t * control.y + t * t * end.y};
    }

    class ThreatMapScene {
        constructor(canvas, options) {
            if (!(canvas instanceof HTMLCanvasElement)) throw new TypeError('ThreatMapScene needs a canvas');
            this.canvas = canvas;
            this.options = options || {};
            this.ctx = canvas.getContext('2d');
            this.base = document.createElement('canvas');
            this.baseCtx = this.base.getContext('2d');
            if (!this.ctx || !this.baseCtx) {
                if (typeof this.options.onError === 'function') this.options.onError('Canvas rendering is unavailable. Use the origin list to inspect records.');
                throw new Error('Canvas rendering is unavailable');
            }
            this.points = [];
            this.entries = [];
            this.paths = [];
            this.densitySprites = {};
            this.rings = [];
            this.hitPoints = [];
            this.selectedPoint = null;
            this.region = 'global';
            this.layer = 'routes';
            this.center = {...REGIONS.global};
            this.zoom = 1;
            this.elapsed = 0;
            this.lastFrame = 0;
            this.baseDirty = true;
            this.frameID = 0;
            this.paused = false;
            this.disposed = false;
            this.loading = true;
            this.error = false;
            this.drag = null;
            this.motionQuery = matchMedia('(prefers-reduced-motion: reduce)');
            this.reducedMotion = this.motionQuery.matches;
            this.originalAccessibility = {};
            ['tabindex', 'role', 'aria-label', 'aria-describedby', 'aria-keyshortcuts'].forEach(name => {
                this.originalAccessibility[name] = canvas.getAttribute(name);
            });
            this.originalCursor = canvas.style.cursor;
            this.originalTouchAction = canvas.style.touchAction;
            canvas.tabIndex = 0;
            canvas.style.touchAction = 'pan-y';
            canvas.setAttribute('role', 'group');
            canvas.setAttribute('aria-label', (this.originalAccessibility['aria-label'] || 'Threat map.') +
                ' Drag to rotate. Use arrow keys to inspect origins; Home and End select the first and last origin. Plus and minus zoom.');
            canvas.setAttribute('aria-keyshortcuts', 'ArrowRight ArrowLeft ArrowUp ArrowDown Home End Enter + -');
            this.selectionStatus = document.createElement('span');
            this.selectionStatus.id = 'threat-map-selection-' + (++sceneCount);
            this.selectionStatus.setAttribute('role', 'status');
            this.selectionStatus.setAttribute('aria-live', 'polite');
            this.selectionStatus.setAttribute('aria-atomic', 'true');
            this.selectionStatus.style.cssText = 'position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap;border:0';
            canvas.insertAdjacentElement('afterend', this.selectionStatus);
            canvas.setAttribute('aria-describedby', [this.originalAccessibility['aria-describedby'], this.selectionStatus.id].filter(Boolean).join(' '));
            this.tick = this.tick.bind(this);
            this.onVisibility = () => this.updateActivity();
            this.onMotion = event => { this.reducedMotion = event.matches; this.updateActivity(); };
            this.handlers = {
                pointerdown: event => this.startDrag(event),
                pointermove: event => this.movePointer(event),
                pointerup: event => this.endDrag(event),
                pointercancel: () => { this.drag = null; this.canvas.style.cursor = 'grab'; },
                lostpointercapture: () => { this.drag = null; },
                keydown: event => this.selectWithKeyboard(event),
                wheel: event => { event.preventDefault(); this.zoomBy(Math.exp(-event.deltaY * 0.001)); },
            };
            Object.entries(this.handlers).forEach(([name, handler]) => canvas.addEventListener(name, handler, name === 'wheel' ? {passive: false} : undefined));
            this.motionQuery.addEventListener('change', this.onMotion);
            document.addEventListener('visibilitychange', this.onVisibility);
            this.resizeObserver = new ResizeObserver(() => this.resize());
            this.resizeObserver.observe(canvas);
            this.resize();
            this.ready = this.retryGeography();
            this.updateActivity();
        }

        retryGeography() {
            if (this.disposed) return Promise.resolve(false);
            if (this.geographyRequest) return this.geographyRequest;
            this.loading = true;
            this.render();
            this.geographyRequest = getGeography().then(rings => {
                if (this.disposed) return false;
                this.rings = rings;
                this.loading = false;
                this.error = false;
                this.announceSelection();
                this.invalidate();
                return true;
            }).catch(() => {
                if (this.disposed) return false;
                this.loading = false;
                this.error = true;
                const message = 'World map unavailable. Origin records remain available in the list.';
                this.selectionStatus.textContent = message;
                if (typeof this.options.onError === 'function') this.options.onError(message);
                this.invalidate();
                return false;
            }).finally(() => { this.geographyRequest = null; });
            return this.geographyRequest;
        }

        setPoints(points) {
            if (this.disposed) return;
            this.points = (Array.isArray(points) ? points : []).filter(point => validLocation(point) && ['block', 'whitelist'].includes(point.kind))
                .map((point, index) => ({...point, id: point.id == null ? point.kind + ':' + (point.ip || index) : point.id}));
            this.entries = this.points.map(point => ({point, vector: vector(point.lon, point.lat)}));
            this.selectedPoint = this.selectedPoint ? this.points.find(point => point.id === this.selectedPoint.id) || null : null;
            if (!this.error) this.announceSelection();
            if (this.layer === 'density') this.invalidate();
            else this.render();
        }

        setPaths(paths) {
            if (this.disposed) return;
            this.paths = (Array.isArray(paths) ? paths : []).filter(path => path && validLocation(path.from) && validLocation(path.to) && ['block', 'whitelist'].includes(path.kind))
                .map(path => ({...path, from: {...path.from}, to: {...path.to},
                    fromVector: vector(path.from.lon, path.from.lat), toVector: vector(path.to.lon, path.to.lat)}));
            this.render();
        }

        setPaused(paused) { this.paused = Boolean(paused); this.updateActivity(); }

        setLayer(layer) {
            if (!['routes', 'density'].includes(layer) || this.disposed) return;
            this.layer = layer;
            this.invalidate();
        }

        setRegion(region) {
            if (!Object.prototype.hasOwnProperty.call(REGIONS, region) || this.disposed) return;
            this.region = region;
            this.center = {...REGIONS[region]};
            if (this.selectedPoint && !inRegion(this.selectedPoint, region)) {
                this.selectedPoint = null;
                if (!this.error) this.selectionStatus.textContent = '';
            }
            this.invalidate();
        }

        zoomBy(factor) {
            if (!Number.isFinite(factor) || factor <= 0 || this.disposed) return;
            this.zoom = Math.max(0.8, Math.min(3, this.zoom * factor));
            this.radius = this.baseRadius * this.zoom;
            this.invalidate();
        }

        reset() {
            if (this.disposed) return;
            this.region = 'global';
            this.layer = 'routes';
            this.center = {...REGIONS.global};
            this.zoom = 1;
            this.radius = this.baseRadius;
            this.selectedPoint = null;
            if (!this.error) this.selectionStatus.textContent = '';
            this.elapsed = 0;
            this.invalidate();
        }

        focusPoint(point) {
            if (!point || this.disposed) return;
            const entry = this.points.find(candidate => candidate.id === point.id || (!point.id && candidate.ip === point.ip));
            if (!entry || !inRegion(entry, this.region)) return;
            this.selectedPoint = entry;
            this.center = {lon: entry.lon, lat: entry.lat};
            this.announceSelection();
            this.invalidate();
        }

        announceSelection() {
            const entry = this.selectedPoint;
            const message = entry ? (entry.name || entry.ip || 'Origin') + (entry.country ? ', ' + entry.country : '') +
                '. ' + (entry.kind === 'whitelist' ? 'Whitelisted' : 'Blocked') + '. IP ' + (entry.ip || 'unavailable') +
                (entry.reason ? '. ' + entry.reason : '') + '.' : '';
            if (this.selectionStatus.textContent !== message) this.selectionStatus.textContent = message;
        }

        resize() {
            if (this.disposed) return;
            const bounds = this.canvas.getBoundingClientRect();
            const width = Math.max(1, bounds.width);
            const height = Math.max(1, bounds.height);
            const dpr = Math.min(window.devicePixelRatio || 1, 2);
            if (width === this.width && height === this.height && dpr === this.dpr) return;
            this.width = width;
            this.height = height;
            this.dpr = dpr;
            this.densitySprites = {};
            this.canvas.width = Math.round(width * dpr);
            this.canvas.height = Math.round(height * dpr);
            this.base.width = this.canvas.width;
            this.base.height = this.canvas.height;
            this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            this.baseCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
            this.cx = width * 0.5;
            this.cy = height * 0.5;
            this.baseRadius = Math.min(width * 0.345, height * 0.363);
            this.radius = this.baseRadius * this.zoom;
            this.invalidate();
        }

        destroy() {
            if (this.disposed) return;
            this.disposed = true;
            cancelAnimationFrame(this.frameID);
            this.resizeObserver.disconnect();
            this.motionQuery.removeEventListener('change', this.onMotion);
            document.removeEventListener('visibilitychange', this.onVisibility);
            Object.entries(this.handlers).forEach(([name, handler]) => this.canvas.removeEventListener(name, handler));
            this.selectionStatus.remove();
            Object.entries(this.originalAccessibility).forEach(([name, value]) => {
                if (value === null) this.canvas.removeAttribute(name);
                else this.canvas.setAttribute(name, value);
            });
            this.canvas.style.cursor = this.originalCursor;
            this.canvas.style.touchAction = this.originalTouchAction;
        }

        updateActivity() {
            cancelAnimationFrame(this.frameID);
            this.frameID = 0;
            this.lastFrame = 0;
            if (this.disposed || document.hidden) return;
            this.draw();
            if (!this.paused && !this.reducedMotion) this.frameID = requestAnimationFrame(this.tick);
        }

        render() { if (!document.hidden && !this.disposed) this.draw(); }
        invalidate() { this.baseDirty = true; this.render(); }

        tick(now) {
            if (this.disposed || this.paused || this.reducedMotion || document.hidden) return;
            this.frameID = requestAnimationFrame(this.tick);
            if (!this.lastFrame) this.lastFrame = now;
            const delta = now - this.lastFrame;
            if (delta < 1000 / 30) return;
            this.elapsed += Math.min(delta, 100) / 1000;
            this.lastFrame = now;
            this.draw();
        }

        project(v) {
            const forward = v[0] * this.view.cosLon + v[1] * this.view.sinLon;
            const x = v[1] * this.view.cosLon - v[0] * this.view.sinLon;
            const y = this.view.cosLat * v[2] - this.view.sinLat * forward;
            const z = this.view.sinLat * v[2] + this.view.cosLat * forward;
            return {x: this.cx + this.radius * x, y: this.cy - this.radius * y, z};
        }

        draw() {
            if (!this.width || this.disposed) return;
            // Detailed coastlines rasterize only after a view change. Live activity and
            // instrument rings animate independently, avoiding costly retina redraws.
            if (this.baseDirty) {
                const lon = this.center.lon * RAD;
                const lat = this.center.lat * RAD;
                this.view = {cosLon: Math.cos(lon), sinLon: Math.sin(lon), cosLat: Math.cos(lat), sinLat: Math.sin(lat)};
                this.drawBase();
                this.baseDirty = false;
            }
            const ctx = this.ctx;
            ctx.clearRect(0, 0, this.width, this.height);
            ctx.drawImage(this.base, 0, 0, this.width, this.height);
            this.drawInstruments(ctx);
            this.drawActivity(ctx);
            if (this.loading || this.error) this.drawStatus(ctx);
        }

        drawBase() {
            const ctx = this.baseCtx;
            const r = this.radius;
            ctx.clearRect(0, 0, this.width, this.height);
            for (let i = 0; i < 92; i += 1) {
                const x = ((i * 0.61803398875) % 1) * this.width;
                const y = ((i * 0.41421356237) % 1) * this.height;
                ctx.fillStyle = i % 7 === 0 ? 'rgba(242,154,145,0.29)' : 'rgba(211,181,177,0.11)';
                ctx.fillRect(x, y, i % 7 === 0 ? 1.3 : 0.7, i % 7 === 0 ? 1.3 : 0.7);
            }
            const halo = ctx.createRadialGradient(this.cx, this.cy, r * 0.83, this.cx, this.cy, r * 1.35);
            halo.addColorStop(0, 'rgba(228,35,49,0)');
            halo.addColorStop(0.39, 'rgba(241,54,63,0.10)');
            halo.addColorStop(0.54, 'rgba(244,37,51,0.04)');
            halo.addColorStop(1, 'rgba(234,41,49,0)');
            ctx.fillStyle = halo;
            circle(ctx, this.cx, this.cy, r * 1.35);
            ctx.fill();
            const ocean = ctx.createRadialGradient(this.cx - r * 0.45, this.cy - r * 0.55, 0,
                this.cx + r * 0.15, this.cy + r * 0.25, r * 1.4);
            ocean.addColorStop(0, '#29151b');
            ocean.addColorStop(0.55, '#140c13');
            ocean.addColorStop(1, '#080b0f');
            ctx.fillStyle = ocean;
            circle(ctx, this.cx, this.cy, r);
            ctx.fill();
            ctx.save();
            circle(ctx, this.cx, this.cy, r - 0.5);
            ctx.clip();
            this.drawGeography(ctx);
            ctx.lineWidth = 0.6;
            GRID.forEach(grid => {
                ctx.strokeStyle = grid.major ? 'rgba(249,112,119,0.24)' : 'rgba(224,104,116,0.13)';
                this.trace(ctx, grid.points);
                ctx.stroke();
            });
            ctx.fillStyle = 'rgba(255,153,153,0.10)';
            TEXTURE.forEach(v => {
                const point = this.project(v);
                if (point.z > 0.08) ctx.fillRect(point.x, point.y, 0.8, 0.8);
            });
            const shade = ctx.createLinearGradient(this.cx - r, this.cy - r, this.cx + r, this.cy + r);
            shade.addColorStop(0, 'rgba(247,99,97,0.09)');
            shade.addColorStop(0.55, 'rgba(0,0,0,0)');
            shade.addColorStop(1, 'rgba(3,7,11,0.55)');
            ctx.fillStyle = shade;
            ctx.fillRect(this.cx - r, this.cy - r, r * 2, r * 2);
            ctx.restore();
            ctx.lineWidth = 0.8;
            ctx.strokeStyle = 'rgba(253,138,125,0.55)';
            circle(ctx, this.cx, this.cy, r);
            ctx.stroke();
            ctx.strokeStyle = 'rgba(255,73,82,0.24)';
            circle(ctx, this.cx, this.cy, r + 3);
            ctx.stroke();
            // Density is a static accumulation for this data/view, not a per-frame effect.
            if (this.layer === 'density') this.entries.forEach(entry => {
                if (!inRegion(entry.point, this.region)) return;
                const position = this.project(entry.vector);
                if (position.z >= 0.03) this.drawDensity(ctx, position, entry.point.kind);
            });
        }

        trace(ctx, vectors) {
            ctx.beginPath();
            let active = false;
            let visible = 0;
            vectors.forEach(v => {
                const point = this.project(v);
                if (point.z < 0) { active = false; return; }
                if (active) ctx.lineTo(point.x, point.y);
                else ctx.moveTo(point.x, point.y);
                active = true;
                visible += 1;
            });
            return visible;
        }

        drawGeography(ctx) {
            ctx.lineWidth = 0.65;
            ctx.strokeStyle = 'rgba(239,110,110,0.57)';
            ctx.fillStyle = 'rgba(180,47,61,0.25)';
            this.rings.forEach(ring => {
                const visible = this.trace(ctx, ring);
                // Filling only complete front-facing polygons avoids lines crossing the globe's limb.
                if (visible === ring.length) { ctx.closePath(); ctx.fill(); }
                if (visible) ctx.stroke();
            });
        }

        drawInstruments(ctx) {
            const r = this.radius;
            ctx.save();
            ctx.translate(this.cx, this.cy);
            ctx.lineWidth = 0.6;
            ctx.strokeStyle = 'rgba(196,120,121,0.24)';
            [1.09, 1.19, 1.205].forEach(scale => { circle(ctx, 0, 0, r * scale); ctx.stroke(); });
            TICKS.forEach((tick, i) => {
                const inner = r * (i % 10 === 0 ? 1.22 : i % 5 === 0 ? 1.235 : 1.25);
                ctx.strokeStyle = i % 10 === 0 ? 'rgba(241,171,161,0.52)' : 'rgba(230,100,113,0.28)';
                line(ctx, tick.cos * inner, tick.sin * inner, tick.cos * r * 1.265, tick.sin * r * 1.265);
            });
            for (let i = 0; i < 3; i += 1) {
                const offset = this.elapsed * 0.008 * (i % 2 ? -1 : 1) + i * 2.07;
                ctx.strokeStyle = i === 0 ? 'rgba(255,140,123,0.65)' : 'rgba(244,55,75,0.45)';
                ctx.lineWidth = i === 0 ? 2.1 : 1.2;
                ctx.beginPath();
                ctx.arc(0, 0, r * (i % 2 ? 1.16 : 1.135), offset, offset + 0.62 + i * 0.18);
                ctx.stroke();
            }
            ctx.restore();
        }

        drawActivity(ctx) {
            this.hitPoints = [];
            if (this.layer === 'routes') this.paths.forEach((path, index) => {
                if (!inRegion(path.from, this.region) && !inRegion(path.to, this.region)) return;
                const start = this.project(path.fromVector);
                const end = this.project(path.toVector);
                if (start.z > 0.02 && end.z > 0.02) this.drawRoute(ctx, start, end, index, path.kind);
            });
            this.entries.forEach((entry, index) => {
                const point = entry.point;
                if (!inRegion(point, this.region)) return;
                const position = this.project(entry.vector);
                if (position.z < 0.03) return;
                this.hitPoints.push({point, x: position.x, y: position.y});
                this.drawMarker(ctx, position, index, point.kind);
                if (this.selectedPoint && point.id === this.selectedPoint.id) this.drawSelection(ctx, position, point);
            });
        }

        drawRoute(ctx, start, end, index, kind) {
            const dx = end.x - start.x;
            const dy = end.y - start.y;
            const lift = Math.min(this.radius * 0.56, Math.hypot(dx, dy) * 0.35) + 16;
            const control = {x: (start.x + end.x) / 2 + dy * 0.1, y: (start.y + end.y) / 2 - lift};
            ctx.beginPath();
            ctx.moveTo(start.x, start.y);
            ctx.quadraticCurveTo(control.x, control.y, end.x, end.y);
            ctx.strokeStyle = kind === 'whitelist' ? 'rgba(238,218,195,0.3)' : 'rgba(253,82,101,0.30)';
            ctx.lineWidth = 0.8;
            ctx.stroke();
            const phase = (this.elapsed * 0.14 + index * 0.173) % 1;
            ctx.beginPath();
            for (let step = 0; step <= 8; step += 1) {
                const point = bezier(start, control, end, Math.max(0, phase - 0.1 + step * 0.0125));
                if (!step) ctx.moveTo(point.x, point.y);
                else ctx.lineTo(point.x, point.y);
            }
            ctx.strokeStyle = kind === 'whitelist' ? 'rgba(238,218,195,0.75)' : 'rgba(255,113,115,0.72)';
            ctx.lineWidth = 1.25;
            ctx.stroke();
        }

        drawMarker(ctx, position, index, kind) {
            const white = kind === 'whitelist';
            const phase = (this.elapsed * 0.30 + index * 0.137) % 1;
            ctx.fillStyle = white ? 'rgba(238,218,195,0.08)' : 'rgba(255,73,85,0.09)';
            circle(ctx, position.x, position.y, 9);
            ctx.fill();
            ctx.strokeStyle = white ? 'rgba(238,218,195,' + (0.46 * (1 - phase)).toFixed(3) + ')' :
                'rgba(255,106,113,' + (0.46 * (1 - phase)).toFixed(3) + ')';
            ctx.lineWidth = 0.8;
            if (white) {
                const r = 4 + phase * 8;
                ctx.strokeRect(position.x - r, position.y - r, r * 2, r * 2);
                ctx.fillStyle = '#eedac3';
                ctx.fillRect(position.x - 2.5, position.y - 2.5, 5, 5);
            } else {
                circle(ctx, position.x, position.y, 5 + phase * 10);
                ctx.stroke();
                ctx.fillStyle = '#ff6671';
                circle(ctx, position.x, position.y, 2.6);
                ctx.fill();
            }
        }

        drawDensity(ctx, position, kind) {
            const r = 28;
            if (!this.densitySprites[kind]) {
                const sprite = document.createElement('canvas');
                sprite.width = sprite.height = Math.ceil(r * 2 * this.dpr);
                const paint = sprite.getContext('2d');
                const center = sprite.width / 2;
                const glow = paint.createRadialGradient(center, center, 0, center, center, center);
                glow.addColorStop(0, kind === 'whitelist' ? 'rgba(238,218,195,0.22)' : 'rgba(255,89,81,0.31)');
                glow.addColorStop(1, kind === 'whitelist' ? 'rgba(238,218,195,0)' : 'rgba(205,23,59,0)');
                paint.fillStyle = glow;
                paint.fillRect(0, 0, sprite.width, sprite.height);
                this.densitySprites[kind] = sprite;
            }
            ctx.drawImage(this.densitySprites[kind], position.x - r, position.y - r, r * 2, r * 2);
        }

        drawSelection(ctx, position, point) {
            ctx.strokeStyle = '#f4dacb';
            ctx.lineWidth = 1;
            ctx.strokeRect(position.x - 9, position.y - 9, 18, 18);
            const label = (point.kind === 'whitelist' ? 'WHITELISTED / ' : 'BLOCKED / ') + String(point.ip || point.name || 'ORIGIN').slice(0, 60);
            ctx.font = '9px ui-monospace, monospace';
            const width = Math.min(ctx.measureText(label).width + 14, this.width - 16);
            const x = Math.max(8, Math.min(this.width - width - 8, position.x - width / 2));
            const y = Math.max(24, position.y - 24);
            ctx.fillStyle = 'rgba(12,11,16,0.92)';
            ctx.fillRect(x, y - 13, width, 20);
            ctx.fillStyle = '#eedac3';
            ctx.textAlign = 'center';
            ctx.fillText(label, x + width / 2, y, width - 10);
        }

        drawStatus(ctx) {
            const message = this.error ? 'WORLD MAP UNAVAILABLE' : 'LOADING WORLD GEOMETRY';
            ctx.font = '10px ui-monospace, monospace';
            ctx.textAlign = 'center';
            const width = ctx.measureText(message).width;
            const y = Math.min(this.height - 24, this.cy + this.radius * 0.67);
            ctx.fillStyle = 'rgba(15,10,15,0.95)';
            ctx.fillRect(this.cx - width / 2 - 12, y - 15, width + 24, 27);
            ctx.fillStyle = '#e7b6ac';
            ctx.fillText(message, this.cx, y + 3);
        }

        nearest(event) {
            const bounds = this.canvas.getBoundingClientRect();
            const x = event.clientX - bounds.left;
            const y = event.clientY - bounds.top;
            let closest = null;
            let distance = 20;
            this.hitPoints.forEach(entry => {
                const next = Math.hypot(entry.x - x, entry.y - y);
                if (next < distance) { closest = entry; distance = next; }
            });
            return closest;
        }

        startDrag(event) {
            if (event.button !== 0 || event.isPrimary === false) return;
            this.canvas.focus({preventScroll: true});
            this.drag = {id: event.pointerId, x: event.clientX, y: event.clientY, center: {...this.center}, moved: false};
            this.canvas.setPointerCapture(event.pointerId);
            this.canvas.style.cursor = 'grabbing';
        }

        movePointer(event) {
            if (!this.drag) { this.canvas.style.cursor = this.nearest(event) ? 'pointer' : 'grab'; return; }
            if (event.pointerId !== this.drag.id) return;
            const dx = event.clientX - this.drag.x;
            const dy = event.clientY - this.drag.y;
            if (Math.hypot(dx, dy) > 4) this.drag.moved = true;
            if (!this.drag.moved) return;
            const scale = 90 / this.radius;
            this.center.lon = ((this.drag.center.lon - dx * scale + 540) % 360 + 360) % 360 - 180;
            this.center.lat = Math.max(-85, Math.min(85, this.drag.center.lat + dy * scale));
            this.invalidate();
        }

        endDrag(event) {
            if (!this.drag || this.drag.id !== event.pointerId) return;
            const moved = this.drag.moved;
            this.drag = null;
            if (this.canvas.hasPointerCapture(event.pointerId)) this.canvas.releasePointerCapture(event.pointerId);
            this.canvas.style.cursor = 'grab';
            if (!moved) {
                const entry = this.nearest(event);
                if (entry) this.choosePoint(entry.point);
            }
        }

        selectWithKeyboard(event) {
            if (event.altKey || event.ctrlKey || event.metaKey) return;
            if (['+', '=', '-', '_'].includes(event.key)) {
                event.preventDefault();
                this.zoomBy(event.key === '+' || event.key === '=' ? 1.2 : 1 / 1.2);
                return;
            }
            if (!['ArrowRight', 'ArrowDown', 'ArrowLeft', 'ArrowUp', 'Home', 'End', 'Enter'].includes(event.key)) return;
            event.preventDefault();
            const points = this.points.filter(point => inRegion(point, this.region));
            if (!points.length) return;
            let index = this.selectedPoint ? points.findIndex(point => point.id === this.selectedPoint.id) : -1;
            if (event.key === 'Home') index = 0;
            else if (event.key === 'End') index = points.length - 1;
            else if (event.key === 'Enter') index = Math.max(0, index);
            else if (event.key === 'ArrowRight' || event.key === 'ArrowDown') index = (index + 1) % points.length;
            else index = (index < 0 ? points.length - 1 : index - 1 + points.length) % points.length;
            this.choosePoint(points[index]);
        }

        choosePoint(point) {
            this.focusPoint(point);
            if (typeof this.options.onSelect === 'function') this.options.onSelect(point);
        }
    }

    window.ThreatMapScene = ThreatMapScene;
}());
