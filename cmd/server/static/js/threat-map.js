/* Live Threat Map: bounded snapshots, event updates, and Orbital/Leaflet views. */
(() => {
    'use strict';
    const D = window.ThreatMapData;
    const $ = id => document.getElementById(id);
    const fmt = value => typeof value === 'number' ? value.toLocaleString() : '—';
    const motion = matchMedia('(prefers-reduced-motion: reduce)');
    const PAGE_SIZE = 6;
    let bootstrap = {};
    try { bootstrap = JSON.parse($('threat-map-bootstrap').textContent); } catch (_) { /* Fetch will report unavailable data. */ }
    let statsAllowed = bootstrap.stats_allowed === true;
    let blocks = [], whitelists = [], records = [], paths = [];
    let blockTotal = null, whitelistTotal = null, blocksTruncated = false;
    let selected = null, page = 0, view = 'globe', layer = 'routes', paused = false;
    let scene, flat, pins, clusters, heat, flatPaths, trendChart;
    let worldData, worldRequest, requestErrors = [];
    const mapErrors = {globe:'',flat:''};
    const centers = {global:[20,0,2],europe:[48,17,4],asia:[27,100,3],americas:[20,-80,3]};
    let refreshQueued = false;
    let version = 0, request, pendingEvents, refreshTimer, pollTimer, pathTimer, renderTimer, reconnectTimer;
    let socket, reconnectDelay = 3000, stopped = false;
    const filters = () => ({blocked:$('toggle-blocked').checked, whitelist:$('toggle-whitelist').checked, region:$('region').value});
    const motionPaused = () => paused || motion.matches || document.hidden;

    function setStatus(message, error = false) {
        $('data-status').textContent = message;
        $('data-status').classList.toggle('is-error', error);
    }

    function showErrors() {
        const errors = [...requestErrors, ...(mapErrors[view] ? [mapErrors[view]] : [])];
        $('retry-data').hidden = !errors.length;
        setStatus(errors.length ? errors.join(' ') : 'Data current · refreshes automatically', errors.length > 0);
    }

    function displayDate(value) {
        if (!value) return 'Not recorded';
        const date = new Date(value);
        return Number.isFinite(date.getTime()) ? date.toLocaleString() : 'Not recorded';
    }

    function selectRecord(point, focus = false) {
        selected = point;
        $('detail-empty').hidden = Boolean(point);
        $('detail-content').hidden = !point;
        if (!point) return;
        const values = {
            'selected-name':point.name, 'selected-country':point.country, 'selected-ip':point.ip,
            'selected-reason':point.reason, 'selected-source':point.addedBy || 'Not recorded',
            'selected-time':displayDate(point.timestamp),
            'selected-asn':point.asn ? `AS${point.asn}${point.asnOrg ? ' · ' + point.asnOrg : ''}` : 'Not recorded',
            'selected-expiry':point.expiresAt ? displayDate(point.expiresAt) : 'No expiry recorded',
            'selected-score':point.threatScore === null ? 'Not recorded' : String(point.threatScore),
            'selected-kind':point.kind === 'whitelist' ? 'WHITELISTED' : 'BLOCKED',
        };
        Object.entries(values).forEach(([id, value]) => { $(id).textContent = value; });
        $('selected-kind').dataset.kind = point.kind;
        document.querySelectorAll('.origin-row').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.id === point.id)));
        if (focus && point.lat !== null) {
            if (view === 'globe') scene?.focusPoint(point);
            else flat?.setView([point.lat, point.lon], Math.max(4, flat.getZoom()), {animate:false});
        }
    }

    function renderOrigins() {
        const list = $('origin-list');
        list.replaceChildren();
        const pages = Math.max(1, Math.ceil(records.length / PAGE_SIZE));
        page = Math.min(page, pages - 1);
        for (const point of records.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)) {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'origin-row';
            button.dataset.id = point.id;
            button.setAttribute('aria-pressed', String(selected?.id === point.id));
            const name = document.createElement('span');
            name.textContent = point.name;
            const address = document.createElement('small');
            address.textContent = point.name === point.ip ? point.country : point.ip;
            const kind = document.createElement('strong');
            kind.textContent = point.kind === 'whitelist' ? 'ALLOW' : 'BLOCK';
            kind.dataset.kind = point.kind;
            name.append(address);
            button.append(name, kind);
            button.addEventListener('click', () => selectRecord(point, true));
            list.append(button);
        }
        if (!records.length) {
            const empty = document.createElement('p');
            empty.className = 'empty-state';
            empty.textContent = !filters().blocked && !filters().whitelist ? 'Enable a data filter to show IPs.' : 'No IPs in this view.';
            list.append(empty);
        }
        $('origin-page').textContent = `${page + 1} / ${pages}`;
        $('origin-prev').disabled = page === 0;
        $('origin-next').disabled = page + 1 >= pages;
    }

    function updateStats(payload, initial = false) {
        const s = D.stats(payload, initial);
        for (const [id, value] of [['stat-total',s.total],['stat-day',s.day],['stat-hour',s.hour],['stat-whitelist',s.whitelisted]]) $(id).textContent = fmt(value);
        $('bpm-display').textContent = s.bpm === null ? '—' : s.bpm.toFixed(1);
        const list = $('country-list');
        list.replaceChildren();
        for (const row of s.countries.slice(0, 6)) {
            const element = document.createElement('div');
            element.className = 'country-row';
            const label = document.createElement('span');
            label.textContent = row.country;
            const count = document.createElement('strong');
            count.textContent = fmt(row.count);
            const bar = document.createElement('i');
            bar.setAttribute('aria-hidden', 'true');
            bar.style.width = `${Math.min(100, row.count / Math.max(1, ...s.countries.map(c => c.count)) * 100)}%`;
            element.append(label, count, bar);
            list.append(element);
        }
        if (!s.countries.length) list.textContent = statsAllowed ? 'No country data available.' : 'Requires statistics permission.';
    }

    function initTrend() {
        const values = Array.isArray(bootstrap.trend) ? bootstrap.trend.filter(p => p && Number.isFinite(p.y) && p.y >= 0) : [];
        if (!statsAllowed || !bootstrap.trend_available) {
            $('trend-chart').hidden = true;
            $('trend-status').textContent = statsAllowed ? 'Trend unavailable. Reload to retry.' : 'Requires statistics permission.';
            return;
        }
        $('trend-status').textContent = `Last 24 hours · snapshot at ${new Date().toLocaleTimeString()}`;
        if (!values.length) {
            $('trend-chart').hidden = true;
            $('trend-status').textContent = 'No recorded blocks in the last 24 hours.';
            return;
        }
        trendChart = new Chart($('trend-chart'), {
            type:'line',
            data:{labels:values.map(p => String(p.x)),datasets:[{data:values.map(p => p.y),borderColor:'#ef6556',backgroundColor:'#ef655622',fill:true,tension:0.2,pointRadius:1,borderWidth:1.5}]},
            options:{animation:false,responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#b7a89b',maxTicksLimit:4,font:{size:10}},grid:{display:false}},y:{beginAtZero:true,ticks:{color:'#b7a89b',maxTicksLimit:3,font:{size:10}},grid:{color:'#3d2a25'}}}},
        });
    }

    async function json(url, signal) {
        const response = await fetch(url, {signal,credentials:'same-origin',headers:{Accept:'application/json'},cache:'no-store'});
        if (!response.ok || response.redirected) {
            const error = new Error(response.redirected || response.status === 401 ? 'Session expired. Reload to sign in.' : `Request failed (${response.status}).`);
            error.status = response.redirected ? 401 : response.status;
            throw error;
        }
        return response.json();
    }

    async function refresh(supersede = false) {
        clearTimeout(refreshTimer);
        refreshTimer = null;
        if (stopped || document.hidden) return;
        if (request && !supersede) { refreshQueued = true; return; }
        request?.abort();
        refreshQueued = false;
        const current = ++version;
        const changes = {events:[],overflow:false};
        pendingEvents = changes;
        request = new AbortController();
        const abort = request;
        const timeout = setTimeout(() => abort.abort(), 12000);
        const jobs = [];
        if (filters().blocked) jobs.push({name:'Blocked IPs',kind:'block',promise:json('/api/v1/ips?limit=500',abort.signal)});
        if (filters().whitelist) jobs.push({name:'Whitelist',kind:'whitelist',promise:json('/api/v1/whitelists',abort.signal)});
        if (statsAllowed) jobs.push({name:'Statistics',kind:'stats',promise:json('/api/v1/stats',abort.signal)});
        setStatus('Refreshing data…');
        const results = await Promise.allSettled(jobs.map(job => job.promise));
        clearTimeout(timeout);
        if (stopped || current !== version) return;
        request = null;
        pendingEvents = null;
        requestErrors = [];
        results.forEach((result, index) => {
            const job = jobs[index];
            if (result.status === 'rejected') {
                const error = result.reason;
                requestErrors.push(error.status === 401 ? error.message : `${job.name} unavailable; previous data retained.`);
                if (job.kind === 'stats' && error.status === 403) {
                    statsAllowed = false;
                    updateStats({});
                    trendChart?.destroy();
                    $('trend-chart').hidden = true;
                    $('trend-status').textContent = 'Requires statistics permission.';
                }
                return;
            }
            const payload = result.value;
            if (job.kind !== 'stats' && changes.overflow) {
                requestErrors.push(`${job.name} changed during loading; refreshing again.`);
                scheduleRefresh();
                return;
            }
            if (job.kind === 'block') {
                if (!payload || (payload.items !== null && !Array.isArray(payload.items))) { requestErrors.push('Blocked IP response invalid; previous data retained.'); return; }
                blocks = D.replay(D.snapshot(payload.items, 'block'),changes.events,'block');
                blockTotal = typeof payload.total === 'number' ? payload.total : null;
                blocksTruncated = Boolean(payload.next) || blockTotal > blocks.length;
            } else if (job.kind === 'whitelist') {
                if (payload !== null && !Array.isArray(payload)) { requestErrors.push('Whitelist response invalid; previous data retained.'); return; }
                whitelistTotal = payload?.length || 0;
                whitelists = D.replay(D.snapshot(payload, 'whitelist'),changes.events,'whitelist');
            } else if (payload && typeof payload === 'object' && typeof payload.active_blocks === 'number') updateStats(payload);
            else requestErrors.push('Statistics response invalid; previous data retained.');
        });
        if (!requestErrors.length) {
            const now = new Date();
            $('updated-at').textContent = now.toLocaleTimeString();
            $('updated-at').dateTime = now.toISOString();
        }
        render();
        showErrors();
        if (refreshQueued) { refreshQueued = false; scheduleRefresh(); }
    }

    function scheduleRefresh() {
        if (refreshTimer || stopped || document.hidden) return;
        refreshTimer = setTimeout(refresh, 5000);
    }

    function render() {
        const active = filters();
        const now = Date.now();
        blocks = blocks.filter(p => !p.expiresAt || !(Date.parse(p.expiresAt) <= now));
        whitelists = whitelists.filter(p => !p.expiresAt || !(Date.parse(p.expiresAt) <= now));
        records = D.visible([...blocks, ...whitelists], active);
        const points = records.filter(p => p.lat !== null);
        scene?.setPoints(points);
        const selectedRecord = selected && records.find(p => p.id === selected.id);
        selectRecord(selectedRecord || null);
        renderOrigins();
        $('missing-geo').textContent = fmt(records.length - points.length);
        const coverage = [`${fmt(points.length)} mapped / ${fmt(records.length)} loaded in view`];
        if (active.blocked && blocksTruncated) coverage.push(`Block sample: up to 500 of ${fmt(blockTotal)}`);
        if (active.whitelist && whitelistTotal > 500) coverage.push(`Whitelist sample: up to 500 of ${fmt(whitelistTotal)}`);
        $('coverage-status').textContent = coverage.join(' · ');
        if (flat && view === 'flat') renderFlat();
        renderPaths();
    }

    function scheduleRender() {
        if (renderTimer || stopped || document.hidden) return;
        renderTimer = setTimeout(() => { renderTimer = null; render(); }, 200);
    }

    function popup(point) {
        const node = document.createElement('div');
        for (const value of [point.ip, `${point.name} · ${point.country}`, point.kind.toUpperCase(), point.reason, `Source: ${point.addedBy || 'Not recorded'}`, displayDate(point.timestamp)]) {
            const line = document.createElement('div');
            line.textContent = value;
            node.append(line);
        }
        return node;
    }

    async function initFlat() {
        if (!flat) {
            const center = centers[$('region').value];
            flat = L.map('flat-map',{center:center.slice(0,2),zoom:center[2],minZoom:1,maxZoom:18,zoomControl:false,attributionControl:false,zoomAnimation:false,fadeAnimation:false,markerZoomAnimation:false});
            pins = L.layerGroup();
            clusters = L.markerClusterGroup({animate:false,showCoverageOnHover:false,maxClusterRadius:45,iconCreateFunction:group => L.divIcon({html:`<span>${group.getChildCount()}</span>`,className:'threat-cluster',iconSize:[34,34]})});
            heat = L.heatLayer([],{radius:24,blur:18,minOpacity:0.3,gradient:{0.3:'#52251f',0.6:'#c64d3d',1:'#ff9980'}});
            flatPaths = L.layerGroup().addTo(flat);
        }
        flat.invalidateSize();
        renderFlat();
        if (worldData || worldRequest) return;
        worldRequest = json('/js/world.json').then(data => {
            if (stopped) return;
            L.geoJSON(data,{interactive:false,style:{color:'#a855414f',weight:0.7,fillColor:'#50251e',fillOpacity:0.4}}).addTo(flat).bringToBack();
            worldData = data;
            mapErrors.flat = '';
            showErrors();
        }).catch(() => { mapErrors.flat = 'Flat-map geography unavailable. Refresh to reload.'; showErrors(); }).finally(() => { worldRequest = null; });
        await worldRequest;
    }

    function renderFlat() {
        if (!flat || view !== 'flat') return;
        [pins,clusters,heat].forEach(group => flat.removeLayer(group));
        pins.clearLayers();
        clusters.clearLayers();
        const points = records.filter(p => p.lat !== null);
        const markers = points.map(point => L.marker([point.lat,point.lon],{
            title:`${point.ip} · ${point.kind}`,keyboard:true,
            icon:L.divIcon({html:`<span class="map-pin ${point.kind}"></span>`,className:'map-marker',iconSize:[14,14]}),
        }).bindPopup(popup(point)).on('click',() => selectRecord(point)));
        if (layer === 'density') {
            heat.setLatLngs(points.map(p => [p.lat,p.lon,1]));
            flat.addLayer(heat);
        } else if ($('toggle-cluster').checked) {
            clusters.addLayers(markers);
            flat.addLayer(clusters);
        } else {
            markers.forEach(marker => pins.addLayer(marker));
            flat.addLayer(pins);
        }
    }

    function renderPaths() {
        const now = Date.now();
        paths = paths.filter(path => now - path.createdAt < 10000).slice(-24);
        const active = filters();
        const visible = $('toggle-paths').checked ? paths.filter(path => (path.kind === 'block' ? active.blocked : active.whitelist) && D.inRegion(path.from,active.region)) : [];
        scene?.setPaths(visible);
        if (!flatPaths || view !== 'flat') return;
        flatPaths.clearLayers();
        for (const path of visible) L.polyline([[path.from.lat,path.from.lon],[path.to.lat,path.to.lon]],{weight:1.5,color:path.kind === 'whitelist' ? '#e6dfd6' : '#ef6556',dashArray:'7 10',className:'live-route'}).addTo(flatPaths);
    }

    function appendEvent(event) {
        const item = document.createElement('li');
        item.className = `event-${event.action}`;
        const time = document.createElement('time');
        time.textContent = new Date().toLocaleTimeString();
        const text = document.createElement('div');
        const type = document.createElement('strong');
        type.textContent = event.action.toUpperCase();
        const ip = document.createElement('span');
        ip.textContent = event.ip;
        const reason = document.createElement('small');
        reason.textContent = event.point?.reason || 'Block removed';
        text.append(type,ip,reason);
        item.append(time,text);
        const list = $('event-stream');
        list.querySelector('.empty-state')?.remove();
        list.prepend(item);
        while (list.children.length > 50) list.lastElementChild.remove();
    }

    function receive(message) {
        let event;
        try { event = D.event(JSON.parse(message.data)); } catch (_) { return; }
        if (!event) return;
        if (pendingEvents) {
            if (pendingEvents.events.length < 1000) pendingEvents.events.push(event);
            else pendingEvents.overflow = true;
        }
        if (event.action === 'unblock') blocks = blocks.filter(p => p.ip !== event.ip);
        else if (event.action === 'block') blocks = [event.point,...blocks.filter(p => p.id !== event.point.id)].slice(0,500);
        else whitelists = [event.point,...whitelists.filter(p => p.id !== event.point.id)].slice(0,500);
        if (event.path) paths = [...paths,event.path].slice(-24);
        const active = filters();
        if (event.action === 'whitelist' ? active.whitelist : active.blocked) appendEvent(event);
        scheduleRender();
        scheduleRefresh();
    }

    function closeSocket() {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
        if (!socket) return;
        socket.onopen = socket.onmessage = socket.onerror = socket.onclose = null;
        socket.close();
        socket = null;
    }

    function connect() {
        if (stopped || document.hidden || socket) return;
        $('live-status').textContent = 'CONNECTING';
        socket = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`);
        socket.onopen = () => { $('live-status').textContent = 'LIVE'; reconnectDelay = 3000; scheduleRefresh(); };
        socket.onmessage = message => { if (typeof message.data === 'string' && message.data.length < 131072) receive(message); };
        socket.onerror = () => socket?.close();
        socket.onclose = () => {
            socket = null;
            $('live-status').textContent = 'RECONNECTING';
            if (!stopped && !document.hidden) {
                reconnectTimer = setTimeout(connect,reconnectDelay);
                reconnectDelay = Math.min(30000,reconnectDelay * 2);
            }
        };
    }

    function updateMotion() {
        const still = motionPaused();
        document.body.classList.toggle('is-paused', still);
        $('pause-motion').textContent = motion.matches ? 'Reduced motion' : paused ? 'Resume motion' : 'Pause motion';
        $('pause-motion').disabled = motion.matches;
        $('pause-motion').setAttribute('aria-pressed', String(still));
        scene?.setPaused(still || view !== 'globe');
    }

    function setView(next) {
        view = next;
        $('scene').hidden = next !== 'globe';
        $('flat-map').hidden = next !== 'flat';
        $('toggle-cluster').disabled = next !== 'flat' || layer === 'density';
        document.querySelectorAll('[data-view]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.view === next)));
        updateMotion();
        if (next === 'flat') initFlat();
        showErrors();
        renderPaths();
    }

    function stopRuntime() {
        clearInterval(pollTimer); clearInterval(pathTimer);
        clearTimeout(refreshTimer); clearTimeout(renderTimer);
        pollTimer = pathTimer = refreshTimer = renderTimer = null;
        request?.abort(); request = null; pendingEvents = null; refreshQueued = false; version++;
        closeSocket();
        scene?.setPaused(true);
    }

    function startRuntime() {
        if (stopped || document.hidden) return;
        if (!pollTimer) pollTimer = setInterval(refresh,30000);
        if (!pathTimer) pathTimer = setInterval(() => { if (paths.length) renderPaths(); },1000);
        updateMotion();
        connect();
        refresh();
    }

    try { scene = new ThreatMapScene($('scene'),{onSelect:point => selectRecord(point),onError:message => { mapErrors.globe = message; showErrors(); }}); }
    catch (_) { mapErrors.globe = 'Globe unavailable. Use the flat map to inspect locations.'; }
    updateStats(statsAllowed ? bootstrap : {},true);
    initTrend();
    for (const id of ['toggle-blocked','toggle-whitelist']) $(id).addEventListener('change',() => { page = 0; render(); refresh(true); });
    $('toggle-cluster').addEventListener('change',renderFlat);
    $('toggle-paths').addEventListener('change',renderPaths);
    $('region').addEventListener('change',() => {
        page = 0;
        scene?.setRegion($('region').value);
        const center = centers[$('region').value];
        flat?.setView(center.slice(0,2),center[2],{animate:false});
        render();
    });
    document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click',() => setView(button.dataset.view)));
    document.querySelectorAll('[data-layer]').forEach(button => button.addEventListener('click',() => {
        layer = button.dataset.layer;
        document.querySelectorAll('[data-layer]').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
        scene?.setLayer(layer);
        $('toggle-cluster').disabled = view !== 'flat' || layer === 'density';
        renderFlat();
    }));
    $('zoom-in').addEventListener('click',() => view === 'globe' ? scene?.zoomBy(1.2) : flat?.zoomIn(1,{animate:false}));
    $('zoom-out').addEventListener('click',() => view === 'globe' ? scene?.zoomBy(1/1.2) : flat?.zoomOut(1,{animate:false}));
    $('reset-view').addEventListener('click',() => {
        $('region').value = 'global'; page = 0; scene?.reset(); scene?.setLayer(layer);
        flat?.setView([20,0],2,{animate:false}); updateMotion(); render();
    });
    $('pause-motion').addEventListener('click',() => { paused = !paused; updateMotion(); });
    $('origin-prev').addEventListener('click',() => { page = Math.max(0,page-1); renderOrigins(); });
    $('origin-next').addEventListener('click',() => { page++; renderOrigins(); });
    $('retry-data').addEventListener('click',() => {
        if (view === 'flat' && !worldData) initFlat();
        if (view === 'globe' && mapErrors.globe && scene) scene.retryGeography().then(ok => { if (ok) mapErrors.globe = ''; showErrors(); });
        refresh(true);
    });
    motion.addEventListener('change',updateMotion);
    document.addEventListener('visibilitychange',() => { if (document.hidden) { stopRuntime(); $('live-status').textContent = 'SUSPENDED'; } else startRuntime(); });
    window.addEventListener('pagehide',event => {
        stopRuntime();
        if (!event.persisted) { stopped = true; scene?.destroy(); flat?.remove(); trendChart?.destroy(); }
    });
    window.addEventListener('pageshow',event => { if (event.persisted) startRuntime(); });
    setView('globe');
    render();
    startRuntime();
})();
