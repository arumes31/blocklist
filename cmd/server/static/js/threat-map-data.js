/* Pure API-to-view normalization, shared by the map controller and its tests. */
(function (root, factory) {
    if (typeof module === 'object' && module.exports) module.exports = factory();
    else root.ThreatMapData = factory();
})(typeof window === 'object' ? window : globalThis, function () {
    'use strict';
    const text = (value, max = 2048) => typeof value === 'string' ? value.slice(0, max) : '';
    const number = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;

    function coordinates(geo) {
        if (!geo || typeof geo.latitude !== 'number' || typeof geo.longitude !== 'number' ||
            !Number.isFinite(geo.latitude) || !Number.isFinite(geo.longitude) ||
            Math.abs(geo.latitude) > 90 || Math.abs(geo.longitude) > 180) return null;
        return {lat:geo.latitude, lon:geo.longitude};
    }

    function normalize(item, kind, now = Date.now()) {
        if (!item || !text(item.ip, 255) || !['block', 'whitelist'].includes(kind)) return null;
        const entry = item.data && typeof item.data === 'object' ? item.data : {};
        const expiresAt = text(entry.expires_at, 80);
        if (expiresAt && Number.isFinite(Date.parse(expiresAt)) && Date.parse(expiresAt) <= now) return null;
        const geo = entry.geolocation || {};
        const position = coordinates(geo);
        const ip = text(item.ip, 255);
        return {
            id: `${kind}:${ip}`, ip, kind, name:text(geo.city, 120) || ip,
            country:text(geo.country, 120) || 'Unknown', lat:position ? position.lat : null,
            lon:position ? position.lon : null, reason:text(entry.reason) || 'No reason recorded',
            addedBy:text(entry.added_by, 255), timestamp:text(entry.timestamp, 80),
            asn:number(geo.asn), asnOrg:text(geo.asn_org, 255), expiresAt,
            threatScore:number(entry.threat_score), count:1,
        };
    }

    function snapshot(items, kind, limit = 500, now = Date.now()) {
        if (!Array.isArray(items)) return [];
        const result = [];
        const seen = new Set();
        for (const item of items) {
            const point = normalize(item, kind, now);
            if (!point || seen.has(point.id)) continue;
            seen.add(point.id);
            result.push(point);
            if (result.length >= limit) break;
        }
        return result;
    }

    function stats(payload, initial = false) {
        payload = payload || {};
        return {
            total:number(initial ? payload.total : payload.active_blocks), day:number(payload.day),
            hour:number(payload.hour), bpm:number(payload.blocks_minute), whitelisted:number(payload.whitelisted),
            countries:Array.isArray(payload.top_countries) ? payload.top_countries
                .filter(row => row && number(row.count) !== null)
                .map(row => ({country:text(row.country, 120) || 'Unknown', count:row.count})).slice(0, 10) : [],
        };
    }

    function event(message, now = Date.now()) {
        if (!message || !['block', 'whitelist', 'unblock'].includes(message.action) || !message.data) return null;
        const ip = text(message.data.ip, 255);
        if (!ip) return null;
        if (message.action === 'unblock') return {action:'unblock', ip, point:null, path:null};
        const point = normalize(message.data, message.action, now);
        if (!point) return null;
        const from = coordinates(message.data.data && message.data.data.geolocation);
        const to = coordinates(message.data.source_geo);
        return {action:message.action, ip, point,
            path:from && to ? {from, to, kind:message.action, createdAt:now} : null};
    }

    function inRegion(point, region) {
        if (region === 'global') return true;
        if (point.lat === null || point.lon === null) return false;
        if (region === 'europe') return point.lon > -15 && point.lon < 50 && point.lat > 35;
        if (region === 'asia') return point.lon >= 50 && point.lat > -15;
        if (region === 'americas') return point.lon < -25;
        return true;
    }

    function visible(points, filters) {
        return points.filter(point => (point.kind === 'block' ? filters.blocked : filters.whitelist) && inRegion(point, filters.region));
    }

    function replay(points, events, kind, limit = 500) {
        let result = points;
        for (const change of events) {
            if (change.action === 'unblock' && kind === 'block') result = result.filter(point => point.ip !== change.ip);
            else if (change.action === kind) result = [change.point,...result.filter(point => point.id !== change.point.id)].slice(0,limit);
        }
        return result;
    }

    return {coordinates, normalize, snapshot, stats, event, inRegion, visible, replay};
});
