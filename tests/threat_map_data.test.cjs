const {test} = require('node:test');
const assert = require('node:assert/strict');
const data = require('../cmd/server/static/js/threat-map-data.js');
const item = (ip, geo = {latitude:0, longitude:0}) => ({ip, data:{geolocation:geo, reason:'Port scan', timestamp:'2026-10-04T10:00:00Z'}});

test('valid zero coordinates survive; absent, coerced and out-of-range geography does not', () => {
    assert.deepEqual(data.coordinates({latitude:0,longitude:0}),{lat:0,lon:0});
    for (const geo of [null,{}, {latitude:null,longitude:0},{latitude:'0',longitude:10},{latitude:91,longitude:0},{latitude:0,longitude:181},{latitude:NaN,longitude:0}]) assert.equal(data.coordinates(geo),null);
    assert.equal(data.normalize(item('192.0.2.1',null),'block').lat,null);
    assert.equal(data.normalize(item('192.0.2.1'),'block').lat,0);
    assert.equal(data.coordinates({latitude:0,longitude:0,asn:64500,city:'',country:''}),null);
    assert.deepEqual(data.coordinates({latitude:0,longitude:0,asn:64500,city:'Located',country:'Example'}),{lat:0,lon:0});
});

test('snapshot retains unmapped records, deduplicates kinds, excludes expiry and stays bounded', () => {
    const input=Array.from({length:600},(_,i)=>item(`192.0.2.${i}`));
    input[1]=input[0];
    input[2]=item('unmapped',null);
    input[3]={ip:'expired',data:{expires_at:'2020-01-01T00:00:00Z'}};
    const snapshot=data.snapshot(input,'block',500,Date.parse('2026-10-04'));
    assert.equal(snapshot.length,500);
    assert.equal(snapshot.filter(p=>p.ip===input[0].ip).length,1);
    assert.equal(snapshot.find(p=>p.ip==='unmapped').lat,null);
    assert.ok(!snapshot.some(p=>p.ip==='expired'));
    assert.deepEqual(data.snapshot(null,'whitelist'),[]);
    assert.notEqual(data.normalize(item('192.0.2.1'),'block').id,data.normalize(item('192.0.2.1'),'whitelist').id);
});

test('stats use active blocks instead of cumulative historical total and preserve unavailable values', () => {
    assert.equal(data.stats({active_blocks:42,total:9000}).total,42);
    assert.equal(data.stats({total:42},true).total,42);
    assert.equal(data.stats({total:9000}).total,null);
    assert.equal(data.stats({active_blocks:null}).total,null);
    assert.equal(data.stats({blocks_minute:2.5}).bpm,2.5);
    assert.deepEqual(data.stats({top_countries:null}).countries,[]);
});

test('events without geolocation still produce ticker updates and unblock invalidations', () => {
    assert.equal(data.event({action:'block',data:item('192.0.2.1',null)}).point.lat,null);
    assert.deepEqual(data.event({action:'unblock',data:{ip:'192.0.2.1'}},100),{action:'unblock',ip:'192.0.2.1',point:null,path:null,visibleUntil:8100});
    for(const message of [null,{}, {action:'unblock',data:null},{action:'other',data:item('x')}]) assert.equal(data.event(message),null);
});

test('paths require both real endpoints and accept the equator', () => {
    const message={action:'block',data:{...item('192.0.2.1'),source_geo:{latitude:0,longitude:16}}};
    assert.deepEqual(data.event(message,123).path,{from:{lat:0,lon:0},to:{lat:0,lon:16},kind:'block',createdAt:123,durationMs:10000,destinationKind:'target',originIP:'192.0.2.1'});
    assert.equal(data.event(message,123).point.visibleUntil,8123);
    delete message.data.source_geo;
    assert.equal(data.event(message).path,null);
});

test('full-list replay retains more than one API page and applies repeated IP updates in order', () => {
    const points=data.snapshot(Array.from({length:1200},(_,i)=>item(`ip-${i}`)),'block',Infinity);
    const events=[data.event({action:'block',data:item('ip-0')}),data.event({action:'unblock',data:{ip:'ip-0'}}),data.event({action:'block',data:item('new')})];
    const all=data.replay(points,events,'block',Infinity);
    assert.equal(all.length,1200);
    assert.equal(all[0].ip,'new');
    assert.ok(all.some(point=>point.ip==='ip-1199'));
    assert.ok(!all.some(point=>point.ip==='ip-0'));
});

test('routes target the reporting server and missing geography never invents a destination', () => {
    const message={action:'block',data:{...item('192.0.2.1'),source_geo:{latitude:51,longitude:10,city:'Berlin'}}};
    assert.deepEqual(data.event(message).path.to,{lat:51,lon:10});
    assert.equal(data.event(message).path.destinationKind,'target');
    assert.equal(data.event(message).point.destination.name,'Berlin');
    message.data.source_geo=null;
    assert.equal(data.event(message).path,null);
    assert.equal(data.event(message).point.destination,null);
});

test('visible records respect filters and region while retaining unknown locations globally', () => {
    const records=[data.normalize(item('1',{latitude:48,longitude:16}),'block'),data.normalize(item('2',{latitude:35,longitude:139}),'whitelist'),data.normalize(item('3',null),'block')];
    assert.equal(data.visible(records,{blocked:true,whitelist:false,region:'global'}).length,2);
    assert.equal(data.visible(records,{blocked:true,whitelist:true,region:'asia'})[0].ip,'2');
    assert.deepEqual(data.visible(records,{blocked:false,whitelist:false,region:'global'}),[]);
});

test('events received during an older snapshot are replayed without resurrecting removed IPs', () => {
    const old=data.snapshot([item('old'),item('removed')],'block');
    const events=[data.event({action:'unblock',data:{ip:'removed'}}),data.event({action:'block',data:item('new')}),data.event({action:'whitelist',data:item('allowed')})];
    const result=data.replay(old,events,'block');
    assert.deepEqual(result.map(p=>p.ip),['new','old']);
    assert.deepEqual(data.replay(result,events,'block'),result);
    assert.deepEqual(data.replay([],events,'whitelist').map(p=>p.ip),['allowed']);
});
