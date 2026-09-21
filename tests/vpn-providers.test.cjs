const fs = require('fs');
const vm = require('vm');
const assert = require('assert/strict');
const source = fs.readFileSync(__dirname + '/../overrides/vpn-providers.js', 'utf8');
const context = vm.createContext({});
vm.runInContext(source + '\nglobalThis.api = {main, VENDOR_DEFS, VPN_LOCATION_LABELS};', context);
const {main, VENDOR_DEFS, VPN_LOCATION_LABELS} = context.api;
const missing = VENDOR_DEFS.flatMap(v => v.locations.filter(l => !VPN_LOCATION_LABELS[l.path]).map(l => l.path));
assert.equal(missing.length, 0, 'every topology path needs a generated label');
const toggles = ['x-pia-openvpn','x-pia-wireguard','x-ss-openvpn','x-ss-wireguard'];
function flags(mask) { return Object.fromEntries(toggles.map((t,i)=>[t, !!(mask & (1<<i))])); }
function validate(config) {
  const groups = config['proxy-groups'];
  const names = groups.map(g=>g.name);
  const duplicates = names.filter((n,i)=>names.indexOf(n)!==i);
  assert.equal(duplicates.length, 0, 'duplicate group names: ' + duplicates.join(', '));
  for (const group of groups) {
    for (const name of group.use || []) assert.ok(config['proxy-providers'][name], 'missing provider '+name);
    for (const name of group.proxies || []) assert.ok(['DIRECT','REJECT'].includes(name) || names.includes(name), 'missing group '+name);
  }
}
for(let mask=0;mask<16;mask++) {
  const config = {'x-vpn-provider-override':true,...flags(mask),'proxy-groups':[{name:'PROXY',type:'select',proxies:['DIRECT']},{name:'AREA-COMBINE',type:'select',proxies:['DIRECT']}]};
  for(const key of ['x-pia-test','x-pia-test-slow','x-ss-test','x-ss-test-slow']) config[key]={'health-check':{enable:true,url:'https://example.com',interval:300}};
  const result = main(config);
  validate(result);
  const once = JSON.stringify(result);
  result['x-vpn-provider-override']=true;
  Object.assign(result,flags(mask));
  validate(main(result));
  assert.equal(JSON.stringify(result),once,'rerun must be stable');
  if(mask===15) console.log('All enabled:', result['proxy-groups'].length, 'unique groups;',Object.keys(result['proxy-providers']).length,'providers');
}
console.log('PASS: all 16 toggle combinations, references and repeat application');


assert.equal(VPN_LOCATION_LABELS['IN\\delhi'], '印度-德里');
assert.equal(VPN_LOCATION_LABELS['IN\\mumbai'], '印度-孟買');
assert.equal(VPN_LOCATION_LABELS['DE\\berlin'], '德國-柏林');
assert.equal(VPN_LOCATION_LABELS['DE\\frankfurt'], '德國-法蘭克福');
// WireGuard topology may be empty in source until provisioning. Exercise shared
// OV/WG paths plus a distinct city without changing generated production data.
const provisioned = vm.createContext({});
vm.runInContext(source.replace('const PIA_WG_PATHS = [];',
  'const PIA_WG_PATHS = ["DE\\\\berlin", "JP\\\\tokyo"];') +
  '\nglobalThis.api = {VENDOR_DEFS, renderVendor};', provisioned);
const vendor = provisioned.api.VENDOR_DEFS[0];
const rendered = provisioned.api.renderVendor(vendor, flags(3), {hot:{},cold:{}});
const berlin = rendered.endpointGroups.filter(g => g.name === '🇩🇪 PIA-DE(德國-柏林)');
assert.equal(berlin.length, 1);
assert.equal(berlin[0].use.length, 2);
assert.ok(rendered.endpointGroups.some(g => g.name === '🇯🇵 PIA-JP(日本-東京)'));
console.log('PASS: shared OV/WG path has one canonical group and both providers');

// Runtime policy must cover both OpenVPN vendors and leave WireGuard alone.
const policyContext = vm.createContext({});
vm.runInContext(source +
  '\nglobalThis.policy = {VENDOR_DEFS, renderVendor, openVpnOverride, HOT_COUNTRIES};', policyContext);
const api = policyContext.policy;
const policyCases = [];
for (const definition of api.VENDOR_DEFS) {
  const result = api.renderVendor(definition, flags(15), {hot:{interval:300},cold:{interval:1800}});
  for (const group of result.endpointGroups) {
    const location = definition.locations.find(l => l.name === group.name);
    assert.ok(location, group.name);
    assert.equal(group.type, location.hot ? 'fallback' : 'select', group.name);
  }
  for (const [name, provider] of Object.entries(result.providers)) {
    if (name.startsWith('ov-')) {
      assert.ok(Array.isArray(provider.override['override-expr']), name);
    } else {
      assert.equal(provider.override, undefined, name);
    }
  }
  for (const cc of ['TW', 'DE']) {
    const location = definition.locations.find(l => l.country === cc);
    const providerName = 'ov-' + definition.key.toLowerCase() + '-' + location.id;
    const expressions = result.providers[providerName].override['override-expr'];
    assert.equal(expressions.length, cc === 'TW' ? 3 : 1);
    assert.equal(expressions[0], 'del(.ping, .["ping-restart"])');
    for (const proto of ['udp', 'tcp']) {
      for (const legacy of [false, true]) {
        const mapping = {name:providerName + '-' + proto,type:'openvpn',proto};
        if (legacy) Object.assign(mapping, {ping:999,'ping-restart':999});
        policyCases.push({
          name:definition.key + '-' + cc + '-' + proto + '-' + (legacy ? 'legacy' : 'new'),
          expressions, mapping, hot:cc === 'TW' && proto === 'udp',
        });
      }
    }
  }
}
// Reclassification uses the same HOT_COUNTRIES as group/health-check policy.
api.HOT_COUNTRIES.delete('TW');
vm.runInContext('globalThis.changedLocation = makeLocation("TW", "SS");', policyContext);
assert.equal(api.openVpnOverride(policyContext.changedLocation)['override-expr'].length, 1);
if (process.env.VPN_POLICY_CASES) {
  fs.writeFileSync(process.env.VPN_POLICY_CASES, JSON.stringify(policyCases, null, 2));
}
console.log('PASS: both OpenVPN vendors share keepalive policy; WireGuard is unaffected');
