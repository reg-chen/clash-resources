// Clash Party JavaScript override
// v14: PIA / Surfshark folder-backed providers share one location renderer.
// Vendor differences live in declarative metadata; routing rules remain YAML.
// Clash Party's JS sandbox cannot access the local filesystem directly.
// Feature flags are therefore the source of truth. Stable generator-defined paths
// make missing provider files fail visibly in Mihomo.

const PROVIDER_ROOT = String.raw`P:\Clash\providers`;
const ICON_ROOT = 'https://cdn.jsdelivr.net/gh/reg-chen/clash-resources@main/icons';

const PIA_PATHS = [
  "TW", "PH", "SG", "MO", "HK", "CN", "JP", "KR", "MY", "ID", "VN", "IN", "KH", "MN", "NP", "BD", "LK", "AE",
  "QA", "SA", "IL", "TR", "EG", "NL\\netherlands", "DE\\berlin", "DE\\frankfurt", "UK\\london",
  "UK\\manchester", "UK\\southampton", "FR", "ES\\madrid", "ES\\valencia", "IT\\milano", "AM", "GE", "KZ", "AD",
  "AL", "AT", "BA", "BE", "BG", "CH", "CY", "CZ", "DK\\copenhagen", "EE", "FI\\helsinki", "GR", "HR", "HU",
  "IE", "IM", "IS", "LI", "LT", "LU", "LV", "MC", "MD", "ME", "MK", "MT", "NO", "PL", "PT", "RO", "RS",
  "SE\\stockholm", "SI", "SK", "UA", "US\\alabama", "US\\alaska", "US\\arkansas", "US\\atlanta",
  "US\\baltimore", "US\\california", "US\\chicago", "US\\connecticut", "US\\denver", "US\\east", "US\\florida",
  "US\\honolulu", "US\\houston", "US\\idaho", "US\\indiana", "US\\iowa", "US\\kansas", "US\\kentucky",
  "US\\las-vegas", "US\\louisiana", "US\\maine", "US\\massachusetts", "US\\michigan", "US\\minnesota",
  "US\\mississippi", "US\\missouri", "US\\montana", "US\\nebraska", "US\\new-hampshire", "US\\new-mexico",
  "US\\new-york", "US\\north-carolina", "US\\north-dakota", "US\\ohio", "US\\oklahoma", "US\\oregon",
  "US\\pennsylvania", "US\\rhode-island", "US\\salt-lake-city", "US\\seattle", "US\\silicon-valley",
  "US\\south-carolina", "US\\south-dakota", "US\\tennessee", "US\\texas", "US\\vermont", "US\\virginia",
  "US\\washington-dc", "US\\west", "US\\west-virginia", "US\\wilmington", "US\\wisconsin", "US\\wyoming",
  "CA\\montreal", "CA\\ontario", "CA\\toronto", "CA\\vancouver", "GL", "MX", "BR", "AR", "CL", "CO", "BO", "BS",
  "CR", "EC", "GT", "PA", "PE", "UY", "VE", "AU\\adelaide", "AU\\brisbane", "AU\\melbourne", "AU\\perth",
  "AU\\sydney", "NZ", "ZA", "NG", "MA", "DZ",
];

const COUNTRY_ZH = {
  "TW": "台灣",
  "PH": "菲律賓",
  "SG": "新加坡",
  "MO": "澳門",
  "HK": "香港",
  "CN": "中國",
  "JP": "日本",
  "KR": "韓國",
  "MY": "馬來西亞",
  "ID": "印尼",
  "VN": "越南",
  "IN": "印度",
  "KH": "柬埔寨",
  "MN": "蒙古",
  "NP": "尼泊爾",
  "BD": "孟加拉",
  "LK": "斯里蘭卡",
  "AE": "阿聯酋",
  "QA": "卡達",
  "SA": "沙烏地阿拉伯",
  "IL": "以色列",
  "TR": "土耳其",
  "EG": "埃及",
  "NL": "荷蘭",
  "DE": "德國",
  "UK": "英國",
  "FR": "法國",
  "ES": "西班牙",
  "IT": "義大利",
  "AM": "亞美尼亞",
  "GE": "喬治亞",
  "KZ": "哈薩克",
  "AD": "安道爾",
  "AL": "阿爾巴尼亞",
  "AT": "奧地利",
  "BA": "波士尼亞",
  "BE": "比利時",
  "BG": "保加利亞",
  "CH": "瑞士",
  "CY": "賽普勒斯",
  "CZ": "捷克",
  "DK": "丹麥",
  "EE": "愛沙尼亞",
  "FI": "芬蘭",
  "GR": "希臘",
  "HR": "克羅埃西亞",
  "HU": "匈牙利",
  "IE": "愛爾蘭",
  "IM": "曼島",
  "IS": "冰島",
  "LI": "列支敦斯登",
  "LT": "立陶宛",
  "LU": "盧森堡",
  "LV": "拉脫維亞",
  "MC": "摩納哥",
  "MD": "摩爾多瓦",
  "ME": "蒙特內哥羅",
  "MK": "北馬其頓",
  "MT": "馬爾他",
  "NO": "挪威",
  "PL": "波蘭",
  "PT": "葡萄牙",
  "RO": "羅馬尼亞",
  "RS": "塞爾維亞",
  "SE": "瑞典",
  "SI": "斯洛維尼亞",
  "SK": "斯洛伐克",
  "UA": "烏克蘭",
  "US": "美國",
  "CA": "加拿大",
  "GL": "格陵蘭",
  "MX": "墨西哥",
  "BR": "巴西",
  "AR": "阿根廷",
  "CL": "智利",
  "CO": "哥倫比亞",
  "BO": "玻利維亞",
  "BS": "巴哈馬",
  "CR": "哥斯大黎加",
  "EC": "厄瓜多",
  "GT": "瓜地馬拉",
  "PA": "巴拿馬",
  "PE": "秘魯",
  "UY": "烏拉圭",
  "VE": "委內瑞拉",
  "AU": "澳洲",
  "NZ": "紐西蘭",
  "ZA": "南非",
  "NG": "奈及利亞",
  "MA": "摩洛哥",
  "DZ": "阿爾及利亞",
  "AZ": "亞塞拜然",
  "BZ": "貝里斯",
  "BT": "不丹",
  "BN": "汶萊",
  "GH": "迦納",
  "LA": "寮國",
  "MM": "緬甸",
  "PK": "巴基斯坦",
  "PY": "巴拉圭",
  "PR": "波多黎各",
  "TH": "泰國",
  "UZ": "烏茲別克",
};

const PIA_LOCATION_ZH = {
  "DE\\berlin": "柏林",
  "DE\\frankfurt": "法蘭克福",
  "UK\\london": "倫敦",
  "UK\\manchester": "曼徹斯特",
  "UK\\southampton": "南安普敦",
  "ES\\madrid": "馬德里",
  "ES\\valencia": "瓦倫西亞",
  "IT\\milano": "米蘭",
  "DK\\copenhagen": "哥本哈根",
  "FI\\helsinki": "赫爾辛基",
  "SE\\stockholm": "斯德哥爾摩",
  "US\\alabama": "阿拉巴馬",
  "US\\alaska": "阿拉斯加",
  "US\\arkansas": "阿肯色",
  "US\\atlanta": "亞特蘭大",
  "US\\baltimore": "巴爾的摩",
  "US\\california": "加州",
  "US\\chicago": "芝加哥",
  "US\\connecticut": "康乃狄克",
  "US\\denver": "丹佛",
  "US\\east": "美東",
  "US\\florida": "佛羅里達",
  "US\\honolulu": "檀香山",
  "US\\houston": "休士頓",
  "US\\idaho": "愛達荷",
  "US\\indiana": "印第安納",
  "US\\iowa": "愛荷華",
  "US\\kansas": "堪薩斯",
  "US\\kentucky": "肯塔基",
  "US\\las-vegas": "拉斯維加斯",
  "US\\louisiana": "路易斯安那",
  "US\\maine": "緬因",
  "US\\massachusetts": "麻薩諸塞",
  "US\\michigan": "密西根",
  "US\\minnesota": "明尼蘇達",
  "US\\mississippi": "密西西比",
  "US\\missouri": "密蘇里",
  "US\\montana": "蒙大拿",
  "US\\nebraska": "內布拉斯加",
  "US\\new-hampshire": "新罕布夏",
  "US\\new-mexico": "新墨西哥",
  "US\\new-york": "紐約",
  "US\\north-carolina": "北卡羅來納",
  "US\\north-dakota": "北達科他",
  "US\\ohio": "俄亥俄",
  "US\\oklahoma": "奧克拉荷馬",
  "US\\oregon": "奧勒岡",
  "US\\pennsylvania": "賓夕法尼亞",
  "US\\rhode-island": "羅德島",
  "US\\salt-lake-city": "鹽湖城",
  "US\\seattle": "西雅圖",
  "US\\silicon-valley": "矽谷",
  "US\\south-carolina": "南卡羅來納",
  "US\\south-dakota": "南達科他",
  "US\\tennessee": "田納西",
  "US\\texas": "德州",
  "US\\vermont": "佛蒙特",
  "US\\virginia": "維吉尼亞",
  "US\\washington-dc": "華盛頓DC",
  "US\\west": "美西",
  "US\\west-virginia": "西維吉尼亞",
  "US\\wilmington": "威明頓",
  "US\\wisconsin": "威斯康辛",
  "US\\wyoming": "懷俄明",
  "CA\\montreal": "蒙特婁",
  "CA\\ontario": "安大略",
  "CA\\toronto": "多倫多",
  "CA\\vancouver": "溫哥華",
  "AU\\adelaide": "阿德雷德",
  "AU\\brisbane": "布里斯本",
  "AU\\melbourne": "墨爾本",
  "AU\\perth": "伯斯",
  "AU\\sydney": "雪梨",
};

const SURFSHARK_COUNTRIES = [
  "TW", "PH", "SG", "MO", "HK", "JP", "KR", "MY", "ID", "VN", "IN", "KH", "MN", "NP", "BD", "LK", "TH", "LA",
  "MM", "PK", "BN", "BT", "AZ", "UZ", "AE", "SA", "IL", "TR", "EG", "NL", "DE", "UK", "FR", "ES", "IT", "AM",
  "GE", "KZ", "AD", "AL", "AT", "BA", "BE", "BG", "CH", "CY", "CZ", "DK", "EE", "FI", "GR", "HR", "HU", "IE",
  "IM", "IS", "LI", "LT", "LU", "LV", "MC", "MD", "ME", "MK", "MT", "NO", "PL", "PT", "RO", "RS", "SE", "SI",
  "SK", "UA", "US", "CA", "GL", "MX", "BR", "AR", "CL", "CO", "BO", "BS", "BZ", "CR", "EC", "PA", "PE", "PR",
  "PY", "UY", "VE", "AU", "NZ", "ZA", "NG", "GH", "MA", "DZ",
];

const HLS = new Set(['TW', 'PH', 'SG']);
const CHINA = new Set(['MO', 'HK', 'CN']);
const ASIA_EXTRA = new Set([
  'JP', 'KR', 'MY', 'ID', 'TH', 'VN', 'IN', 'KH', 'LA', 'LK', 'MM', 'MN',
  'NP', 'PK', 'BD', 'BN', 'BT', 'AZ', 'UZ'
]);
const MIDDLE_EAST = new Set(['AE', 'QA', 'SA', 'IL', 'TR', 'EG']);
const EUROPE = new Set([
  'AD', 'AL', 'AM', 'AT', 'BA', 'BE', 'BG', 'CH', 'CY', 'CZ', 'DE', 'DK',
  'EE', 'ES', 'FI', 'FR', 'GE', 'GR', 'HR', 'HU', 'IE', 'IM', 'IS',
  'IT', 'KZ', 'LI', 'LT', 'LU', 'LV', 'MC', 'MD', 'ME', 'MK', 'MT', 'NL',
  'NO', 'PL', 'PT', 'RO', 'RS', 'SE', 'SI', 'SK', 'UA', 'UK'
]);
const NORTH_AMERICA = new Set(['US', 'CA', 'GL']);
const LATIN_AMERICA = new Set([
  'MX', 'BR', 'AR', 'CL', 'CO', 'BO', 'BS', 'BZ', 'CR', 'EC', 'GT', 'PA', 'PE',
  'PR', 'PY', 'UY', 'VE'
]);
const OCEANIA = new Set(['AU', 'NZ']);
const AFRICA = new Set(['ZA', 'NG', 'GH', 'MA', 'DZ']);
const ASIA = new Set([...HLS, ...CHINA, ...ASIA_EXTRA]);

const HOT_COUNTRY_ORDER = [
  'TW', 'PH', 'SG', 'MO', 'HK', 'CN', 'JP', 'KR', 'MY', 'ID', 'VN', 'IN',
  'KH', 'MN', 'NP', 'BD', 'LK'
];
const HOT_COUNTRIES = new Set(HOT_COUNTRY_ORDER);

const REGION_DEFS = [
  ['ASIA', ASIA, 'fluent-emoji-flat/japanese-castle.svg'],
  ['MIDDLE-EAST', MIDDLE_EAST, 'fluent-emoji-flat/mosque.svg'],
  ['EUROPE', EUROPE, 'fluent-emoji-flat/classical-building.svg'],
  ['NORTH-AMERICA', NORTH_AMERICA, 'fluent-emoji-flat/statue-of-liberty.svg'],
  ['LATIN-AMERICA', LATIN_AMERICA, 'fluent-emoji-flat/cactus.svg'],
  ['OCEANIA', OCEANIA, 'fluent-emoji-flat/bridge-at-night.svg'],
  ['AFRICA', AFRICA, 'fluent-emoji-flat/hut.svg'],
];

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function flagEmoji(alpha2) {
  return [...alpha2.toUpperCase()]
    .map((ch) => String.fromCodePoint(0x1F1E6 + ch.charCodeAt(0) - 65))
    .join('');
}

function locationFlagEmoji(alpha2) {
  return flagEmoji(alpha2.toUpperCase() === 'UK' ? 'GB' : alpha2);
}

function countryCode(location) {
  return location.country || location.path.split('\\')[0];
}

function locationId(path) {
  return path.toLowerCase().replaceAll('\\', '-');
}

function countryLabel(cc) {
  return COUNTRY_ZH[cc] || cc;
}

function makeLocation(path, vendor) {
  const cc = path.split('\\')[0];
  const suffix = PIA_LOCATION_ZH[path];
  const label = suffix ? `${countryLabel(cc)}-${suffix}` : countryLabel(cc);
  return {
    id: locationId(path),
    path,
    country: cc,
    name: `${locationFlagEmoji(cc)} ${vendor}-${cc}(${label})`,
    hot: HOT_COUNTRIES.has(cc),
  };
}

const PIA_ENDPOINTS = PIA_PATHS.map((path) => makeLocation(path, 'PIA'));
const SURFSHARK_LOCATIONS = SURFSHARK_COUNTRIES.map((cc) => makeLocation(cc, 'SS'));

function countCountries(locations) {
  return locations.reduce((counts, location) => {
    const cc = countryCode(location);
    counts[cc] = (counts[cc] || 0) + 1;
    return counts;
  }, {});
}

function locationPath(location, countryCounts) {
  const cc = countryCode(location);
  return countryCounts[cc] > 1 ? location.path : cc;
}

function appendUnique(target, values) {
  const seen = new Set(target);
  for (const value of values) {
    if (!seen.has(value)) {
      target.push(value);
      seen.add(value);
    }
  }
  return target;
}

function addUses(group, providerNames) {
  const current = Array.isArray(group.use) ? group.use : [];
  group.use = appendUnique(current, providerNames);
}

function addProxies(group, proxyNames) {
  const current = Array.isArray(group.proxies) ? group.proxies : [];
  group.proxies = appendUnique(current, proxyNames);
}

function makeProvider(path, healthCheck) {
  return { type: 'file', path, 'health-check': clone(healthCheck) };
}

function flagFilter(countries) {
  return Array.from(countries).sort().map(flagEmoji).join('|');
}

const VENDOR_DEFS = [
  {
    key: 'PIA',
    icon: 'PrivateInternetAccess.svg',
    locations: PIA_ENDPOINTS,
    health: { hot: 'x-pia-test', cold: 'x-pia-test-slow' },
    protocols: [
      { toggle: 'x-pia-wireguard', providerPrefix: 'wg-pia', filename: 'pia-wg.yaml' },
      { toggle: 'x-pia-openvpn', providerPrefix: 'ov-pia', filename: 'pia-ov.yaml' },
    ],
  },
  {
    key: 'SS',
    icon: 'Surfshark.svg',
    locations: SURFSHARK_LOCATIONS,
    health: { hot: 'x-ss-test', cold: 'x-ss-test-slow' },
    protocols: [
      { toggle: 'x-ss-openvpn', providerPrefix: 'ov-ss', filename: 'surfshark-ov.yaml' },
    ],
    aggregateProviders: [
      { toggle: 'x-ss-wireguard', bucket: 'hls', name: 'hls-wg-ss', filename: 'hls-wg-ss.yaml' },
      { toggle: 'x-ss-wireguard', bucket: 'china', name: 'china-wg-ss', filename: 'china-wg-ss.yaml' },
      { toggle: 'x-ss-wireguard', bucket: 'asiaExtra', name: 'asia-extra-wg-ss', filename: 'asia-extra-wg-ss.yaml' },
      { toggle: 'x-ss-wireguard', bucket: 'globalExtra', name: 'global-extra-wg-ss', filename: 'global-extra-wg-ss.yaml' },
    ],
  },
];

const MANAGED_TOGGLES = new Set(
  VENDOR_DEFS.flatMap((vendor) => [
    ...vendor.protocols.map((protocol) => protocol.toggle),
    ...(vendor.aggregateProviders || []).map((provider) => provider.toggle),
  ])
);

function readFeatureFlags(config) {
  const flags = {};
  for (const key of MANAGED_TOGGLES) {
    flags[key] = config[key] === true;
    delete config[key];
  }
  return flags;
}

function readHealthChecks(config, vendor) {
  const hot = config[vendor.health.hot]?.['health-check'];
  const cold = config[vendor.health.cold]?.['health-check'];
  if (!hot || !cold) {
    throw new Error(`VPN provider override requires ${vendor.health.hot} and ${vendor.health.cold}`);
  }
  return { hot, cold };
}

function renderVendor(vendor, flags, checks) {
  const providers = {};
  const endpointGroups = [];
  const activeLocations = [];
  const aggregateBuckets = {};
  const countryCounts = countCountries(vendor.locations);

  for (const location of vendor.locations) {
    const uses = [];
    const basePath = `${PROVIDER_ROOT}\\${locationPath(location, countryCounts)}`;
    const healthCheck = location.hot ? checks.hot : checks.cold;

    for (const protocol of vendor.protocols) {
      if (!flags[protocol.toggle]) continue;
      const providerName = `${protocol.providerPrefix}-${location.id}`;
      providers[providerName] = makeProvider(`${basePath}\\${protocol.filename}`, healthCheck);
      uses.push(providerName);
    }

    if (uses.length === 0) continue;
    activeLocations.push(location);
    endpointGroups.push({
      name: location.name,
      type: location.hot ? 'fallback' : 'select',
      hidden: true,
      use: uses,
    });
  }

  for (const aggregate of vendor.aggregateProviders || []) {
    if (!flags[aggregate.toggle]) continue;
    providers[aggregate.name] = makeProvider(`${PROVIDER_ROOT}\\${aggregate.filename}`, checks.hot);
    (aggregateBuckets[aggregate.bucket] ||= []).push(aggregate.name);
  }

  return { vendor, providers, endpointGroups, activeLocations, aggregateBuckets };
}

function locationNames(rendered, predicate = () => true) {
  return rendered.activeLocations.filter(predicate).map((location) => location.name);
}

function regionLocationNames(rendered, countries, predicate = () => true) {
  return locationNames(
    rendered,
    (location) => countries.has(countryCode(location)) && predicate(location)
  );
}

function bucket(rendered, name) {
  return rendered.aggregateBuckets[name] || [];
}

function isManagedVendorGroupName(name) {
  return typeof name === 'string' &&
    /^(?:PIA|SS)-(?:ALL|ASIA|MIDDLE-EAST|EUROPE|NORTH-AMERICA|LATIN-AMERICA|OCEANIA|AFRICA)$/i.test(name);
}

function isManagedProviderName(name) {
  if (typeof name !== 'string') return false;
  return /^(?:ov|wg)-(?:pia|ss)-/i.test(name) ||
    /^(?:hls|china|asia-extra|global-extra)-wg-ss$/i.test(name);
}

function isManagedEndpointName(name) {
  if (typeof name !== 'string') return false;
  return /\s(?:PIA|SS)-[A-Z]{2}(?:\(|$)/.test(name) ||
    /\sOV-(?:PIA|SS)-[A-Z]{2}(?:\(|$)/.test(name);
}

function cleanManagedRefs(group) {
  if (Array.isArray(group.use)) {
    group.use = group.use.filter((name) => !isManagedProviderName(name));
    if (group.use.length === 0) delete group.use;
  }
  if (Array.isArray(group.proxies)) {
    group.proxies = group.proxies.filter((name) =>
      !isManagedEndpointName(name) && !isManagedVendorGroupName(name)
    );
  }
}

function makeVendorGroup(name, icon, proxies = [], use = []) {
  const group = { name, type: 'select', icon };
  if (proxies.length > 0) group.proxies = proxies;
  if (use.length > 0) group.use = use;
  return group;
}

function buildPiaVendorGroups(rendered) {
  if (rendered.activeLocations.length === 0) return [];

  const groups = [
    makeVendorGroup('PIA-ALL', `${ICON_ROOT}/${rendered.vendor.icon}`, locationNames(rendered)),
  ];
  for (const [regionName, countries, icon] of REGION_DEFS) {
    const proxies = regionLocationNames(rendered, countries);
    if (proxies.length === 0) continue;
    groups.push(makeVendorGroup(`PIA-${regionName}`, `${ICON_ROOT}/${icon}`, proxies));
  }
  return groups;
}

function buildSurfsharkVendorGroups(rendered) {
  const wgAsia = [...bucket(rendered, 'hls'), ...bucket(rendered, 'china'), ...bucket(rendered, 'asiaExtra')];
  const wgAll = [...wgAsia, ...bucket(rendered, 'globalExtra')];
  if (rendered.activeLocations.length === 0 && wgAll.length === 0) return [];

  const groups = [
    makeVendorGroup('SS-ALL', `${ICON_ROOT}/${rendered.vendor.icon}`, locationNames(rendered), wgAll),
  ];

  const asiaGroup = makeVendorGroup(
    'SS-ASIA',
    `${ICON_ROOT}/fluent-emoji-flat/japanese-castle.svg`,
    regionLocationNames(rendered, ASIA, (location) => location.hot),
    wgAsia
  );
  if (asiaGroup.proxies || asiaGroup.use) groups.push(asiaGroup);

  for (const [regionName, countries, icon] of REGION_DEFS) {
    if (regionName === 'ASIA') continue;
    const group = makeVendorGroup(
      `SS-${regionName}`,
      `${ICON_ROOT}/${icon}`,
      regionLocationNames(rendered, countries)
    );
    if (bucket(rendered, 'globalExtra').length > 0) {
      group.use = [...bucket(rendered, 'globalExtra')];
      group.filter = flagFilter(countries);
    }
    if (group.proxies || group.use) groups.push(group);
  }
  return groups;
}

function applyAutomationPolicy(baseGroups, pia, ss) {
  const piaAsia = locationNames(pia, (location) => location.hot);
  const piaHls = regionLocationNames(pia, HLS);
  const piaAi = locationNames(pia, (location) => location.hot && !CHINA.has(countryCode(location)));

  const ssAsia = regionLocationNames(ss, ASIA, (location) => location.hot);
  const ssHls = regionLocationNames(ss, HLS, (location) => location.hot);
  const ssAi = regionLocationNames(
    ss,
    ASIA,
    (location) => location.hot && !CHINA.has(countryCode(location))
  );

  const ssWgAsia = [...bucket(ss, 'hls'), ...bucket(ss, 'china'), ...bucket(ss, 'asiaExtra')];
  const ssWgAi = [...bucket(ss, 'hls'), ...bucket(ss, 'asiaExtra')];

  const asiaProxies = [...piaAsia, ...ssAsia];
  const hlsProxies = [...piaHls, ...ssHls];
  const aiProxies = [...piaAi, ...ssAi];

  const policyByGroup = {
    'AUTO-FAST': { proxies: asiaProxies, use: ssWgAsia },
    'AUTO-SAFE': { proxies: asiaProxies, use: ssWgAsia },
    'LB-HLS': { proxies: hlsProxies, use: bucket(ss, 'hls') },
    'LB-STICKY': { proxies: asiaProxies, use: ssWgAsia },
    'LB-ROBIN': { proxies: asiaProxies, use: ssWgAsia },
    'LB-CONSISTENT': { proxies: asiaProxies, use: ssWgAsia },
    'AI-PROXY': { proxies: aiProxies, use: ssWgAi },
  };

  for (const group of baseGroups) {
    const policy = policyByGroup[group?.name];
    if (!policy) continue;

    delete group.filter;
    delete group['exclude-filter'];
    if (policy.proxies.length > 0) addProxies(group, policy.proxies);
    if (policy.use.length > 0) addUses(group, policy.use);

    const hasDynamicSource = policy.proxies.length > 0 || policy.use.length > 0;
    if (hasDynamicSource && Array.isArray(group.proxies)) {
      group.proxies = group.proxies.filter((name) => name !== 'REJECT');
      if (group.proxies.length === 0) delete group.proxies;
    }

    const hasSource =
      (Array.isArray(group.proxies) && group.proxies.length > 0) ||
      (Array.isArray(group.use) && group.use.length > 0);
    if (!hasSource) group.proxies = ['REJECT'];
  }
}

function applyRouteGroupPolicy(baseGroups, vendorGroups) {
  const activeVendorGroupNames = new Set(vendorGroups.map((group) => group.name));
  const policyByGroup = {
    'PROXY': [
      'SS-ALL', 'SS-ASIA', 'SS-MIDDLE-EAST', 'SS-EUROPE', 'SS-NORTH-AMERICA',
      'SS-LATIN-AMERICA', 'SS-OCEANIA', 'SS-AFRICA',
      'PIA-ALL', 'PIA-ASIA', 'PIA-MIDDLE-EAST', 'PIA-EUROPE', 'PIA-NORTH-AMERICA',
      'PIA-LATIN-AMERICA', 'PIA-OCEANIA', 'PIA-AFRICA',
    ],
    'HLS-PROXY': ['SS-ALL', 'PIA-ASIA'],
    'DRM-PROXY': ['SS-ALL', 'PIA-ASIA'],
    'BANKGOV-PROXY': ['SS-ALL', 'PIA-ASIA'],
  };

  for (const group of baseGroups) {
    const candidates = policyByGroup[group?.name];
    if (!candidates) continue;
    addProxies(group, candidates.filter((name) => activeVendorGroupNames.has(name)));
  }
}

function main(config) {
  if (!config || typeof config !== 'object') return config;
  if (config['x-vpn-provider-override'] !== true) return config;
  delete config['x-vpn-provider-override'];

  const flags = readFeatureFlags(config);
  const renderedByVendor = Object.fromEntries(
    VENDOR_DEFS.map((vendor) => [
      vendor.key,
      renderVendor(vendor, flags, readHealthChecks(config, vendor)),
    ])
  );
  const pia = renderedByVendor.PIA;
  const ss = renderedByVendor.SS;

  const existingProviders =
    config['proxy-providers'] && typeof config['proxy-providers'] === 'object'
      ? config['proxy-providers']
      : {};
  const baseProviders = Object.fromEntries(
    Object.entries(existingProviders).filter(([name]) => !isManagedProviderName(name))
  );
  config['proxy-providers'] = { ...pia.providers, ...ss.providers, ...baseProviders };

  const existingGroups = Array.isArray(config['proxy-groups']) ? config['proxy-groups'] : [];
  const baseGroups = existingGroups.filter((group) =>
    !(group?.hidden === true && isManagedEndpointName(group?.name)) &&
    !isManagedVendorGroupName(group?.name)
  );
  for (const group of baseGroups) {
    if (group && typeof group === 'object') cleanManagedRefs(group);
  }

  applyAutomationPolicy(baseGroups, pia, ss);
  const vendorGroups = [...buildPiaVendorGroups(pia), ...buildSurfsharkVendorGroups(ss)];
  applyRouteGroupPolicy(baseGroups, vendorGroups);

  config['proxy-groups'] = [
    ...pia.endpointGroups,
    ...ss.endpointGroups,
    ...baseGroups,
    ...vendorGroups,
  ];
  return config;
}