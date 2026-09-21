// Clash Party JavaScript override
// v20: runtime policy consumes generator-owned topology and presentation metadata.
// Generators canonicalize provider source names into shared location paths;
// this override only renders policy from those generated paths.

const PROVIDER_ROOT = String.raw`P:\Clash\providers`;
const ICON_ROOT = 'https://cdn.jsdelivr.net/gh/reg-chen/clash-resources@main/icons';

// BEGIN GENERATED PIA OPENVPN PATHS
// AUTO-GENERATED from the current PIA OpenVPN bundles.
// Do not edit this block by hand; regenerate it with tools/pia-openvpn-generator.py.
const PIA_OV_PATHS = [
  "TW", "PH", "SG", "MO", "HK", "CN",
  "JP", "KR", "MY", "ID", "VN", "IN",
  "KH", "MN", "NP", "BD", "LK", "AE",
  "QA", "SA", "IL", "TR", "EG", "NL",
  "DE\\berlin", "DE\\frankfurt", "UK\\london", "UK\\manchester", "UK\\southampton", "FR",
  "ES\\madrid", "ES\\valencia", "IT", "AM", "GE", "KZ",
  "AD", "AL", "AT", "BA", "BE", "BG",
  "CH", "CY", "CZ", "DK", "EE", "FI",
  "GR", "HR", "HU", "IE", "IM", "IS",
  "LI", "LT", "LU", "LV", "MC", "MD",
  "ME", "MK", "MT", "NO", "PL", "PT",
  "RO", "RS", "SE", "SI", "SK", "UA",
  "US\\alabama", "US\\alaska", "US\\arkansas", "US\\atlanta", "US\\baltimore", "US\\california",
  "US\\chicago", "US\\connecticut", "US\\denver", "US\\east", "US\\florida", "US\\honolulu",
  "US\\houston", "US\\idaho", "US\\indiana", "US\\iowa", "US\\kansas", "US\\kentucky",
  "US\\las-vegas", "US\\louisiana", "US\\maine", "US\\massachusetts", "US\\michigan", "US\\minnesota",
  "US\\mississippi", "US\\missouri", "US\\montana", "US\\nebraska", "US\\new-hampshire", "US\\new-mexico",
  "US\\new-york", "US\\north-carolina", "US\\north-dakota", "US\\ohio", "US\\oklahoma", "US\\oregon",
  "US\\pennsylvania", "US\\rhode-island", "US\\salt-lake-city", "US\\seattle", "US\\silicon-valley", "US\\south-carolina",
  "US\\south-dakota", "US\\tennessee", "US\\texas", "US\\vermont", "US\\virginia", "US\\washington-dc",
  "US\\west", "US\\west-virginia", "US\\wilmington", "US\\wisconsin", "US\\wyoming", "CA\\montreal",
  "CA\\ontario", "CA\\toronto", "CA\\vancouver", "GL", "MX", "BR",
  "AR", "CL", "CO", "BO", "BS", "CR",
  "EC", "GT", "PA", "PE", "UY", "VE",
  "AU\\adelaide", "AU\\brisbane", "AU\\melbourne", "AU\\perth", "AU\\sydney", "NZ",
  "ZA", "NG", "MA", "DZ",
];
// END GENERATED PIA OPENVPN PATHS

// BEGIN GENERATED PIA WIREGUARD PATHS
// AUTO-GENERATED from the successfully provisioned PIA WireGuard regions.
// Do not edit this block by hand; regenerate it with tools/pia-wireguard-generator.py.
const PIA_WG_PATHS = [];
// END GENERATED PIA WIREGUARD PATHS

// BEGIN GENERATED VPN LOCATION LABELS
// AUTO-GENERATED from the shared VPN generator location catalog.
// Do not edit this block by hand; regenerate it with the VPN generators.
const VPN_LOCATION_LABELS = {
  "AD": "安道爾",
  "AE": "阿聯酋",
  "AL": "阿爾巴尼亞",
  "AM": "亞美尼亞",
  "AR": "阿根廷",
  "AT": "奧地利",
  "AU": "澳洲",
  "AU\\adelaide": "澳洲-阿德雷德",
  "AU\\brisbane": "澳洲-布里斯本",
  "AU\\melbourne": "澳洲-墨爾本",
  "AU\\perth": "澳洲-伯斯",
  "AU\\sydney": "澳洲-雪梨",
  "AZ": "亞塞拜然",
  "BA": "波士尼亞",
  "BD": "孟加拉",
  "BE": "比利時",
  "BE\\antwerp": "比利時-安特衛普",
  "BE\\brussels": "比利時-布魯塞爾",
  "BG": "保加利亞",
  "BN": "汶萊",
  "BO": "玻利維亞",
  "BR": "巴西",
  "BS": "巴哈馬",
  "BT": "不丹",
  "BZ": "貝里斯",
  "CA": "加拿大",
  "CA\\montreal": "加拿大-蒙特婁",
  "CA\\ontario": "加拿大-安大略",
  "CA\\toronto": "加拿大-多倫多",
  "CA\\vancouver": "加拿大-溫哥華",
  "CH": "瑞士",
  "CL": "智利",
  "CN": "中國",
  "CO": "哥倫比亞",
  "CR": "哥斯大黎加",
  "CY": "賽普勒斯",
  "CZ": "捷克",
  "DE": "德國",
  "DE\\berlin": "德國-柏林",
  "DE\\frankfurt": "德國-法蘭克福",
  "DK": "丹麥",
  "DK\\copenhagen": "丹麥-哥本哈根",
  "DZ": "阿爾及利亞",
  "EC": "厄瓜多",
  "EE": "愛沙尼亞",
  "EG": "埃及",
  "ES": "西班牙",
  "ES\\barcelona": "西班牙-巴塞隆納",
  "ES\\madrid": "西班牙-馬德里",
  "ES\\valencia": "西班牙-瓦倫西亞",
  "FI": "芬蘭",
  "FI\\helsinki": "芬蘭-赫爾辛基",
  "FR": "法國",
  "FR\\bordeaux": "法國-波爾多",
  "FR\\marseille": "法國-馬賽",
  "FR\\paris": "法國-巴黎",
  "GE": "喬治亞",
  "GH": "迦納",
  "GL": "格陵蘭",
  "GR": "希臘",
  "GT": "瓜地馬拉",
  "HK": "香港",
  "HR": "克羅埃西亞",
  "HU": "匈牙利",
  "ID": "印尼",
  "IE": "愛爾蘭",
  "IL": "以色列",
  "IM": "曼島",
  "IN": "印度",
  "IN\\delhi": "印度-德里",
  "IN\\mumbai": "印度-孟買",
  "IS": "冰島",
  "IT": "義大利",
  "IT\\milan": "義大利-米蘭",
  "IT\\rome": "義大利-羅馬",
  "JP": "日本",
  "JP\\tokyo": "日本-東京",
  "KH": "柬埔寨",
  "KR": "韓國",
  "KZ": "哈薩克",
  "LA": "寮國",
  "LI": "列支敦斯登",
  "LK": "斯里蘭卡",
  "LT": "立陶宛",
  "LU": "盧森堡",
  "LV": "拉脫維亞",
  "MA": "摩洛哥",
  "MC": "摩納哥",
  "MD": "摩爾多瓦",
  "ME": "蒙特內哥羅",
  "MK": "北馬其頓",
  "MM": "緬甸",
  "MN": "蒙古",
  "MO": "澳門",
  "MT": "馬爾他",
  "MX": "墨西哥",
  "MY": "馬來西亞",
  "NG": "奈及利亞",
  "NL": "荷蘭",
  "NO": "挪威",
  "NP": "尼泊爾",
  "NZ": "紐西蘭",
  "PA": "巴拿馬",
  "PE": "秘魯",
  "PH": "菲律賓",
  "PK": "巴基斯坦",
  "PL": "波蘭",
  "PL\\gdansk": "波蘭-格但斯克",
  "PL\\warsaw": "波蘭-華沙",
  "PR": "波多黎各",
  "PT": "葡萄牙",
  "PT\\lisbon": "葡萄牙-里斯本",
  "PT\\porto": "葡萄牙-波多",
  "PY": "巴拉圭",
  "QA": "卡達",
  "RO": "羅馬尼亞",
  "RS": "塞爾維亞",
  "SA": "沙烏地阿拉伯",
  "SE": "瑞典",
  "SE\\stockholm": "瑞典-斯德哥爾摩",
  "SG": "新加坡",
  "SI": "斯洛維尼亞",
  "SK": "斯洛伐克",
  "TH": "泰國",
  "TR": "土耳其",
  "TW": "台灣",
  "UA": "烏克蘭",
  "UK": "英國",
  "UK\\edinburgh": "英國-愛丁堡",
  "UK\\glasgow": "英國-格拉斯哥",
  "UK\\london": "英國-倫敦",
  "UK\\manchester": "英國-曼徹斯特",
  "UK\\southampton": "英國-南安普敦",
  "US": "美國",
  "US\\alabama": "美國-阿拉巴馬",
  "US\\alaska": "美國-阿拉斯加",
  "US\\arkansas": "美國-阿肯色",
  "US\\ashburn": "美國-阿什本",
  "US\\atlanta": "美國-亞特蘭大",
  "US\\baltimore": "美國-巴爾的摩",
  "US\\bend": "美國-本德",
  "US\\boston": "美國-波士頓",
  "US\\buffalo": "美國-水牛城",
  "US\\california": "美國-加州",
  "US\\charlotte": "美國-夏洛特",
  "US\\chicago": "美國-芝加哥",
  "US\\connecticut": "美國-康乃狄克",
  "US\\dallas": "美國-達拉斯",
  "US\\denver": "美國-丹佛",
  "US\\detroit": "美國-底特律",
  "US\\east": "美國-美東",
  "US\\florida": "美國-佛羅里達",
  "US\\honolulu": "美國-檀香山",
  "US\\houston": "美國-休士頓",
  "US\\idaho": "美國-愛達荷",
  "US\\indiana": "美國-印第安納",
  "US\\iowa": "美國-愛荷華",
  "US\\kansas": "美國-堪薩斯",
  "US\\kansas-city": "美國-堪薩斯城",
  "US\\kentucky": "美國-肯塔基",
  "US\\las-vegas": "美國-拉斯維加斯",
  "US\\latham": "美國-拉瑟姆",
  "US\\los-angeles": "美國-洛杉磯",
  "US\\louisiana": "美國-路易斯安那",
  "US\\maine": "美國-緬因",
  "US\\massachusetts": "美國-麻薩諸塞",
  "US\\miami": "美國-邁阿密",
  "US\\michigan": "美國-密西根",
  "US\\minnesota": "美國-明尼蘇達",
  "US\\mississippi": "美國-密西西比",
  "US\\missouri": "美國-密蘇里",
  "US\\montana": "美國-蒙大拿",
  "US\\nashville": "美國-納什維爾",
  "US\\nebraska": "美國-內布拉斯加",
  "US\\new-hampshire": "美國-新罕布夏",
  "US\\new-mexico": "美國-新墨西哥",
  "US\\new-york": "美國-紐約",
  "US\\north-carolina": "美國-北卡羅來納",
  "US\\north-dakota": "美國-北達科他",
  "US\\ohio": "美國-俄亥俄",
  "US\\oklahoma": "美國-奧克拉荷馬",
  "US\\omaha": "美國-奧馬哈",
  "US\\oregon": "美國-奧勒岡",
  "US\\pennsylvania": "美國-賓夕法尼亞",
  "US\\phoenix": "美國-鳳凰城",
  "US\\rhode-island": "美國-羅德島",
  "US\\salt-lake-city": "美國-鹽湖城",
  "US\\san-francisco": "美國-舊金山",
  "US\\san-jose": "美國-聖荷西",
  "US\\seattle": "美國-西雅圖",
  "US\\silicon-valley": "美國-矽谷",
  "US\\south-carolina": "美國-南卡羅來納",
  "US\\south-dakota": "美國-南達科他",
  "US\\tennessee": "美國-田納西",
  "US\\texas": "美國-德州",
  "US\\vermont": "美國-佛蒙特",
  "US\\virginia": "美國-維吉尼亞",
  "US\\washington-dc": "美國-華盛頓DC",
  "US\\west": "美國-美西",
  "US\\west-virginia": "美國-西維吉尼亞",
  "US\\wilmington": "美國-威明頓",
  "US\\wisconsin": "美國-威斯康辛",
  "US\\wyoming": "美國-懷俄明",
  "UY": "烏拉圭",
  "UZ": "烏茲別克",
  "VE": "委內瑞拉",
  "VN": "越南",
  "ZA": "南非"
};
// END GENERATED VPN LOCATION LABELS

// Shared presentation policy only; this never controls provider topology.
const COUNTRY_DISPLAY_ORDER = [
  'TW','PH','SG','MO','HK','CN','JP','KR','MY','ID','VN','IN','KH','MN','NP','BD','LK','TH','LA','MM','PK','BN','BT','AZ','UZ',
  'AE','SA','IL','TR','EG','NL','DE','UK','FR','ES','IT','AM','GE','KZ','AD','AL','AT','BA','BE','BG','CH','CY','CZ','DK',
  'EE','FI','GR','HR','HU','IE','IM','IS','LI','LT','LU','LV','MC','MD','ME','MK','MT','NO','PL','PT','RO','RS','SE','SI','SK','UA',
  'US','CA','GL','MX','BR','AR','CL','CO','BO','BS','BZ','CR','EC','PA','PE','PR','PY','UY','VE','AU','NZ','ZA','NG','GH','MA','DZ',
];

// BEGIN GENERATED SURFSHARK OPENVPN PATHS
// AUTO-GENERATED from the official Surfshark OpenVPN bundle.
// Do not edit this block by hand; regenerate it with tools/surfshark-openvpn-generator.py.
const SURFSHARK_OV_PATHS = [
  "TW", "PH", "SG", "MO", "HK", "JP",
  "KR", "MY", "ID", "VN", "IN\\delhi", "IN\\mumbai",
  "KH", "MN", "NP", "BD", "LK", "TH",
  "LA", "MM", "PK", "BN", "BT", "AZ",
  "UZ", "AE", "SA", "IL", "TR", "EG",
  "NL", "DE\\berlin", "DE\\frankfurt", "UK\\edinburgh", "UK\\glasgow", "UK\\london",
  "UK\\manchester", "FR\\bordeaux", "FR\\marseille", "FR\\paris", "ES\\barcelona", "ES\\madrid",
  "ES\\valencia", "IT\\milan", "IT\\rome", "AM", "GE", "KZ",
  "AD", "AL", "AT", "BA", "BE\\antwerp", "BE\\brussels",
  "BG", "CH", "CY", "CZ", "DK", "EE",
  "FI", "GR", "HR", "HU", "IE", "IM",
  "IS", "LI", "LT", "LU", "LV", "MC",
  "MD", "ME", "MK", "MT", "NO", "PL\\gdansk",
  "PL\\warsaw", "PT\\lisbon", "PT\\porto", "RO", "RS", "SE",
  "SI", "SK", "UA", "US\\ashburn", "US\\atlanta", "US\\nashville",
  "US\\boston", "US\\buffalo", "US\\chicago", "US\\charlotte", "US\\dallas", "US\\denver",
  "US\\detroit", "US\\houston", "US\\kansas-city", "US\\las-vegas", "US\\los-angeles", "US\\miami",
  "US\\new-york", "US\\omaha", "US\\phoenix", "US\\seattle", "US\\san-francisco", "US\\san-jose",
  "US\\salt-lake-city", "US\\bend", "US\\latham", "CA\\montreal", "CA\\toronto", "CA\\vancouver",
  "GL", "MX", "BR", "AR", "CL", "CO",
  "BO", "BS", "BZ", "CR", "EC", "PA",
  "PE", "PR", "PY", "UY", "VE", "AU\\adelaide",
  "AU\\brisbane", "AU\\melbourne", "AU\\perth", "AU\\sydney", "NZ", "ZA",
  "NG", "GH", "MA", "DZ",
];
// END GENERATED SURFSHARK OPENVPN PATHS

const HLS = new Set(['TW', 'PH', 'SG']);
const CHINA = new Set(['MO', 'HK', 'CN']);
const ASIA_EXTRA = new Set(['JP','KR','MY','ID','TH','VN','IN','KH','LA','LK','MM','MN','NP','PK','BD','BN','BT','AZ','UZ']);
const MIDDLE_EAST = new Set(['AE','QA','SA','IL','TR','EG']);
const EUROPE = new Set(['AD','AL','AM','AT','BA','BE','BG','CH','CY','CZ','DE','DK','EE','ES','FI','FR','GE','GR','HR','HU','IE','IM','IS','IT','KZ','LI','LT','LU','LV','MC','MD','ME','MK','MT','NL','NO','PL','PT','RO','RS','SE','SI','SK','UA','UK']);
const NORTH_AMERICA = new Set(['US','CA','GL']);
const LATIN_AMERICA = new Set(['MX','BR','AR','CL','CO','BO','BS','BZ','CR','EC','GT','PA','PE','PR','PY','UY','VE']);
const OCEANIA = new Set(['AU','NZ']);
const AFRICA = new Set(['ZA','NG','GH','MA','DZ']);
const ASIA = new Set([...HLS, ...CHINA, ...ASIA_EXTRA]);
const HOT_COUNTRIES = new Set(ASIA);
const OPENVPN_HOT_KEEPALIVE = { ping: 20, pingRestart: 60 };

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

function makeLocation(path, vendor) {
  const cc = path.split('\\')[0];
  const label = VPN_LOCATION_LABELS[path] || VPN_LOCATION_LABELS[cc] || cc;
  return {
    id: locationId(path),
    path,
    country: cc,
    name: `${locationFlagEmoji(cc)} ${vendor}-${cc}(${label})`,
    hot: HOT_COUNTRIES.has(cc),
  };
}

function sortPathsByCountryOrder(source, countryOrder) {
  const rank = new Map(countryOrder.map((cc, index) => [cc, index]));
  return [...source].sort((a, b) => {
    const acc = a.split('\\')[0];
    const bcc = b.split('\\')[0];
    const ar = rank.get(acc) ?? Number.MAX_SAFE_INTEGER;
    const br = rank.get(bcc) ?? Number.MAX_SAFE_INTEGER;
    return ar - br || acc.localeCompare(bcc) || a.localeCompare(b);
  });
}

function orderedUnion(...lists) {
  const result = [];
  const seen = new Set();
  for (const list of lists) {
    for (const value of list) {
      if (!seen.has(value)) {
        seen.add(value);
        result.push(value);
      }
    }
  }
  return result;
}

function buildLocations(vendor, ...pathLists) {
  return sortPathsByCountryOrder(
    orderedUnion(...pathLists),
    COUNTRY_DISPLAY_ORDER
  ).map((path) => makeLocation(path, vendor));
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
  group.use = appendUnique(Array.isArray(group.use) ? group.use : [], providerNames);
}

function addProxies(group, proxyNames) {
  group.proxies = appendUnique(Array.isArray(group.proxies) ? group.proxies : [], proxyNames);
}

function makeProvider(path, healthCheck) {
  return { type: 'file', path, 'health-check': clone(healthCheck) };
}

// Requires Mihomo provider override-expr support. Clear old generated values
// first so changing HOT_COUNTRIES also updates already-generated payloads.
function openVpnOverride(location) {
  const expressions = ['del(.ping, .["ping-restart"])'];
  if (location.hot) {
    expressions.push(
      `(select(.proto == "udp") | .ping) = ${OPENVPN_HOT_KEEPALIVE.ping}`,
      `(select(.proto == "udp") | .["ping-restart"]) = ${OPENVPN_HOT_KEEPALIVE.pingRestart}`
    );
  }
  return { 'override-expr': expressions };
}

function flagFilter(countries) {
  return Array.from(countries).sort().map(locationFlagEmoji).join('|');
}

const VENDOR_DEFS = [
  {
    key: 'PIA',
    icon: 'PrivateInternetAccess.svg',
    locations: buildLocations('PIA', PIA_OV_PATHS, PIA_WG_PATHS),
    health: { hot: 'x-pia-test', cold: 'x-pia-test-slow' },
    protocols: [
      { toggle: 'x-pia-wireguard', type: 'wireguard', providerPrefix: 'wg-pia', filename: 'pia-wg.yaml', paths: new Set(PIA_WG_PATHS) },
      { toggle: 'x-pia-openvpn', type: 'openvpn', providerPrefix: 'ov-pia', filename: 'pia-ov.yaml', paths: new Set(PIA_OV_PATHS) },
    ],
  },
  {
    key: 'SS',
    icon: 'Surfshark.svg',
    locations: buildLocations('SS', SURFSHARK_OV_PATHS),
    health: { hot: 'x-ss-test', cold: 'x-ss-test-slow' },
    protocols: [
      { toggle: 'x-ss-openvpn', type: 'openvpn', providerPrefix: 'ov-ss', filename: 'surfshark-ov.yaml', paths: new Set(SURFSHARK_OV_PATHS) },
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

  for (const location of vendor.locations) {
    const uses = [];
    const healthCheck = location.hot ? checks.hot : checks.cold;

    for (const protocol of vendor.protocols) {
      if (!flags[protocol.toggle] || !protocol.paths.has(location.path)) continue;
      const providerName = `${protocol.providerPrefix}-${location.id}`;
      const provider = makeProvider(
        `${PROVIDER_ROOT}\\${location.path}\\${protocol.filename}`,
        healthCheck
      );
      if (protocol.type === 'openvpn') {
        provider.override = openVpnOverride(location);
      }
      providers[providerName] = provider;
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
  return locationNames(rendered, (location) => countries.has(countryCode(location)) && predicate(location));
}

function countryLocationNames(rendered, cc) {
  return locationNames(rendered, (location) => location.hot && countryCode(location) === cc);
}

function bucket(rendered, name) {
  return rendered.aggregateBuckets[name] || [];
}

function isManagedVendorGroupName(name) {
  return typeof name === 'string' && /^(?:PIA|SS)-(?:ALL|ASIA|MIDDLE-EAST|EUROPE|NORTH-AMERICA|LATIN-AMERICA|OCEANIA|AFRICA)$/i.test(name);
}

function areaGroupName(cc) {
  return `${locationFlagEmoji(cc)} AREA-${cc}(${VPN_LOCATION_LABELS[cc] || cc})`;
}

function isManagedAreaGroupName(name) {
  if (typeof name !== 'string') return false;
  const match = name.match(/AREA-([A-Z]{2})(?:\([^)]*\))?$/);
  if (!match) return false;
  const cc = match[1];
  return name === `AREA-${cc}` ||
    name === `${locationFlagEmoji(cc)} AREA-${cc}` ||
    name === areaGroupName(cc);
}

function isManagedProviderName(name) {
  return typeof name === 'string' && (
    /^(?:ov|wg)-(?:pia|ss)-/i.test(name) || /^(?:hls|china|asia-extra|global-extra)-wg-ss$/i.test(name)
  );
}

function isManagedEndpointName(name) {
  return typeof name === 'string' && (
    /\s(?:PIA|SS)-[A-Z]{2}(?:\(|$)/.test(name) || /\sOV-(?:PIA|SS)-[A-Z]{2}(?:\(|$)/.test(name)
  );
}

function cleanManagedRefs(group) {
  if (Array.isArray(group.use)) {
    group.use = group.use.filter((name) => !isManagedProviderName(name));
    if (group.use.length === 0) delete group.use;
  }
  if (Array.isArray(group.proxies)) {
    group.proxies = group.proxies.filter((name) =>
      !isManagedEndpointName(name) && !isManagedVendorGroupName(name) && !isManagedAreaGroupName(name)
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
  const groups = [makeVendorGroup('PIA-ALL', `${ICON_ROOT}/${rendered.vendor.icon}`, locationNames(rendered))];
  for (const [regionName, countries, icon] of REGION_DEFS) {
    const proxies = regionLocationNames(rendered, countries);
    if (proxies.length > 0) groups.push(makeVendorGroup(`PIA-${regionName}`, `${ICON_ROOT}/${icon}`, proxies));
  }
  return groups;
}

function buildSurfsharkVendorGroups(rendered) {
  const wgAsia = [...bucket(rendered, 'hls'), ...bucket(rendered, 'china'), ...bucket(rendered, 'asiaExtra')];
  const wgAll = [...wgAsia, ...bucket(rendered, 'globalExtra')];
  if (rendered.activeLocations.length === 0 && wgAll.length === 0) return [];

  const groups = [makeVendorGroup('SS-ALL', `${ICON_ROOT}/${rendered.vendor.icon}`, locationNames(rendered), wgAll)];
  const asiaGroup = makeVendorGroup(
    'SS-ASIA',
    `${ICON_ROOT}/fluent-emoji-flat/japanese-castle.svg`,
    regionLocationNames(rendered, ASIA, (location) => location.hot),
    wgAsia
  );
  if (asiaGroup.proxies || asiaGroup.use) groups.push(asiaGroup);

  for (const [regionName, countries, icon] of REGION_DEFS) {
    if (regionName === 'ASIA') continue;
    const group = makeVendorGroup(`SS-${regionName}`, `${ICON_ROOT}/${icon}`, regionLocationNames(rendered, countries));
    if (bucket(rendered, 'globalExtra').length > 0) {
      group.use = [...bucket(rendered, 'globalExtra')];
      group.filter = flagFilter(countries);
    }
    if (group.proxies || group.use) groups.push(group);
  }
  return groups;
}

function buildAreaGroups(pia, ss, checksByVendor) {
  const piaCountries = new Set(
    pia.activeLocations
      .filter((location) => location.hot && ASIA.has(countryCode(location)))
      .map(countryCode)
  );
  const ssCountries = new Set(
    ss.activeLocations
      .filter((location) => location.hot && ASIA.has(countryCode(location)))
      .map(countryCode)
  );
  const commonCountries = COUNTRY_DISPLAY_ORDER.filter((cc) =>
    ASIA.has(cc) && piaCountries.has(cc) && ssCountries.has(cc)
  );

  const hotChecks = [checksByVendor.PIA.hot, checksByVendor.SS.hot];
  const probeUrl = hotChecks.map((check) => check?.url).find(Boolean);
  if (!probeUrl && commonCountries.length > 0) {
    throw new Error('AREA-COMBINE requires a health-check URL');
  }
  const intervals = hotChecks.map((check) => Number(check?.interval)).filter((value) => value > 0);
  const timeouts = hotChecks.map((check) => Number(check?.timeout)).filter((value) => value > 0);
  const interval = intervals.length > 0 ? Math.max(...intervals) : 120;
  const timeout = timeouts.length > 0 ? Math.max(...timeouts) : 15000;

  return commonCountries.map((cc) => ({
    name: areaGroupName(cc),
    type: 'fallback',
    hidden: true,
    url: probeUrl,
    interval,
    timeout,
    lazy: true,
    proxies: [
      ...countryLocationNames(ss, cc),
      ...countryLocationNames(pia, cc),
    ],
  }));
}

function applyAreaPolicy(baseGroups, areaGroups) {
  const areaCombine = baseGroups.find((group) => group?.name === 'AREA-COMBINE');
  if (!areaCombine) return;
  const proxies = areaGroups.map((group) => group.name);
  areaCombine.proxies = proxies.length > 0 ? proxies : ['REJECT'];
}

function applyAutomationPolicy(baseGroups, pia, ss) {
  const piaAsia = locationNames(pia, (location) => location.hot);
  const piaHls = regionLocationNames(pia, HLS);
  const ssAsia = regionLocationNames(ss, ASIA, (location) => location.hot);
  const ssHls = regionLocationNames(ss, HLS, (location) => location.hot);

  const ssWgAsia = [...bucket(ss, 'hls'), ...bucket(ss, 'china'), ...bucket(ss, 'asiaExtra')];
  const asiaProxies = [...piaAsia, ...ssAsia];
  const hlsProxies = [...piaHls, ...ssHls];

  const policyByGroup = {
    'AUTO-FAST': { proxies: asiaProxies, use: ssWgAsia },
    'AUTO-SAFE': { proxies: asiaProxies, use: ssWgAsia },
    'LB-HLS': { proxies: hlsProxies, use: bucket(ss, 'hls') },
    'LB-STICKY': { proxies: asiaProxies, use: ssWgAsia },
    'LB-ROBIN': { proxies: asiaProxies, use: ssWgAsia },
    'LB-CONSISTENT': { proxies: asiaProxies, use: ssWgAsia },
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
    PROXY: [
      'SS-ALL','SS-ASIA','SS-MIDDLE-EAST','SS-EUROPE','SS-NORTH-AMERICA','SS-LATIN-AMERICA','SS-OCEANIA','SS-AFRICA',
      'PIA-ALL','PIA-ASIA','PIA-MIDDLE-EAST','PIA-EUROPE','PIA-NORTH-AMERICA','PIA-LATIN-AMERICA','PIA-OCEANIA','PIA-AFRICA',
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
  const checksByVendor = Object.fromEntries(
    VENDOR_DEFS.map((vendor) => [vendor.key, readHealthChecks(config, vendor)])
  );
  const renderedByVendor = Object.fromEntries(
    VENDOR_DEFS.map((vendor) => [vendor.key, renderVendor(vendor, flags, checksByVendor[vendor.key])])
  );
  const pia = renderedByVendor.PIA;
  const ss = renderedByVendor.SS;

  const existingProviders = config['proxy-providers'] && typeof config['proxy-providers'] === 'object'
    ? config['proxy-providers']
    : {};
  const baseProviders = Object.fromEntries(
    Object.entries(existingProviders).filter(([name]) => !isManagedProviderName(name))
  );
  config['proxy-providers'] = { ...pia.providers, ...ss.providers, ...baseProviders };

  const existingGroups = Array.isArray(config['proxy-groups']) ? config['proxy-groups'] : [];
  const baseGroups = existingGroups.filter((group) =>
    !(group?.hidden === true && isManagedEndpointName(group?.name)) &&
    !isManagedVendorGroupName(group?.name) &&
    !isManagedAreaGroupName(group?.name)
  );
  for (const group of baseGroups) {
    if (group && typeof group === 'object') cleanManagedRefs(group);
  }

  applyAutomationPolicy(baseGroups, pia, ss);
  const areaGroups = buildAreaGroups(pia, ss, checksByVendor);
  applyAreaPolicy(baseGroups, areaGroups);
  const vendorGroups = [...buildPiaVendorGroups(pia), ...buildSurfsharkVendorGroups(ss)];
  applyRouteGroupPolicy(baseGroups, vendorGroups);

  config['proxy-groups'] = [
    ...pia.endpointGroups,
    ...ss.endpointGroups,
    ...areaGroups,
    ...baseGroups,
    ...vendorGroups,
  ];
  return config;
}
