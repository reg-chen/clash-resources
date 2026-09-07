// Clash Party JavaScript override
// v10: PIA endpoint override has independent OpenVPN and WireGuard toggles.
// Scope: PIA provider declarations, hidden per-endpoint transport groups, and only
// the PIA endpoint members of existing high-level groups. Routing rules remain YAML.

const PIA_PROVIDER_ROOT = String.raw`P:\Clash\providers`;

const PIA_ENDPOINTS = [
  {"id":"tw","path":"TW","name":"🇹🇼 OV-PIA-TW(台灣)","hot":true},
  {"id":"ph","path":"PH","name":"🇵🇭 OV-PIA-PH(菲律賓)","hot":true},
  {"id":"sg","path":"SG","name":"🇸🇬 OV-PIA-SG(新加坡)","hot":true},
  {"id":"mo","path":"MO","name":"🇲🇴 OV-PIA-MO(澳門)","hot":true},
  {"id":"hk","path":"HK","name":"🇭🇰 OV-PIA-HK(香港)","hot":true},
  {"id":"cn","path":"CN","name":"🇨🇳 OV-PIA-CN(中國)","hot":true},
  {"id":"jp","path":"JP","name":"🇯🇵 OV-PIA-JP(日本)","hot":true},
  {"id":"kr","path":"KR","name":"🇰🇷 OV-PIA-KR(韓國)","hot":true},
  {"id":"my","path":"MY","name":"🇲🇾 OV-PIA-MY(馬來西亞)","hot":true},
  {"id":"id","path":"ID","name":"🇮🇩 OV-PIA-ID(印尼)","hot":true},
  {"id":"vn","path":"VN","name":"🇻🇳 OV-PIA-VN(越南)","hot":true},
  {"id":"in","path":"IN","name":"🇮🇳 OV-PIA-IN(印度)","hot":true},
  {"id":"kh","path":"KH","name":"🇰🇭 OV-PIA-KH(柬埔寨)","hot":true},
  {"id":"mn","path":"MN","name":"🇲🇳 OV-PIA-MN(蒙古)","hot":true},
  {"id":"np","path":"NP","name":"🇳🇵 OV-PIA-NP(尼泊爾)","hot":true},
  {"id":"bd","path":"BD","name":"🇧🇩 OV-PIA-BD(孟加拉)","hot":true},
  {"id":"lk","path":"LK","name":"🇱🇰 OV-PIA-LK(斯里蘭卡)","hot":true},
  {"id":"ae","path":"AE","name":"🇦🇪 OV-PIA-AE(阿聯酋)","hot":false},
  {"id":"qa","path":"QA","name":"🇶🇦 OV-PIA-QA(卡達)","hot":false},
  {"id":"sa","path":"SA","name":"🇸🇦 OV-PIA-SA(沙烏地阿拉伯)","hot":false},
  {"id":"il","path":"IL","name":"🇮🇱 OV-PIA-IL(以色列)","hot":false},
  {"id":"tr","path":"TR","name":"🇹🇷 OV-PIA-TR(土耳其)","hot":false},
  {"id":"eg","path":"EG","name":"🇪🇬 OV-PIA-EG(埃及)","hot":false},
  {"id":"nl-netherlands","path":"NL\\netherlands","name":"🇳🇱 OV-PIA-NL(荷蘭)","hot":false},
  {"id":"de-berlin","path":"DE\\berlin","name":"🇩🇪 OV-PIA-DE(德國-柏林)","hot":false},
  {"id":"de-frankfurt","path":"DE\\frankfurt","name":"🇩🇪 OV-PIA-DE(德國-法蘭克福)","hot":false},
  {"id":"uk-london","path":"UK\\london","name":"🇬🇧 OV-PIA-UK(英國-倫敦)","hot":false},
  {"id":"uk-manchester","path":"UK\\manchester","name":"🇬🇧 OV-PIA-UK(英國-曼徹斯特)","hot":false},
  {"id":"uk-southampton","path":"UK\\southampton","name":"🇬🇧 OV-PIA-UK(英國-南安普敦)","hot":false},
  {"id":"fr","path":"FR","name":"🇫🇷 OV-PIA-FR(法國)","hot":false},
  {"id":"es-madrid","path":"ES\\madrid","name":"🇪🇸 OV-PIA-ES(西班牙-馬德里)","hot":false},
  {"id":"es-valencia","path":"ES\\valencia","name":"🇪🇸 OV-PIA-ES(西班牙-瓦倫西亞)","hot":false},
  {"id":"it-milano","path":"IT\\milano","name":"🇮🇹 OV-PIA-IT(義大利-米蘭)","hot":false},
  {"id":"am","path":"AM","name":"🇦🇲 OV-PIA-AM(亞美尼亞)","hot":false},
  {"id":"ge","path":"GE","name":"🇬🇪 OV-PIA-GE(喬治亞)","hot":false},
  {"id":"kz","path":"KZ","name":"🇰🇿 OV-PIA-KZ(哈薩克)","hot":false},
  {"id":"ad","path":"AD","name":"🇦🇩 OV-PIA-AD(安道爾)","hot":false},
  {"id":"al","path":"AL","name":"🇦🇱 OV-PIA-AL(阿爾巴尼亞)","hot":false},
  {"id":"at","path":"AT","name":"🇦🇹 OV-PIA-AT(奧地利)","hot":false},
  {"id":"ba","path":"BA","name":"🇧🇦 OV-PIA-BA(波士尼亞)","hot":false},
  {"id":"be","path":"BE","name":"🇧🇪 OV-PIA-BE(比利時)","hot":false},
  {"id":"bg","path":"BG","name":"🇧🇬 OV-PIA-BG(保加利亞)","hot":false},
  {"id":"ch","path":"CH","name":"🇨🇭 OV-PIA-CH(瑞士)","hot":false},
  {"id":"cy","path":"CY","name":"🇨🇾 OV-PIA-CY(賽普勒斯)","hot":false},
  {"id":"cz","path":"CZ","name":"🇨🇿 OV-PIA-CZ(捷克)","hot":false},
  {"id":"dk-copenhagen","path":"DK\\copenhagen","name":"🇩🇰 OV-PIA-DK(丹麥-哥本哈根)","hot":false},
  {"id":"ee","path":"EE","name":"🇪🇪 OV-PIA-EE(愛沙尼亞)","hot":false},
  {"id":"fi-helsinki","path":"FI\\helsinki","name":"🇫🇮 OV-PIA-FI(芬蘭-赫爾辛基)","hot":false},
  {"id":"gr","path":"GR","name":"🇬🇷 OV-PIA-GR(希臘)","hot":false},
  {"id":"hr","path":"HR","name":"🇭🇷 OV-PIA-HR(克羅埃西亞)","hot":false},
  {"id":"hu","path":"HU","name":"🇭🇺 OV-PIA-HU(匈牙利)","hot":false},
  {"id":"ie","path":"IE","name":"🇮🇪 OV-PIA-IE(愛爾蘭)","hot":false},
  {"id":"im","path":"IM","name":"🇮🇲 OV-PIA-IM(曼島)","hot":false},
  {"id":"is","path":"IS","name":"🇮🇸 OV-PIA-IS(冰島)","hot":false},
  {"id":"li","path":"LI","name":"🇱🇮 OV-PIA-LI(列支敦斯登)","hot":false},
  {"id":"lt","path":"LT","name":"🇱🇹 OV-PIA-LT(立陶宛)","hot":false},
  {"id":"lu","path":"LU","name":"🇱🇺 OV-PIA-LU(盧森堡)","hot":false},
  {"id":"lv","path":"LV","name":"🇱🇻 OV-PIA-LV(拉脫維亞)","hot":false},
  {"id":"mc","path":"MC","name":"🇲🇨 OV-PIA-MC(摩納哥)","hot":false},
  {"id":"md","path":"MD","name":"🇲🇩 OV-PIA-MD(摩爾多瓦)","hot":false},
  {"id":"me","path":"ME","name":"🇲🇪 OV-PIA-ME(蒙特內哥羅)","hot":false},
  {"id":"mk","path":"MK","name":"🇲🇰 OV-PIA-MK(北馬其頓)","hot":false},
  {"id":"mt","path":"MT","name":"🇲🇹 OV-PIA-MT(馬爾他)","hot":false},
  {"id":"no","path":"NO","name":"🇳🇴 OV-PIA-NO(挪威)","hot":false},
  {"id":"pl","path":"PL","name":"🇵🇱 OV-PIA-PL(波蘭)","hot":false},
  {"id":"pt","path":"PT","name":"🇵🇹 OV-PIA-PT(葡萄牙)","hot":false},
  {"id":"ro","path":"RO","name":"🇷🇴 OV-PIA-RO(羅馬尼亞)","hot":false},
  {"id":"rs","path":"RS","name":"🇷🇸 OV-PIA-RS(塞爾維亞)","hot":false},
  {"id":"se-stockholm","path":"SE\\stockholm","name":"🇸🇪 OV-PIA-SE(瑞典-斯德哥爾摩)","hot":false},
  {"id":"si","path":"SI","name":"🇸🇮 OV-PIA-SI(斯洛維尼亞)","hot":false},
  {"id":"sk","path":"SK","name":"🇸🇰 OV-PIA-SK(斯洛伐克)","hot":false},
  {"id":"ua","path":"UA","name":"🇺🇦 OV-PIA-UA(烏克蘭)","hot":false},
  {"id":"us-alabama","path":"US\\alabama","name":"🇺🇸 OV-PIA-US(美國-阿拉巴馬)","hot":false},
  {"id":"us-alaska","path":"US\\alaska","name":"🇺🇸 OV-PIA-US(美國-阿拉斯加)","hot":false},
  {"id":"us-arkansas","path":"US\\arkansas","name":"🇺🇸 OV-PIA-US(美國-阿肯色)","hot":false},
  {"id":"us-atlanta","path":"US\\atlanta","name":"🇺🇸 OV-PIA-US(美國-亞特蘭大)","hot":false},
  {"id":"us-baltimore","path":"US\\baltimore","name":"🇺🇸 OV-PIA-US(美國-巴爾的摩)","hot":false},
  {"id":"us-california","path":"US\\california","name":"🇺🇸 OV-PIA-US(美國-加州)","hot":false},
  {"id":"us-chicago","path":"US\\chicago","name":"🇺🇸 OV-PIA-US(美國-芝加哥)","hot":false},
  {"id":"us-connecticut","path":"US\\connecticut","name":"🇺🇸 OV-PIA-US(美國-康乃狄克)","hot":false},
  {"id":"us-denver","path":"US\\denver","name":"🇺🇸 OV-PIA-US(美國-丹佛)","hot":false},
  {"id":"us-east","path":"US\\east","name":"🇺🇸 OV-PIA-US(美國-美東)","hot":false},
  {"id":"us-florida","path":"US\\florida","name":"🇺🇸 OV-PIA-US(美國-佛羅里達)","hot":false},
  {"id":"us-honolulu","path":"US\\honolulu","name":"🇺🇸 OV-PIA-US(美國-檀香山)","hot":false},
  {"id":"us-houston","path":"US\\houston","name":"🇺🇸 OV-PIA-US(美國-休士頓)","hot":false},
  {"id":"us-idaho","path":"US\\idaho","name":"🇺🇸 OV-PIA-US(美國-愛達荷)","hot":false},
  {"id":"us-indiana","path":"US\\indiana","name":"🇺🇸 OV-PIA-US(美國-印第安納)","hot":false},
  {"id":"us-iowa","path":"US\\iowa","name":"🇺🇸 OV-PIA-US(美國-愛荷華)","hot":false},
  {"id":"us-kansas","path":"US\\kansas","name":"🇺🇸 OV-PIA-US(美國-堪薩斯)","hot":false},
  {"id":"us-kentucky","path":"US\\kentucky","name":"🇺🇸 OV-PIA-US(美國-肯塔基)","hot":false},
  {"id":"us-las-vegas","path":"US\\las-vegas","name":"🇺🇸 OV-PIA-US(美國-拉斯維加斯)","hot":false},
  {"id":"us-louisiana","path":"US\\louisiana","name":"🇺🇸 OV-PIA-US(美國-路易斯安那)","hot":false},
  {"id":"us-maine","path":"US\\maine","name":"🇺🇸 OV-PIA-US(美國-緬因)","hot":false},
  {"id":"us-massachusetts","path":"US\\massachusetts","name":"🇺🇸 OV-PIA-US(美國-麻薩諸塞)","hot":false},
  {"id":"us-michigan","path":"US\\michigan","name":"🇺🇸 OV-PIA-US(美國-密西根)","hot":false},
  {"id":"us-minnesota","path":"US\\minnesota","name":"🇺🇸 OV-PIA-US(美國-明尼蘇達)","hot":false},
  {"id":"us-mississippi","path":"US\\mississippi","name":"🇺🇸 OV-PIA-US(美國-密西西比)","hot":false},
  {"id":"us-missouri","path":"US\\missouri","name":"🇺🇸 OV-PIA-US(美國-密蘇里)","hot":false},
  {"id":"us-montana","path":"US\\montana","name":"🇺🇸 OV-PIA-US(美國-蒙大拿)","hot":false},
  {"id":"us-nebraska","path":"US\\nebraska","name":"🇺🇸 OV-PIA-US(美國-內布拉斯加)","hot":false},
  {"id":"us-new-hampshire","path":"US\\new-hampshire","name":"🇺🇸 OV-PIA-US(美國-新罕布夏)","hot":false},
  {"id":"us-new-mexico","path":"US\\new-mexico","name":"🇺🇸 OV-PIA-US(美國-新墨西哥)","hot":false},
  {"id":"us-new-york","path":"US\\new-york","name":"🇺🇸 OV-PIA-US(美國-紐約)","hot":false},
  {"id":"us-north-carolina","path":"US\\north-carolina","name":"🇺🇸 OV-PIA-US(美國-北卡羅來納)","hot":false},
  {"id":"us-north-dakota","path":"US\\north-dakota","name":"🇺🇸 OV-PIA-US(美國-北達科他)","hot":false},
  {"id":"us-ohio","path":"US\\ohio","name":"🇺🇸 OV-PIA-US(美國-俄亥俄)","hot":false},
  {"id":"us-oklahoma","path":"US\\oklahoma","name":"🇺🇸 OV-PIA-US(美國-奧克拉荷馬)","hot":false},
  {"id":"us-oregon","path":"US\\oregon","name":"🇺🇸 OV-PIA-US(美國-奧勒岡)","hot":false},
  {"id":"us-pennsylvania","path":"US\\pennsylvania","name":"🇺🇸 OV-PIA-US(美國-賓夕法尼亞)","hot":false},
  {"id":"us-rhode-island","path":"US\\rhode-island","name":"🇺🇸 OV-PIA-US(美國-羅德島)","hot":false},
  {"id":"us-salt-lake-city","path":"US\\salt-lake-city","name":"🇺🇸 OV-PIA-US(美國-鹽湖城)","hot":false},
  {"id":"us-seattle","path":"US\\seattle","name":"🇺🇸 OV-PIA-US(美國-西雅圖)","hot":false},
  {"id":"us-silicon-valley","path":"US\\silicon-valley","name":"🇺🇸 OV-PIA-US(美國-矽谷)","hot":false},
  {"id":"us-south-carolina","path":"US\\south-carolina","name":"🇺🇸 OV-PIA-US(美國-南卡羅來納)","hot":false},
  {"id":"us-south-dakota","path":"US\\south-dakota","name":"🇺🇸 OV-PIA-US(美國-南達科他)","hot":false},
  {"id":"us-tennessee","path":"US\\tennessee","name":"🇺🇸 OV-PIA-US(美國-田納西)","hot":false},
  {"id":"us-texas","path":"US\\texas","name":"🇺🇸 OV-PIA-US(美國-德州)","hot":false},
  {"id":"us-vermont","path":"US\\vermont","name":"🇺🇸 OV-PIA-US(美國-佛蒙特)","hot":false},
  {"id":"us-virginia","path":"US\\virginia","name":"🇺🇸 OV-PIA-US(美國-維吉尼亞)","hot":false},
  {"id":"us-washington-dc","path":"US\\washington-dc","name":"🇺🇸 OV-PIA-US(美國-華盛頓DC)","hot":false},
  {"id":"us-west","path":"US\\west","name":"🇺🇸 OV-PIA-US(美國-美西)","hot":false},
  {"id":"us-west-virginia","path":"US\\west-virginia","name":"🇺🇸 OV-PIA-US(美國-西維吉尼亞)","hot":false},
  {"id":"us-wilmington","path":"US\\wilmington","name":"🇺🇸 OV-PIA-US(美國-威明頓)","hot":false},
  {"id":"us-wisconsin","path":"US\\wisconsin","name":"🇺🇸 OV-PIA-US(美國-威斯康辛)","hot":false},
  {"id":"us-wyoming","path":"US\\wyoming","name":"🇺🇸 OV-PIA-US(美國-懷俄明)","hot":false},
  {"id":"ca-montreal","path":"CA\\montreal","name":"🇨🇦 OV-PIA-CA(加拿大-蒙特婁)","hot":false},
  {"id":"ca-ontario","path":"CA\\ontario","name":"🇨🇦 OV-PIA-CA(加拿大-安大略)","hot":false},
  {"id":"ca-toronto","path":"CA\\toronto","name":"🇨🇦 OV-PIA-CA(加拿大-多倫多)","hot":false},
  {"id":"ca-vancouver","path":"CA\\vancouver","name":"🇨🇦 OV-PIA-CA(加拿大-溫哥華)","hot":false},
  {"id":"gl","path":"GL","name":"🇬🇱 OV-PIA-GL(格陵蘭)","hot":false},
  {"id":"mx","path":"MX","name":"🇲🇽 OV-PIA-MX(墨西哥)","hot":false},
  {"id":"br","path":"BR","name":"🇧🇷 OV-PIA-BR(巴西)","hot":false},
  {"id":"ar","path":"AR","name":"🇦🇷 OV-PIA-AR(阿根廷)","hot":false},
  {"id":"cl","path":"CL","name":"🇨🇱 OV-PIA-CL(智利)","hot":false},
  {"id":"co","path":"CO","name":"🇨🇴 OV-PIA-CO(哥倫比亞)","hot":false},
  {"id":"bo","path":"BO","name":"🇧🇴 OV-PIA-BO(玻利維亞)","hot":false},
  {"id":"bs","path":"BS","name":"🇧🇸 OV-PIA-BS(巴哈馬)","hot":false},
  {"id":"cr","path":"CR","name":"🇨🇷 OV-PIA-CR(哥斯大黎加)","hot":false},
  {"id":"ec","path":"EC","name":"🇪🇨 OV-PIA-EC(厄瓜多)","hot":false},
  {"id":"gt","path":"GT","name":"🇬🇹 OV-PIA-GT(瓜地馬拉)","hot":false},
  {"id":"pa","path":"PA","name":"🇵🇦 OV-PIA-PA(巴拿馬)","hot":false},
  {"id":"pe","path":"PE","name":"🇵🇪 OV-PIA-PE(秘魯)","hot":false},
  {"id":"uy","path":"UY","name":"🇺🇾 OV-PIA-UY(烏拉圭)","hot":false},
  {"id":"ve","path":"VE","name":"🇻🇪 OV-PIA-VE(委內瑞拉)","hot":false},
  {"id":"au-adelaide","path":"AU\\adelaide","name":"🇦🇺 OV-PIA-AU(澳洲-阿德雷德)","hot":false},
  {"id":"au-brisbane","path":"AU\\brisbane","name":"🇦🇺 OV-PIA-AU(澳洲-布里斯本)","hot":false},
  {"id":"au-melbourne","path":"AU\\melbourne","name":"🇦🇺 OV-PIA-AU(澳洲-墨爾本)","hot":false},
  {"id":"au-perth","path":"AU\\perth","name":"🇦🇺 OV-PIA-AU(澳洲-伯斯)","hot":false},
  {"id":"au-sydney","path":"AU\\sydney","name":"🇦🇺 OV-PIA-AU(澳洲-雪梨)","hot":false},
  {"id":"nz","path":"NZ","name":"🇳🇿 OV-PIA-NZ(紐西蘭)","hot":false},
  {"id":"za","path":"ZA","name":"🇿🇦 OV-PIA-ZA(南非)","hot":false},
  {"id":"ng","path":"NG","name":"🇳🇬 OV-PIA-NG(奈及利亞)","hot":false},
  {"id":"ma","path":"MA","name":"🇲🇦 OV-PIA-MA(摩洛哥)","hot":false},
  {"id":"dz","path":"DZ","name":"🇩🇿 OV-PIA-DZ(阿爾及利亞)","hot":false}
];

const CHINA = new Set(['MO', 'HK', 'CN']);
const MIDDLE_EAST = new Set(['AE', 'QA', 'SA', 'IL', 'TR', 'EG']);
const NORTH_AMERICA = new Set(['US', 'CA', 'GL']);
const LATIN_AMERICA = new Set(['MX', 'BR', 'AR', 'CL', 'CO', 'BO', 'BS', 'CR', 'EC', 'GT', 'PA', 'PE', 'UY', 'VE']);
const OCEANIA = new Set(['AU', 'NZ']);
const AFRICA = new Set(['ZA', 'NG', 'MA', 'DZ']);

function countryCode(endpoint) {
  return endpoint.path.split('\\')[0];
}

const countryCounts = PIA_ENDPOINTS.reduce((counts, endpoint) => {
  const cc = countryCode(endpoint);
  counts[cc] = (counts[cc] || 0) + 1;
  return counts;
}, {});

function endpointPath(endpoint) {
  const cc = countryCode(endpoint);
  return countryCounts[cc] > 1 ? endpoint.path : cc;
}

function endpointNames(predicate) {
  return PIA_ENDPOINTS.filter(predicate).map((endpoint) => endpoint.name);
}

const ASIA_ENDPOINTS = endpointNames((endpoint) => endpoint.hot);
const HLS_ENDPOINTS = endpointNames((endpoint) => ['TW', 'PH', 'SG'].includes(countryCode(endpoint)));
const AI_ENDPOINTS = endpointNames((endpoint) => endpoint.hot && !CHINA.has(countryCode(endpoint)));
const ALL_ENDPOINTS = PIA_ENDPOINTS.map((endpoint) => endpoint.name);

const EUROPE_ENDPOINTS = endpointNames((endpoint) => {
  const cc = countryCode(endpoint);
  return !endpoint.hot && !MIDDLE_EAST.has(cc) && !NORTH_AMERICA.has(cc) &&
    !LATIN_AMERICA.has(cc) && !OCEANIA.has(cc) && !AFRICA.has(cc);
});

const PIA_GROUP_MEMBERS = {
  'AUTO-FAST': ASIA_ENDPOINTS,
  'AUTO-SAFE': ASIA_ENDPOINTS,
  'LB-HLS': HLS_ENDPOINTS,
  'LB-STICKY': ASIA_ENDPOINTS,
  'LB-ROBIN': ASIA_ENDPOINTS,
  'LB-CONSISTENT': ASIA_ENDPOINTS,
  'AI-PROXY': AI_ENDPOINTS,
  'OV-ALL': ALL_ENDPOINTS,
  'OV-ASIA': ASIA_ENDPOINTS,
  'OV-MIDDLE-EAST': endpointNames((endpoint) => MIDDLE_EAST.has(countryCode(endpoint))),
  'OV-EUROPE': EUROPE_ENDPOINTS,
  'OV-NORTH-AMERICA': endpointNames((endpoint) => NORTH_AMERICA.has(countryCode(endpoint))),
  'OV-LATIN-AMERICA': endpointNames((endpoint) => LATIN_AMERICA.has(countryCode(endpoint))),
  'OV-OCEANIA': endpointNames((endpoint) => OCEANIA.has(countryCode(endpoint))),
  'OV-AFRICA': endpointNames((endpoint) => AFRICA.has(countryCode(endpoint))),
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function main(config) {
  if (!config || typeof config !== 'object') return config;

  if (config['x-pia-endpoint-override'] !== true) return config;
  delete config['x-pia-endpoint-override'];

  const ovEnabled = config['x-pia-openvpn'] === true;
  delete config['x-pia-openvpn'];

  const wgEnabled = config['x-pia-wireguard'] === true;
  delete config['x-pia-wireguard'];

  const hot = config['x-pia-test']?.['health-check'];
  const cold = config['x-pia-test-slow']?.['health-check'];
  if (!hot || !cold) {
    throw new Error('PIA endpoint override requires x-pia-test and x-pia-test-slow in the base YAML');
  }

  const existingProviders = config['proxy-providers'] && typeof config['proxy-providers'] === 'object'
    ? config['proxy-providers']
    : {};

  // Remove both generated protocol families so protocol toggles are deterministic.
  const nonPiaProviders = Object.fromEntries(
    Object.entries(existingProviders).filter(([name]) => !/^(?:ov|wg)-pia-/i.test(name))
  );
  const piaProviders = {};
  const endpointGroups = [];

  for (const endpoint of PIA_ENDPOINTS) {
    const healthCheck = endpoint.hot ? hot : cold;
    const basePath = `${PIA_PROVIDER_ROOT}\\${endpointPath(endpoint)}`;
    const uses = [];

    if (wgEnabled) {
      const wgProviderName = `wg-pia-${endpoint.id}`;
      piaProviders[wgProviderName] = {
        type: 'file',
        path: `${basePath}\\pia-wg.yaml`,
        'health-check': clone(healthCheck),
      };
      uses.push(wgProviderName);
    }

    if (ovEnabled) {
      const ovProviderName = `ov-pia-${endpoint.id}`;
      piaProviders[ovProviderName] = {
        type: 'file',
        path: `${basePath}\\pia-ov.yaml`,
        'health-check': clone(healthCheck),
      };
      uses.push(ovProviderName);
    }

    if (uses.length > 0) {
      endpointGroups.push({
        name: endpoint.name,
        type: endpoint.hot ? 'fallback' : 'select',
        hidden: true,
        use: uses,
      });
    }
  }

  config['proxy-providers'] = { ...piaProviders, ...nonPiaProviders };

  const existingGroups = Array.isArray(config['proxy-groups']) ? config['proxy-groups'] : [];
  const nonEndpointGroups = existingGroups.filter((group) => {
    const name = group?.name;
    const isPiaEndpointGroup =
      group?.hidden === true &&
      typeof name === 'string' &&
      name.includes('OV-PIA-');
    return !isPiaEndpointGroup;
  });

  if (ovEnabled || wgEnabled) {
    for (const group of nonEndpointGroups) {
      const piaMembers = PIA_GROUP_MEMBERS[group?.name];
      if (!piaMembers) continue;

      const current = Array.isArray(group.proxies) ? group.proxies : [];
      const nonPia = current.filter(
        (name) => typeof name !== 'string' || !name.includes('OV-PIA-')
      );
      const isPiaOnlyGroup = nonPia.length === 1 && nonPia[0] === 'REJECT';
      group.proxies = [...(isPiaOnlyGroup ? [] : nonPia), ...piaMembers];
    }
  }

  config['proxy-groups'] = [...endpointGroups, ...nonEndpointGroups];
  return config;
}
