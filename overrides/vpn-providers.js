// Clash Party JavaScript override
// v13: VPN provider/group topology is injected from YAML feature flags.
// PIA and Surfshark protocol families are independent. Routing rules remain YAML.
// Clash Party's JS sandbox cannot access the local filesystem directly.
// Protocol family toggles are therefore the single source of truth. Provider files
// use stable generator-defined paths so a missing file fails visibly in Mihomo.

const PROVIDER_ROOT = String.raw`P:\Clash\providers`;
const ICON_ROOT = 'https://cdn.jsdelivr.net/gh/reg-chen/clash-resources@main/icons';

const PIA_ENDPOINTS = [
  {"id":"tw","path":"TW","name":"🇹🇼 PIA-TW(台灣)","hot":true},
  {"id":"ph","path":"PH","name":"🇵🇭 PIA-PH(菲律賓)","hot":true},
  {"id":"sg","path":"SG","name":"🇸🇬 PIA-SG(新加坡)","hot":true},
  {"id":"mo","path":"MO","name":"🇲🇴 PIA-MO(澳門)","hot":true},
  {"id":"hk","path":"HK","name":"🇭🇰 PIA-HK(香港)","hot":true},
  {"id":"cn","path":"CN","name":"🇨🇳 PIA-CN(中國)","hot":true},
  {"id":"jp","path":"JP","name":"🇯🇵 PIA-JP(日本)","hot":true},
  {"id":"kr","path":"KR","name":"🇰🇷 PIA-KR(韓國)","hot":true},
  {"id":"my","path":"MY","name":"🇲🇾 PIA-MY(馬來西亞)","hot":true},
  {"id":"id","path":"ID","name":"🇮🇩 PIA-ID(印尼)","hot":true},
  {"id":"vn","path":"VN","name":"🇻🇳 PIA-VN(越南)","hot":true},
  {"id":"in","path":"IN","name":"🇮🇳 PIA-IN(印度)","hot":true},
  {"id":"kh","path":"KH","name":"🇰🇭 PIA-KH(柬埔寨)","hot":true},
  {"id":"mn","path":"MN","name":"🇲🇳 PIA-MN(蒙古)","hot":true},
  {"id":"np","path":"NP","name":"🇳🇵 PIA-NP(尼泊爾)","hot":true},
  {"id":"bd","path":"BD","name":"🇧🇩 PIA-BD(孟加拉)","hot":true},
  {"id":"lk","path":"LK","name":"🇱🇰 PIA-LK(斯里蘭卡)","hot":true},
  {"id":"ae","path":"AE","name":"🇦🇪 PIA-AE(阿聯酋)","hot":false},
  {"id":"qa","path":"QA","name":"🇶🇦 PIA-QA(卡達)","hot":false},
  {"id":"sa","path":"SA","name":"🇸🇦 PIA-SA(沙烏地阿拉伯)","hot":false},
  {"id":"il","path":"IL","name":"🇮🇱 PIA-IL(以色列)","hot":false},
  {"id":"tr","path":"TR","name":"🇹🇷 PIA-TR(土耳其)","hot":false},
  {"id":"eg","path":"EG","name":"🇪🇬 PIA-EG(埃及)","hot":false},
  {"id":"nl-netherlands","path":"NL\\netherlands","name":"🇳🇱 PIA-NL(荷蘭)","hot":false},
  {"id":"de-berlin","path":"DE\\berlin","name":"🇩🇪 PIA-DE(德國-柏林)","hot":false},
  {"id":"de-frankfurt","path":"DE\\frankfurt","name":"🇩🇪 PIA-DE(德國-法蘭克福)","hot":false},
  {"id":"uk-london","path":"UK\\london","name":"🇬🇧 PIA-UK(英國-倫敦)","hot":false},
  {"id":"uk-manchester","path":"UK\\manchester","name":"🇬🇧 PIA-UK(英國-曼徹斯特)","hot":false},
  {"id":"uk-southampton","path":"UK\\southampton","name":"🇬🇧 PIA-UK(英國-南安普敦)","hot":false},
  {"id":"fr","path":"FR","name":"🇫🇷 PIA-FR(法國)","hot":false},
  {"id":"es-madrid","path":"ES\\madrid","name":"🇪🇸 PIA-ES(西班牙-馬德里)","hot":false},
  {"id":"es-valencia","path":"ES\\valencia","name":"🇪🇸 PIA-ES(西班牙-瓦倫西亞)","hot":false},
  {"id":"it-milano","path":"IT\\milano","name":"🇮🇹 PIA-IT(義大利-米蘭)","hot":false},
  {"id":"am","path":"AM","name":"🇦🇲 PIA-AM(亞美尼亞)","hot":false},
  {"id":"ge","path":"GE","name":"🇬🇪 PIA-GE(喬治亞)","hot":false},
  {"id":"kz","path":"KZ","name":"🇰🇿 PIA-KZ(哈薩克)","hot":false},
  {"id":"ad","path":"AD","name":"🇦🇩 PIA-AD(安道爾)","hot":false},
  {"id":"al","path":"AL","name":"🇦🇱 PIA-AL(阿爾巴尼亞)","hot":false},
  {"id":"at","path":"AT","name":"🇦🇹 PIA-AT(奧地利)","hot":false},
  {"id":"ba","path":"BA","name":"🇧🇦 PIA-BA(波士尼亞)","hot":false},
  {"id":"be","path":"BE","name":"🇧🇪 PIA-BE(比利時)","hot":false},
  {"id":"bg","path":"BG","name":"🇧🇬 PIA-BG(保加利亞)","hot":false},
  {"id":"ch","path":"CH","name":"🇨🇭 PIA-CH(瑞士)","hot":false},
  {"id":"cy","path":"CY","name":"🇨🇾 PIA-CY(賽普勒斯)","hot":false},
  {"id":"cz","path":"CZ","name":"🇨🇿 PIA-CZ(捷克)","hot":false},
  {"id":"dk-copenhagen","path":"DK\\copenhagen","name":"🇩🇰 PIA-DK(丹麥-哥本哈根)","hot":false},
  {"id":"ee","path":"EE","name":"🇪🇪 PIA-EE(愛沙尼亞)","hot":false},
  {"id":"fi-helsinki","path":"FI\\helsinki","name":"🇫🇮 PIA-FI(芬蘭-赫爾辛基)","hot":false},
  {"id":"gr","path":"GR","name":"🇬🇷 PIA-GR(希臘)","hot":false},
  {"id":"hr","path":"HR","name":"🇭🇷 PIA-HR(克羅埃西亞)","hot":false},
  {"id":"hu","path":"HU","name":"🇭🇺 PIA-HU(匈牙利)","hot":false},
  {"id":"ie","path":"IE","name":"🇮🇪 PIA-IE(愛爾蘭)","hot":false},
  {"id":"im","path":"IM","name":"🇮🇲 PIA-IM(曼島)","hot":false},
  {"id":"is","path":"IS","name":"🇮🇸 PIA-IS(冰島)","hot":false},
  {"id":"li","path":"LI","name":"🇱🇮 PIA-LI(列支敦斯登)","hot":false},
  {"id":"lt","path":"LT","name":"🇱🇹 PIA-LT(立陶宛)","hot":false},
  {"id":"lu","path":"LU","name":"🇱🇺 PIA-LU(盧森堡)","hot":false},
  {"id":"lv","path":"LV","name":"🇱🇻 PIA-LV(拉脫維亞)","hot":false},
  {"id":"mc","path":"MC","name":"🇲🇨 PIA-MC(摩納哥)","hot":false},
  {"id":"md","path":"MD","name":"🇲🇩 PIA-MD(摩爾多瓦)","hot":false},
  {"id":"me","path":"ME","name":"🇲🇪 PIA-ME(蒙特內哥羅)","hot":false},
  {"id":"mk","path":"MK","name":"🇲🇰 PIA-MK(北馬其頓)","hot":false},
  {"id":"mt","path":"MT","name":"🇲🇹 PIA-MT(馬爾他)","hot":false},
  {"id":"no","path":"NO","name":"🇳🇴 PIA-NO(挪威)","hot":false},
  {"id":"pl","path":"PL","name":"🇵🇱 PIA-PL(波蘭)","hot":false},
  {"id":"pt","path":"PT","name":"🇵🇹 PIA-PT(葡萄牙)","hot":false},
  {"id":"ro","path":"RO","name":"🇷🇴 PIA-RO(羅馬尼亞)","hot":false},
  {"id":"rs","path":"RS","name":"🇷🇸 PIA-RS(塞爾維亞)","hot":false},
  {"id":"se-stockholm","path":"SE\\stockholm","name":"🇸🇪 PIA-SE(瑞典-斯德哥爾摩)","hot":false},
  {"id":"si","path":"SI","name":"🇸🇮 PIA-SI(斯洛維尼亞)","hot":false},
  {"id":"sk","path":"SK","name":"🇸🇰 PIA-SK(斯洛伐克)","hot":false},
  {"id":"ua","path":"UA","name":"🇺🇦 PIA-UA(烏克蘭)","hot":false},
  {"id":"us-alabama","path":"US\\alabama","name":"🇺🇸 PIA-US(美國-阿拉巴馬)","hot":false},
  {"id":"us-alaska","path":"US\\alaska","name":"🇺🇸 PIA-US(美國-阿拉斯加)","hot":false},
  {"id":"us-arkansas","path":"US\\arkansas","name":"🇺🇸 PIA-US(美國-阿肯色)","hot":false},
  {"id":"us-atlanta","path":"US\\atlanta","name":"🇺🇸 PIA-US(美國-亞特蘭大)","hot":false},
  {"id":"us-baltimore","path":"US\\baltimore","name":"🇺🇸 PIA-US(美國-巴爾的摩)","hot":false},
  {"id":"us-california","path":"US\\california","name":"🇺🇸 PIA-US(美國-加州)","hot":false},
  {"id":"us-chicago","path":"US\\chicago","name":"🇺🇸 PIA-US(美國-芝加哥)","hot":false},
  {"id":"us-connecticut","path":"US\\connecticut","name":"🇺🇸 PIA-US(美國-康乃狄克)","hot":false},
  {"id":"us-denver","path":"US\\denver","name":"🇺🇸 PIA-US(美國-丹佛)","hot":false},
  {"id":"us-east","path":"US\\east","name":"🇺🇸 PIA-US(美國-美東)","hot":false},
  {"id":"us-florida","path":"US\\florida","name":"🇺🇸 PIA-US(美國-佛羅里達)","hot":false},
  {"id":"us-honolulu","path":"US\\honolulu","name":"🇺🇸 PIA-US(美國-檀香山)","hot":false},
  {"id":"us-houston","path":"US\\houston","name":"🇺🇸 PIA-US(美國-休士頓)","hot":false},
  {"id":"us-idaho","path":"US\\idaho","name":"🇺🇸 PIA-US(美國-愛達荷)","hot":false},
  {"id":"us-indiana","path":"US\\indiana","name":"🇺🇸 PIA-US(美國-印第安納)","hot":false},
  {"id":"us-iowa","path":"US\\iowa","name":"🇺🇸 PIA-US(美國-愛荷華)","hot":false},
  {"id":"us-kansas","path":"US\\kansas","name":"🇺🇸 PIA-US(美國-堪薩斯)","hot":false},
  {"id":"us-kentucky","path":"US\\kentucky","name":"🇺🇸 PIA-US(美國-肯塔基)","hot":false},
  {"id":"us-las-vegas","path":"US\\las-vegas","name":"🇺🇸 PIA-US(美國-拉斯維加斯)","hot":false},
  {"id":"us-louisiana","path":"US\\louisiana","name":"🇺🇸 PIA-US(美國-路易斯安那)","hot":false},
  {"id":"us-maine","path":"US\\maine","name":"🇺🇸 PIA-US(美國-緬因)","hot":false},
  {"id":"us-massachusetts","path":"US\\massachusetts","name":"🇺🇸 PIA-US(美國-麻薩諸塞)","hot":false},
  {"id":"us-michigan","path":"US\\michigan","name":"🇺🇸 PIA-US(美國-密西根)","hot":false},
  {"id":"us-minnesota","path":"US\\minnesota","name":"🇺🇸 PIA-US(美國-明尼蘇達)","hot":false},
  {"id":"us-mississippi","path":"US\\mississippi","name":"🇺🇸 PIA-US(美國-密西西比)","hot":false},
  {"id":"us-missouri","path":"US\\missouri","name":"🇺🇸 PIA-US(美國-密蘇里)","hot":false},
  {"id":"us-montana","path":"US\\montana","name":"🇺🇸 PIA-US(美國-蒙大拿)","hot":false},
  {"id":"us-nebraska","path":"US\\nebraska","name":"🇺🇸 PIA-US(美國-內布拉斯加)","hot":false},
  {"id":"us-new-hampshire","path":"US\\new-hampshire","name":"🇺🇸 PIA-US(美國-新罕布夏)","hot":false},
  {"id":"us-new-mexico","path":"US\\new-mexico","name":"🇺🇸 PIA-US(美國-新墨西哥)","hot":false},
  {"id":"us-new-york","path":"US\\new-york","name":"🇺🇸 PIA-US(美國-紐約)","hot":false},
  {"id":"us-north-carolina","path":"US\\north-carolina","name":"🇺🇸 PIA-US(美國-北卡羅來納)","hot":false},
  {"id":"us-north-dakota","path":"US\\north-dakota","name":"🇺🇸 PIA-US(美國-北達科他)","hot":false},
  {"id":"us-ohio","path":"US\\ohio","name":"🇺🇸 PIA-US(美國-俄亥俄)","hot":false},
  {"id":"us-oklahoma","path":"US\\oklahoma","name":"🇺🇸 PIA-US(美國-奧克拉荷馬)","hot":false},
  {"id":"us-oregon","path":"US\\oregon","name":"🇺🇸 PIA-US(美國-奧勒岡)","hot":false},
  {"id":"us-pennsylvania","path":"US\\pennsylvania","name":"🇺🇸 PIA-US(美國-賓夕法尼亞)","hot":false},
  {"id":"us-rhode-island","path":"US\\rhode-island","name":"🇺🇸 PIA-US(美國-羅德島)","hot":false},
  {"id":"us-salt-lake-city","path":"US\\salt-lake-city","name":"🇺🇸 PIA-US(美國-鹽湖城)","hot":false},
  {"id":"us-seattle","path":"US\\seattle","name":"🇺🇸 PIA-US(美國-西雅圖)","hot":false},
  {"id":"us-silicon-valley","path":"US\\silicon-valley","name":"🇺🇸 PIA-US(美國-矽谷)","hot":false},
  {"id":"us-south-carolina","path":"US\\south-carolina","name":"🇺🇸 PIA-US(美國-南卡羅來納)","hot":false},
  {"id":"us-south-dakota","path":"US\\south-dakota","name":"🇺🇸 PIA-US(美國-南達科他)","hot":false},
  {"id":"us-tennessee","path":"US\\tennessee","name":"🇺🇸 PIA-US(美國-田納西)","hot":false},
  {"id":"us-texas","path":"US\\texas","name":"🇺🇸 PIA-US(美國-德州)","hot":false},
  {"id":"us-vermont","path":"US\\vermont","name":"🇺🇸 PIA-US(美國-佛蒙特)","hot":false},
  {"id":"us-virginia","path":"US\\virginia","name":"🇺🇸 PIA-US(美國-維吉尼亞)","hot":false},
  {"id":"us-washington-dc","path":"US\\washington-dc","name":"🇺🇸 PIA-US(美國-華盛頓DC)","hot":false},
  {"id":"us-west","path":"US\\west","name":"🇺🇸 PIA-US(美國-美西)","hot":false},
  {"id":"us-west-virginia","path":"US\\west-virginia","name":"🇺🇸 PIA-US(美國-西維吉尼亞)","hot":false},
  {"id":"us-wilmington","path":"US\\wilmington","name":"🇺🇸 PIA-US(美國-威明頓)","hot":false},
  {"id":"us-wisconsin","path":"US\\wisconsin","name":"🇺🇸 PIA-US(美國-威斯康辛)","hot":false},
  {"id":"us-wyoming","path":"US\\wyoming","name":"🇺🇸 PIA-US(美國-懷俄明)","hot":false},
  {"id":"ca-montreal","path":"CA\\montreal","name":"🇨🇦 PIA-CA(加拿大-蒙特婁)","hot":false},
  {"id":"ca-ontario","path":"CA\\ontario","name":"🇨🇦 PIA-CA(加拿大-安大略)","hot":false},
  {"id":"ca-toronto","path":"CA\\toronto","name":"🇨🇦 PIA-CA(加拿大-多倫多)","hot":false},
  {"id":"ca-vancouver","path":"CA\\vancouver","name":"🇨🇦 PIA-CA(加拿大-溫哥華)","hot":false},
  {"id":"gl","path":"GL","name":"🇬🇱 PIA-GL(格陵蘭)","hot":false},
  {"id":"mx","path":"MX","name":"🇲🇽 PIA-MX(墨西哥)","hot":false},
  {"id":"br","path":"BR","name":"🇧🇷 PIA-BR(巴西)","hot":false},
  {"id":"ar","path":"AR","name":"🇦🇷 PIA-AR(阿根廷)","hot":false},
  {"id":"cl","path":"CL","name":"🇨🇱 PIA-CL(智利)","hot":false},
  {"id":"co","path":"CO","name":"🇨🇴 PIA-CO(哥倫比亞)","hot":false},
  {"id":"bo","path":"BO","name":"🇧🇴 PIA-BO(玻利維亞)","hot":false},
  {"id":"bs","path":"BS","name":"🇧🇸 PIA-BS(巴哈馬)","hot":false},
  {"id":"cr","path":"CR","name":"🇨🇷 PIA-CR(哥斯大黎加)","hot":false},
  {"id":"ec","path":"EC","name":"🇪🇨 PIA-EC(厄瓜多)","hot":false},
  {"id":"gt","path":"GT","name":"🇬🇹 PIA-GT(瓜地馬拉)","hot":false},
  {"id":"pa","path":"PA","name":"🇵🇦 PIA-PA(巴拿馬)","hot":false},
  {"id":"pe","path":"PE","name":"🇵🇪 PIA-PE(秘魯)","hot":false},
  {"id":"uy","path":"UY","name":"🇺🇾 PIA-UY(烏拉圭)","hot":false},
  {"id":"ve","path":"VE","name":"🇻🇪 PIA-VE(委內瑞拉)","hot":false},
  {"id":"au-adelaide","path":"AU\\adelaide","name":"🇦🇺 PIA-AU(澳洲-阿德雷德)","hot":false},
  {"id":"au-brisbane","path":"AU\\brisbane","name":"🇦🇺 PIA-AU(澳洲-布里斯本)","hot":false},
  {"id":"au-melbourne","path":"AU\\melbourne","name":"🇦🇺 PIA-AU(澳洲-墨爾本)","hot":false},
  {"id":"au-perth","path":"AU\\perth","name":"🇦🇺 PIA-AU(澳洲-伯斯)","hot":false},
  {"id":"au-sydney","path":"AU\\sydney","name":"🇦🇺 PIA-AU(澳洲-雪梨)","hot":false},
  {"id":"nz","path":"NZ","name":"🇳🇿 PIA-NZ(紐西蘭)","hot":false},
  {"id":"za","path":"ZA","name":"🇿🇦 PIA-ZA(南非)","hot":false},
  {"id":"ng","path":"NG","name":"🇳🇬 PIA-NG(奈及利亞)","hot":false},
  {"id":"ma","path":"MA","name":"🇲🇦 PIA-MA(摩洛哥)","hot":false},
  {"id":"dz","path":"DZ","name":"🇩🇿 PIA-DZ(阿爾及利亞)","hot":false}
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
  'EE', 'ES', 'FI', 'FR', 'GE', 'GB', 'GR', 'HR', 'HU', 'IE', 'IM', 'IS',
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

const SURFSHARK_COUNTRIES = ["AL","DZ","AD","AR","AM","AU","AT","AZ","BS","BD","BE","BZ","BT","BO","BA","BR","BN","BG","KH","CA","CL","CO","CR","HR","CY","CZ","DK","EC","EG","EE","FI","FR","GE","DE","GH","GR","GL","HK","HU","IS","IN","ID","IE","IM","IL","IT","JP","KZ","LA","LV","LI","LT","LU","MO","MY","MT","MA","MX","MD","MC","MN","ME","MM","NP","NL","NZ","NG","MK","NO","PK","PA","PY","PE","PH","PL","PT","PR","RO","SA","RS","SG","SK","SI","ZA","KR","ES","LK","SE","CH","TW","TH","TR","UA","AE","GB","US","UY","UZ","VE","VN"];

const PIA_HOT_COUNTRY_ORDER = [
  'TW', 'PH', 'SG', 'MO', 'HK', 'CN', 'JP', 'KR', 'MY', 'ID', 'VN', 'IN',
  'KH', 'MN', 'NP', 'BD', 'LK'
];

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

function endpointNames(predicate, availableNames = null) {
  return PIA_ENDPOINTS
    .filter(predicate)
    .map((endpoint) => endpoint.name)
    .filter((name) => !availableNames || availableNames.has(name));
}

function isPiaEndpointName(name) {
  return typeof name === 'string' && (
    name.includes(' PIA-') || name.includes(' OV-PIA-')
  );
}

function isManagedVendorGroupName(name) {
  return typeof name === 'string' && /^(?:PIA|SS)-(?:ALL|ASIA|MIDDLE-EAST|EUROPE|NORTH-AMERICA|LATIN-AMERICA|OCEANIA|AFRICA)$/i.test(name);
}

function isManagedProviderName(name) {
  if (typeof name !== 'string') return false;
  return /^(?:ov|wg)-pia-/i.test(name) ||
    /^(?:ov|wg)-ss-/i.test(name) ||
    /^(?:hls|china|asia-extra|global-extra)-wg-ss$/i.test(name);
}

const EXTRA_COUNTRY_ZH = {
  AZ: '亞塞拜然',
  BZ: '貝里斯',
  BT: '不丹',
  BN: '汶萊',
  GH: '迦納',
  LA: '寮國',
  MM: '緬甸',
  PK: '巴基斯坦',
  PY: '巴拉圭',
  PR: '波多黎各',
  TH: '泰國',
  GB: '英國',
  UZ: '烏茲別克',
};

const PIA_COUNTRY_ZH = PIA_ENDPOINTS.reduce((map, endpoint) => {
  const cc = countryCode(endpoint);
  if (map[cc]) return map;
  const match = endpoint.name.match(/\(([^)]+)\)$/);
  if (!match) return map;
  map[cc] = match[1].split('-')[0];
  return map;
}, {});

function countryZh(countryCode) {
  return PIA_COUNTRY_ZH[countryCode] || EXTRA_COUNTRY_ZH[countryCode] || countryCode;
}

function flagEmoji(alpha2) {
  return [...alpha2.toUpperCase()]
    .map((ch) => String.fromCodePoint(0x1F1E6 + ch.charCodeAt(0) - 65))
    .join('');
}

function flagFilter(countries) {
  return Array.from(countries).sort().map(flagEmoji).join('|');
}

function piaRegionMembers(countries, availableNames) {
  return endpointNames((endpoint) => countries.has(countryCode(endpoint)), availableNames);
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

function cleanManagedRefs(group) {
  if (Array.isArray(group.use)) {
    group.use = group.use.filter((name) => !isManagedProviderName(name));
    if (group.use.length === 0) delete group.use;
  }
  if (Array.isArray(group.proxies)) {
    group.proxies = group.proxies.filter((name) =>
      !isPiaEndpointName(name) && !isManagedVendorGroupName(name)
    );
  }
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

function main(config) {
  if (!config || typeof config !== 'object') return config;
  if (config['x-vpn-provider-override'] !== true) return config;
  delete config['x-vpn-provider-override'];

  const piaOpenvpnEnabled = config['x-pia-openvpn'] === true;
  const piaWireguardEnabled = config['x-pia-wireguard'] === true;
  const ssOpenvpnEnabled = config['x-ss-openvpn'] === true;
  const ssWireguardEnabled = config['x-ss-wireguard'] === true;
  delete config['x-pia-openvpn'];
  delete config['x-pia-wireguard'];
  delete config['x-ss-openvpn'];
  delete config['x-ss-wireguard'];

  const piaHot = config['x-pia-test']?.['health-check'];
  const piaCold = config['x-pia-test-slow']?.['health-check'];
  const ssHot = config['x-ss-test']?.['health-check'];
  const ssCold = config['x-ss-test-slow']?.['health-check'];
  if (!piaHot || !piaCold || !ssHot || !ssCold) {
    throw new Error('VPN provider override requires x-pia-test, x-pia-test-slow, x-ss-test and x-ss-test-slow');
  }

  const existingProviders = config['proxy-providers'] && typeof config['proxy-providers'] === 'object'
    ? config['proxy-providers'] : {};
  const baseProviders = Object.fromEntries(
    Object.entries(existingProviders).filter(([name]) => !isManagedProviderName(name))
  );

  const generatedProviders = {};
  const piaEndpointGroups = [];
  const availablePiaEndpointNames = new Set();

  for (const endpoint of PIA_ENDPOINTS) {
    const healthCheck = endpoint.hot ? piaHot : piaCold;
    const basePath = `${PROVIDER_ROOT}\\${endpointPath(endpoint)}`;
    const uses = [];

    if (piaWireguardEnabled) {
      const providerName = `wg-pia-${endpoint.id}`;
      generatedProviders[providerName] = makeProvider(`${basePath}\\pia-wg.yaml`, healthCheck);
      uses.push(providerName);
    }
    if (piaOpenvpnEnabled) {
      const providerName = `ov-pia-${endpoint.id}`;
      generatedProviders[providerName] = makeProvider(`${basePath}\\pia-ov.yaml`, healthCheck);
      uses.push(providerName);
    }
    if (uses.length > 0) {
      availablePiaEndpointNames.add(endpoint.name);
      piaEndpointGroups.push({
        name: endpoint.name,
        type: endpoint.hot ? 'fallback' : 'select',
        hidden: true,
        use: uses,
      });
    }
  }

  const ssBuckets = {
    hls: [],
    china: [],
    asiaExtra: [],
    wgGlobalExtra: [],
  };
  const ssRegionBuckets = Object.fromEntries(
    REGION_DEFS.map(([regionName]) => [regionName, []])
  );
  const ssOpenvpnByCountry = new Map();

  if (ssWireguardEnabled) {
    const defs = [
      ['hls', 'hls-wg-ss', 'hls-wg-ss.yaml'],
      ['china', 'china-wg-ss', 'china-wg-ss.yaml'],
      ['asiaExtra', 'asia-extra-wg-ss', 'asia-extra-wg-ss.yaml'],
      ['wgGlobalExtra', 'global-extra-wg-ss', 'global-extra-wg-ss.yaml'],
    ];
    for (const [bucket, providerName, filename] of defs) {
      generatedProviders[providerName] = makeProvider(
        `${PROVIDER_ROOT}\\${filename}`,
        ssHot
      );
      ssBuckets[bucket].push(providerName);
    }
  }

  const ssCountryGroups = [];
  const ssCountryGroupByCode = new Map();

  if (ssOpenvpnEnabled) {
    for (const countryCode of SURFSHARK_COUNTRIES) {
      const providerName = `ov-ss-${countryCode.toLowerCase()}`;
      const hotCountry = PIA_HOT_COUNTRY_ORDER.includes(countryCode);
      generatedProviders[providerName] = makeProvider(
        `${PROVIDER_ROOT}\\${countryCode}\\surfshark-ov.yaml`,
        hotCountry ? ssHot : ssCold
      );
      ssOpenvpnByCountry.set(countryCode, providerName);

      const countryGroupName = `${flagEmoji(countryCode)} SS-${countryCode}(${countryZh(countryCode)})`;
      ssCountryGroupByCode.set(countryCode, countryGroupName);
      ssCountryGroups.push({
        name: countryGroupName,
        type: hotCountry ? 'fallback' : 'select',
        hidden: true,
        use: [providerName],
      });
    }
  }

  const orderedSsAsiaCodes = PIA_HOT_COUNTRY_ORDER.filter((code) => ASIA.has(code));
  const ssOvHlsGroups = orderedSsAsiaCodes
    .filter((code) => HLS.has(code))
    .map((code) => ssCountryGroupByCode.get(code))
    .filter(Boolean);
  const ssOvChinaGroups = orderedSsAsiaCodes
    .filter((code) => CHINA.has(code))
    .map((code) => ssCountryGroupByCode.get(code))
    .filter(Boolean);
  const ssOvAsiaExtraGroups = orderedSsAsiaCodes
    .filter((code) => ASIA_EXTRA.has(code))
    .map((code) => ssCountryGroupByCode.get(code))
    .filter(Boolean);
  const ssOvAsiaGroups = [
    ...ssOvHlsGroups,
    ...ssOvChinaGroups,
    ...ssOvAsiaExtraGroups,
  ];
  const ssOvAiGroups = [
    ...ssOvHlsGroups,
    ...ssOvAsiaExtraGroups,
  ];

  const ssWgAsiaProviders = [
    ...ssBuckets.hls,
    ...ssBuckets.china,
    ...ssBuckets.asiaExtra,
  ];
  const ssWgAiProviders = [
    ...ssBuckets.hls,
    ...ssBuckets.asiaExtra,
  ];

  const ssProviderNames = [
    ...ssWgAsiaProviders,
    ...ssBuckets.wgGlobalExtra,
  ];

  config['proxy-providers'] = { ...generatedProviders, ...baseProviders };

  const existingGroups = Array.isArray(config['proxy-groups']) ? config['proxy-groups'] : [];
  const baseGroups = existingGroups.filter((group) => {
    const isGeneratedEndpoint = group?.hidden === true && isPiaEndpointName(group?.name);
    return !isGeneratedEndpoint && !isManagedVendorGroupName(group?.name);
  });
  for (const group of baseGroups) {
    if (group && typeof group === 'object') cleanManagedRefs(group);
  }

  const piaAsia = endpointNames((endpoint) => endpoint.hot, availablePiaEndpointNames);
  const piaHls = endpointNames((endpoint) => HLS.has(countryCode(endpoint)), availablePiaEndpointNames);
  const piaAi = endpointNames(
    (endpoint) => endpoint.hot && !CHINA.has(countryCode(endpoint)),
    availablePiaEndpointNames
  );

  const automationPolicy = {
    'AUTO-FAST': {
      proxies: [...piaAsia, ...ssOvAsiaGroups],
      use: ssWgAsiaProviders,
    },
    'AUTO-SAFE': {
      proxies: [...piaAsia, ...ssOvAsiaGroups],
      use: ssWgAsiaProviders,
    },
    'LB-HLS': {
      proxies: [...piaHls, ...ssOvHlsGroups],
      use: ssBuckets.hls,
    },
    'LB-STICKY': {
      proxies: [...piaAsia, ...ssOvAsiaGroups],
      use: ssWgAsiaProviders,
    },
    'LB-ROBIN': {
      proxies: [...piaAsia, ...ssOvAsiaGroups],
      use: ssWgAsiaProviders,
    },
    'LB-CONSISTENT': {
      proxies: [...piaAsia, ...ssOvAsiaGroups],
      use: ssWgAsiaProviders,
    },
    'AI-PROXY': {
      proxies: [...piaAi, ...ssOvAiGroups],
      use: ssWgAiProviders,
    },
  };

  for (const group of baseGroups) {
    const policy = automationPolicy[group?.name];
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

    const hasSource = (Array.isArray(group.proxies) && group.proxies.length > 0) ||
      (Array.isArray(group.use) && group.use.length > 0);
    if (!hasSource) group.proxies = ['REJECT'];
  }

  const vendorGroups = [];
  if (availablePiaEndpointNames.size > 0) {
    vendorGroups.push({
      name: 'PIA-ALL',
      type: 'select',
      icon: `${ICON_ROOT}/PrivateInternetAccess.svg`,
      proxies: endpointNames(() => true, availablePiaEndpointNames),
    });
    for (const [regionName, countries, icon] of REGION_DEFS) {
      const members = piaRegionMembers(countries, availablePiaEndpointNames);
      if (members.length === 0) continue;
      vendorGroups.push({
        name: `PIA-${regionName}`,
        type: 'select',
        icon: `${ICON_ROOT}/${icon}`,
        proxies: members,
      });
    }
  }

  const hasSsOpenvpn = ssCountryGroups.length > 0;
  const hasSsWireguard = ssProviderNames.length > 0;
  if (hasSsOpenvpn || hasSsWireguard) {
    const ssAllGroup = {
      name: 'SS-ALL',
      type: 'select',
      icon: `${ICON_ROOT}/Surfshark.svg`,
    };
    const allProxies = SURFSHARK_COUNTRIES
      .map((code) => ssCountryGroupByCode.get(code))
      .filter(Boolean);
    if (allProxies.length > 0) ssAllGroup.proxies = allProxies;
    if (ssProviderNames.length > 0) ssAllGroup.use = [...ssProviderNames];
    vendorGroups.push(ssAllGroup);

    const asiaGroup = {
      name: 'SS-ASIA',
      type: 'select',
      icon: `${ICON_ROOT}/fluent-emoji-flat/japanese-castle.svg`,
    };
    if (ssOvAsiaGroups.length > 0) asiaGroup.proxies = [...ssOvAsiaGroups];
    if (ssWgAsiaProviders.length > 0) asiaGroup.use = [...ssWgAsiaProviders];
    if (asiaGroup.proxies || asiaGroup.use) vendorGroups.push(asiaGroup);

    for (const [regionName, countries, icon] of REGION_DEFS) {
      if (regionName === 'ASIA') continue;

      const group = {
        name: `SS-${regionName}`,
        type: 'select',
        icon: `${ICON_ROOT}/${icon}`,
      };

      const regionProxies = SURFSHARK_COUNTRIES
        .filter((code) => countries.has(code))
        .map((code) => ssCountryGroupByCode.get(code))
        .filter(Boolean);
      if (regionProxies.length > 0) group.proxies = regionProxies;

      if (ssBuckets.wgGlobalExtra.includes('global-extra-wg-ss')) {
        group.use = ['global-extra-wg-ss'];
        group.filter = flagFilter(countries);
      }

      if (group.proxies || group.use) vendorGroups.push(group);
    }
  }

  const activeVendorGroupNames = new Set(vendorGroups.map((group) => group.name));
  const routeGroupPolicy = {
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
    const candidates = routeGroupPolicy[group?.name];
    if (!candidates) continue;
    addProxies(group, candidates.filter((name) => activeVendorGroupNames.has(name)));
  }

  config['proxy-groups'] = [
    ...piaEndpointGroups,
    ...ssCountryGroups,
    ...baseGroups,
    ...vendorGroups,
  ];
  return config;
}
