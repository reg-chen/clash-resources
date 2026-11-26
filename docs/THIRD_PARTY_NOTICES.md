# Third-party notices, licenses and trademarks

## 1. 適用範圍

1.1 本聲明適用於 `reg-chen/clash-resources` 引用、下載、修改、整合或散布之第三方資料、程式及素材。

1.2 第三方作品依其各自授權及適用版本之原文使用；著作權及其他權利歸各權利人所有。本聲明不構成本儲存庫之統一授權，亦不擴張原授權所授予之權利。

<a id="third-party-rule-sources"></a>
## 2. 規則資料

| 上游 | 用途 | 授權 | 授權原文 |
| --- | --- | --- | --- |
| [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) | TIF Medium／Fake／DynDNS／TIF IPv4、Native Trackers、Popup Ads 等來源 | **GPL-3.0** | [GPL-3.0](licenses/GPL-3.0.txt) |
| [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) | `reject.txt` 廣告規則 | **GPL-3.0** | [GPL-3.0](licenses/GPL-3.0.txt) |
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) | Phishing domain／ACTIVE IPv4 feed | **MIT** | [原作者及 MIT 全文](licenses/MIT-Phishing.Database.txt) |
| [MetaMask eth-phishing-detect](https://github.com/MetaMask/eth-phishing-detect) | `src/config.json` Web3 phishing explicit domain blocklist | **DBAD v1.2** | [原作者及完整授權](licenses/DBAD-1.2-MetaMask.txt) |
| [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) | Recommended Botnet C2 IPv4 feed | **CC0** | [服務條款 §3.4](https://abuse.ch/terms-of-use/)、[CC0 全文](https://creativecommons.org/publicdomain/zero/1.0/legalcode) |
| [anti-AD](https://github.com/privacy-protection-tools/anti-AD) | `anti-ad-clash.yaml` 廣告規則 | **MIT** | [原作者及 MIT 全文](licenses/MIT-anti-AD.txt) |

2.1 本專案以非營利方式整合及免費散布規則資料。自 2026 年起對上游資料進行格式轉換、擷取、篩選、正規化、分類、去重、合併及 MRS 編譯；經處理之產物不代表上游原始版本。

2.2 GPL-3.0 涵蓋之資料及其適用衍生作品依 GPL-3.0 散布；MIT、DBAD v1.2 等來源保留原授權及著作權告知。不得僅因資料合併而將其他來源擅自重新授權，亦不得以本聲明限制 GPL-3.0 所保障之權利。

2.3 MetaMask 資料（Copyright (C) 2018 kumavis）適用 DBAD v1.2。僅擷取明確封鎖網域，排除自身允許清單涵蓋項目，不納入模糊比對或擴張至子網域。其與 GPL-3.0 之衍生作品授權相容性尚未確認；如有權利異議，將評估獨立散布、調整或停止散布。

2.4 對應來源及修改資訊：

- [原始來源登錄](../tools/third-party-mrs-sources.json)｜[來源追溯及 SHA-256](../tools/third-party-mrs-provenance.json)
- [原始位元組快照](../sources/mrs/)｜[公開 MRS 產物](../rules/)
- [建置流程](../.github/workflows/update-third-party-mrs.yml)｜[建置腳本](../tools/build-third-party-mrs.py)｜[合併腳本](../tools/mrs_merge.py)

原始輸入、來源版本、雜湊及產物隨建置結果一併提交；無固定上游版本之即時來源以原始回應及雜湊識別。GPL 所要求之對應來源，依其適用範圍提供，並不限於原始規則快照。

<a id="brand-artwork-and-trademarks"></a>
<a id="third-party-artwork"></a>
## 3. 圖像及商標

| 來源／權利人 | 使用方式 | 授權／權利聲明 |
| --- | --- | --- |
| [Microsoft Fluent UI Emoji](https://github.com/microsoft/fluentui-emoji)（經 [Iconify](https://icon-sets.iconify.design/fluent-emoji-flat/)） | `icons/fluent-emoji-flat/` | MIT；Copyright (c) Microsoft Corporation；[完整授權與歸屬](FLUENT_EMOJI_ATTRIBUTION.md) |
| [Cloudflare](https://raw.githubusercontent.com/devicons/devicon/32fe1d3b3f36ad11f90ab94f7db59738139c2bf6/icons/cloudflare/cloudflare-original.svg)（Devicon） | 外部引用 | [商標政策](https://www.cloudflare.com/trademark/) |
| [Private Internet Access](https://raw.githubusercontent.com/glincker/thesvg/bec352dd80ed68c597d57f3aa599b40eb9ecd4ee/public/icons/private-internet-access/default.svg)（theSVG） | 外部引用 | 商標權歸其權利人 |
| [Surfshark](https://raw.githubusercontent.com/glincker/thesvg/bec352dd80ed68c597d57f3aa599b40eb9ecd4ee/public/icons/surfshark/default.svg)（theSVG） | 外部引用 | [媒體使用政策](https://surfshark.com/press) |

3.1 品牌圖像僅供服務識別，現行配置直接引用外部來源，不另行鏡像或修改。圖像之著作權授權不當然包含商標使用權；本專案不主張任何第三方商標權、代理關係、贊助或官方認可。

3.2 已移除之素材可能仍存在於 Git 歷史或第三方快取；移除現行檔案不代表既有副本已撤回。

<a id="tools-build-dependencies-and-downloaded-inputs"></a>
## 4. 程式及服務

| 專案／服務 | 使用方式 | 授權／條款 |
| --- | --- | --- |
| [Mihomo](https://github.com/MetaCubeX/mihomo) | CI 下載並執行；不散布其執行檔 | GPL-3.0 |
| [Iconify Utils](https://www.npmjs.com/package/@iconify/utils)／[@iconify-json/fluent-emoji-flat](https://www.npmjs.com/package/@iconify-json/fluent-emoji-flat) | CI 建置圖像；不散布 node_modules | MIT |
| [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) | EXE GUI | MIT；Copyright (c) 2023 Tom Schimansky；[授權原文](https://github.com/TomSchimansky/CustomTkinter/blob/master/LICENSE) |
| [Python／Tkinter／Tcl/Tk](https://www.tcl-lang.org/software/tcltk/license.html) | EXE runtime | 各版本所附授權 |
| [Pillow](https://github.com/python-pillow/Pillow) | GUI 依賴 | HPND／MIT-CMU 類型；依實際版本 |
| [PyInstaller](https://pyinstaller.org/en/stable/license.html) | EXE 打包 | GPL-2.0 with special exception；部分 Apache-2.0 |
| [cryptography](https://github.com/pyca/cryptography) | 憑證及 GUI 依賴 | Apache-2.0 OR BSD-3-Clause |
| [PIA manual-connections](https://github.com/pia-foss/manual-connections) | CA 憑證、API 與配置 | MIT（上游專案）；服務另依其條款 |
| [Surfshark](https://surfshark.com/) | 本機匯入官方配置 | 服務條款；不散布官方 ZIP |
| [Cloudflare WARP](https://one.one.one.one/) | API 註冊及本機配置 | 服務及 API 條款 |
| [GitHub Actions](https://github.com/actions)／[jsDelivr](https://www.jsdelivr.com/) | CI、CDN | 各元件授權及服務條款 |

4.1 執行時下載或呼叫第三方服務，不代表取得其程式、配置、帳號或服務的再散布權。

4.2 EXE 依實際建置版本收集直接及轉依賴之 LICENSE、COPYING、NOTICE，封裝於 `EXE_THIRD_PARTY_LICENSES.generated.txt`，並於 GUI 提供閱覽。以實際封裝內容及授權原文為準；PyInstaller 打包例外不免除其他依賴之授權義務。

<a id="distribution-access"></a>
## 5. 散布及存取

5.1 MRS 及其來源透過公開儲存庫、GitHub Raw 或 CDN 散布，適用相關來源之授權義務。

5.2 Windows EXE 透過 [GitHub Actions Artifact](../.github/workflows/build-vpn-generator.yml) 散布，非 GitHub Release。依 [GitHub 存取規則](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts)，具有讀取權限之登入使用者可下載；僅限制 Owner 觸發建置不構成下載權限限制。

5.3 本聲明為第三方來源及權利告知，不取代適用之授權原文、服務條款或依法應履行之其他義務。
