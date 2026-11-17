# Third-party notices, data licenses and trademarks

本文件記錄 `reg-chen/clash-resources` 中**實際存放、由 Action 產生、執行時下載，或於 EXE 建置時打包**的第三方素材／程式。請以相應的**上游授權原文及特定發行版本**為準；這是來源與權利聲明，不是本 Repo 的統一開源授權，也不構成第三方對本專案的認可。

## Brand artwork and trademarks

下列名稱及相關商標、標誌、圖樣的權利歸各自權利人。本儲存庫只是用作個人 Mihomo／Clash 設定中的供應商或服務識別，不宣稱權利移轉、官方授權、合作、認可或背書。

| 儲存庫中的檔案 | 對應名稱／權利歸屬 | 參考來源 |
| --- | --- | --- |
| `icons/GitHub.svg`, `icons/GitHub-Invertocat.svg` | GitHub、Octocat／Invertocat | [GitHub](https://github.com/)、[GitHub Logos and Usage](https://github.com/logos) |
| `icons/Cloudflare.svg`, `icons/WARP-Cloudflare.svg`, `icons/WARP.svg` | Cloudflare、Cloudflare WARP | [Cloudflare](https://www.cloudflare.com/)、[Cloudflare WARP](https://one.one.one.one/) |
| `icons/PrivateInternetAccess.svg` | Private Internet Access (PIA) | [PIA](https://www.privateinternetaccess.com/) |
| `icons/Surfshark.svg` | Surfshark | [Surfshark](https://surfshark.com/) |
| `icons/OpenVPN.png` | OpenVPN | [OpenVPN](https://openvpn.net/) |

### 官方品牌規範（核對於 2026-11-17）

| 品牌 | 官方資料 | 對目前公開圖示的限制與證據 |
| --- | --- | --- |
| GitHub／Invertocat | [GitHub 品牌指南](https://brand.github.com/foundations/logo)、[Logo Policy](https://docs.github.com/en/site-policy/other-site-policies/github-logo-policy) | 允許特定辨識 GitHub、指向服務或顯示整合的用途；禁止將 Logo 當作自家產品識別、任意修改或暗示 GitHub 背書；目前個別檔案未核對來源 |
| Cloudflare／WARP | [Cloudflare 商標使用規範](https://www.cloudflare.com/trademark/) | 官方對一般 Cloudflare Logo 使用原則上要求**事先書面許可**；文字描述與特定 Web badge 的例外不等於 Logo 再散布許可 |
| Surfshark | [Surfshark 媒體中心](https://surfshark.com/press) | 提供官方素材，容許個人或非商業下載／複製，限制修改、衍生、販售及商業使用；須先確認目前 SVG 與官方素材一致 |
| PIA | [PIA 媒體素材](https://www.privateinternetaccess.com/press-page)、[使用條款](https://www.privateinternetaccess.com/terms-of-service) | 有官方素材頁，但**未確認可任意公開再散布或修改**的授權 |
| OpenVPN | [OpenVPN 品牌素材](https://openvpn.net/branding/)、[商標條款](https://openvpn.net/legal/) | OpenVPN 程式的 GPL 不授權其商標；其鑰匙孔標誌等依官方條款需預先取得書面許可，並限制更動圖像 |

此表僅記錄**官方可核對的規範**，不代表目前的檔案已逐項取得授權。公開儲存庫及 CDN 可供第三人下載，與本地使用作為個人 VPN 分流識別不同。對未經核實的品牌圖檔，應核對實際來源、是否經修改及官方允許範圍；必要時改用純文字服務名稱或取得書面許可。

**重要：** 現有檔案未附足以確認各圖示最初下載位置／單一檔案再散布授權的來源紀錄。因此，上表識別的是品牌與參考官方網站，**不是已驗證取得商標或圖示重製授權的證明**。商標聲明也不能取代權利人可能要求的使用許可。若將圖示用於公開發行、商業使用、或品牌識別，應另外核對各品牌的使用規範。檔名 `WARP-Cloudflare.svg` 不表示這是 Cloudflare 官方核准的 WARP 專用標誌。

## Third-party artwork

- `icons/fluent-emoji-flat/*.svg`：來源 [Microsoft Fluent UI Emoji](https://github.com/microsoft/fluentui-emoji)，經由 [Iconify Fluent Emoji Flat](https://icon-sets.iconify.design/fluent-emoji-flat/) 提供，**MIT License**，Copyright (c) Microsoft Corporation。
- SVG 會由 `tools/sync-fluent-emoji-flat.mjs` 比對與產生；`icons/` 根目錄的品牌圖示**不包含**在此 MIT 授權聲明中。
- 完整授權文字與來源：[FLUENT_EMOJI_ATTRIBUTION.md](FLUENT_EMOJI_ATTRIBUTION.md)。

<a id="third-party-rule-sources"></a>
## Third-party rule sources

`.github/workflows/update-third-party-mrs.yml` 透過 `tools/third-party-mrs-sources.json` 下載外部規則；`tools/build-third-party-mrs.py`、`tools/mrs_merge.py` 使用 Mihomo 轉成 MRS、依 security／privacy／ads 分類、正規化與合併部分規則，並把產物發布到 `rules/**/mrs/`。**這是再散布經處理的第三方資料，而不是只有在本機查詢 API。**

| 上游 | 對應用途 | 上游授權 | 授權文字 |
| --- | --- | --- | --- |
| [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) | Threat／DynDNS、Native Trackers、Popup Ads 等來源 | **GPL-3.0** | [GPL-3.0](licenses/GPL-3.0.txt) |
| [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) | `reject.txt` 廣告規則 | **GPL-3.0** | [GPL-3.0](licenses/GPL-3.0.txt) |
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) | Phishing domain feed | **MIT** | [原作者及 MIT 全文](licenses/MIT-Phishing.Database.txt) |
| [anti-AD](https://github.com/privacy-protection-tools/anti-AD) | `anti-ad-clash.yaml` 廣告規則 | **MIT** | [原作者及 MIT 全文](licenses/MIT-anti-AD.txt) |

目前的合併 MRS 可能同時包含 GPL-3.0 與 MIT 上游規則及本地自訂項目；不能把整組輸出簡單標為 MIT。**GPL-3.0 涵蓋來源的修改／再散布必須遵循 GPL-3.0**；MIT 來源亦須保留其著作權及授權告知。合併後的法律邊界需依實際內容判斷，而不是因此自動認定同一 Repo 下所有獨立檔案都採 GPL。

**修改聲明：** 本專案使用腳本自動下載、擷取網域、過濾不能轉換的格式、分類／去重／合併並以 Mihomo 編譯為 `.mrs`，屬於對原始規則的格式轉換及編輯（2026 年起持續更新）。原始來源清單見 [third-party-mrs-sources.json](../tools/third-party-mrs-sources.json)，建置程序見 [MRS workflow](../.github/workflows/update-third-party-mrs.yml)、[build script](../tools/build-third-party-mrs.py)、[merge script](../tools/mrs_merge.py)。

**來源追溯機制：** MRS 建置先解析各上游 GitHub commit，再下載該 commit 對應的固定 Raw URL。每次更新時，Action 將 [來源追溯清單](../tools/third-party-mrs-provenance.json) **與 MRS 產物放進同一個 commit**；清單包含原始 URL、固定版本 URL、上游 commit SHA、原始檔 SHA-256／位元組數與產物 SHA-256。未變更的來源會保留原本驗證過的固定版本，避免每小時無謂提交。

**GPL 對應來源的剩餘風險：** 固定 URL 和 SHA-256 能追溯版本，卻不能保證第三方 GitHub 儲存庫永久可取用。若適用 GPL-3.0 的「對應來源」交付義務，**僅有雜湊及連結未必充分**；仍應評估保存原始輸入快照或其他可持續提供相同來源的方式。

## Tools, build dependencies and downloaded inputs

以下依實際用途區分，避免誤稱執行時向第三方取得的程式都「已包含在本 Repo」。

| 專案／服務 | 使用位置與方式 | 來源及授權／權利狀態 |
| --- | --- | --- |
| [Mihomo](https://github.com/MetaCubeX/mihomo) | MRS Action 於建置時下載 Linux release，使用 `convert-ruleset`；**此工作流程不把 Linux Mihomo binary 加入 Repo** | 上游 **MIT**；若另行重新散布 binary 須留意其實際套件所含授權及告知 |
| [Iconify Utils](https://www.npmjs.com/package/@iconify/utils)／[@iconify-json/fluent-emoji-flat](https://www.npmjs.com/package/@iconify-json/fluent-emoji-flat) | SVG Action 的 `npm install` 安裝於 Runner，轉換並提交 SVG；**不提交 node_modules** | 工具及圖示資料為 **MIT**；產出圖示另見 Microsoft 授權 |
| [CustomTkinter 6](https://github.com/TomSchimansky/CustomTkinter) | 現行 Windows GUI：`customtkinter==6.0.0`，隨 EXE 打包 | **MIT**，Copyright (c) 2023 Tom Schimansky；依 [上游 LICENSE](https://github.com/TomSchimansky/CustomTkinter/blob/master/LICENSE) 保留授權與著作權告知 |
| [Tkinter／Tcl/Tk](https://www.tcl-lang.org/software/tcltk/license.html) | Python GUI 介面與 Windows 上的 Tcl/Tk runtime | Tcl/Tk 寬鬆自由軟體授權，請核對打包版本包含的原始授權及歸屬 |
| [Pillow](https://pypi.org/project/pillow/) | CustomTkinter 的圖像依賴，可能打包於 Windows EXE | **HPND／MIT-CMU 類型**，依當次實際發行套件 LICENSE 為準，保留必要歸屬 |
| [PyInstaller](https://pyinstaller.org/en/stable/license.html) | 將 Python GUI 與其函式庫打包成 EXE | **GPL-2.0 with special exception**，部分檔案 Apache-2.0；官方例外允許產物採不同授權，不要求單為 PyInstaller 加入其授權檔，但其**相依函式庫**授權仍須遵守 |
| [Python cryptography](https://pypi.org/project/cryptography/) | 本地 DoH 憑證及相關 GUI 功能，並打包至 EXE | **Apache-2.0 OR BSD-3-Clause**；發行 EXE 時應核對打包相依套件所需的授權、歸屬／NOTICE |
| [PIA manual-connections](https://github.com/pia-foss/manual-connections) | `pia-wireguard-generator.py` 下載其 CA certificate 並呼叫 PIA API；另有 PIA OpenVPN profiles 作為產生設定的輸入 | 上游手動連線專案 **MIT**；PIA 的服務、API、帳號及連線設定不因此全面取得 MIT 授權，仍受服務條款約束 |
| [Surfshark](https://surfshark.com/) | `surfshark-openvpn-generator.py` 處理使用者取得的官方 OpenVPN ZIP | 服務與配置檔的再散布權利**未由本次審核確認**；本 Repo 不將該 ZIP 直接存放於來源樹 |
| [Cloudflare WARP](https://one.one.one.one/) | `warp-wireguard-generator.py` 透過 Cloudflare API 註冊並產生本機 WireGuard 設定 | 屬第三方服務/API，**不因呼叫 API 而取得程式或服務的 MIT 再散布授權** |
| [GitHub Actions](https://github.com/actions)、[jsDelivr](https://www.jsdelivr.com/) | CI 工作流程／CDN 清除和驗證 | 工作流程中引用第三方 CI 元件與線上服務，不代表將其完整程式碼重新散布於 Repo；各元件仍適用自己的授權／服務條款 |

**EXE 內建授權聲明：** Windows 建置 Action 會從當次實際安裝的 Python 套件及其轉依賴收集 LICENSE／COPYING／NOTICE 文字，並將可用的 Python／Tcl/Tk 授權文件一併封裝為 `EXE_THIRD_PARTY_LICENSES.generated.txt`；使用者可於 GUI 的「授權聲明」分頁閱讀。主要 runtime 套件缺少授權全文時，授權收集步驟會讓建置失敗，避免只發佈空泛的授權名稱；其餘未發現的授權檔仍須依實際版本核對。

**GUI 歷史註記：** 曾使用 PySide6／Qt（LGPL-3.0）與 ttkbootstrap；**舊版 EXE Artifact 已清理，現行建置與下載產物均不包含這些 GUI 套件**。

<a id="distribution-access"></a>
## Distribution surfaces and access control

- **MRS：公開散布。** `rules/**/mrs/` 的輸出會提交到此公開儲存庫，並供 GitHub Raw／jsDelivr 或其他 CDN 下載；不能因為未建立 GitHub Release，就視為私下自用的資料。MRS 應保持公開，否則 Mihomo 的遠端更新／無認證下載流程將無法正常使用。相關上游的授權、歸屬及對應來源義務仍需履行。
- **Windows EXE：GitHub Actions Artifact，不是 GitHub Release。** [目前的建置 Workflow](../.github/workflows/build-vpn-generator.yml) 將 EXE 以 Artifact 保存 30 天，並刪除較舊版本。但這是公開 Repo，**Artifact 的下載不是 Owner-only**：GitHub 允許已登入且具有儲存庫讀取權限的使用者下載 Workflow Artifact。詳見 [GitHub 官方下載文件](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts)。
- Workflow 的 `github.actor == github.repository_owner` 判斷只限制手動觸發者，不是 Artifact 的存取控制；刪除過期或舊版 Artifact 也不能追回已被下載的副本。若必須只有 Owner 能取得 EXE，需把**建置成果儲存在私人儲存庫或真正具授權控管的私人位置**，或不將可執行成果上傳公開 Repo；不需要因此將 MRS 設為私人。
- **授權告知不等於已履行所有散布義務。** 對目前提供下載的 CustomTkinter EXE，仍須依實際打包的 Python／Tcl/Tk 函式庫版本保留必要授權與著作權告知；對公開 MRS，仍須確認可取得適用授權要求的原始規則及修改內容。

## Scope and non-endorsement

- 商標標誌與著作權是不同問題：**標誌檔案即使能依某份開源授權使用，也不代表取得商標上的背書或識別使用權**。
- 對未驗證個別 SVG／PNG 原始下載網址及授權的品牌圖示，不宣稱「已取得商標／著作權人許可」。
- 本文件僅整理已辨識的直接來源；Python／Node 套件及其**轉依賴**可能還有額外授權，正式散布二進位成果時應依實際安裝版本核對 third-party notices／SBOM。
- 本 Repo 的自行編寫檔案沒有因列出其他程式的 MIT、LGPL 或 GPL 而自動統一授權；請勿把第三方授權當作本 Repo 的根目錄 `LICENSE`。
