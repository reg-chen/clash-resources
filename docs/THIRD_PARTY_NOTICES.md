# Third-party notices, data licenses and trademarks

本文件記錄 `reg-chen/clash-resources` 中**實際存放、由 Action 產生、執行時下載，或於 EXE 建置時打包**的第三方素材／程式。請以相應的**上游授權原文及特定發行版本**為準；這是來源與權利聲明，不是本 Repo 的統一開源授權，也不構成第三方對本專案的認可。

## Brand artwork and trademarks

本儲存庫的 `main` 分支已移除 `icons/` 根目錄下的品牌 SVG／PNG（Git 歷史可能仍包含先前版本）。配置中的品牌圖像直接引用第三方來源，**不在此儲存庫重新保存、鏡像或修改**。第三方託管不代表取得商標權；名稱、Logo、識別圖樣的權利仍屬各權利人。

| 配置識別 | 使用中的外部圖示 | 一致性查證與限制 |
| --- | --- | --- |
| Cloudflare（WARP-PROXY） | [Devicon / Cloudflare 原始 SVG](https://raw.githubusercontent.com/devicons/devicon/32fe1d3b3f36ad11f90ab94f7db59738139c2bf6/icons/cloudflare/cloudflare-original.svg) | 與移除前 `Cloudflare.svg` 的 SVG viewBox、三段 Path、填色完全一致；僅檔尾換行不同。Cloudflare [商標政策](https://www.cloudflare.com/trademark/) 對 Logo 用途有明確限制 |
| Private Internet Access（PIA-ALL） | [theSVG / PIA](https://raw.githubusercontent.com/glincker/thesvg/bec352dd80ed68c597d57f3aa599b40eb9ecd4ee/public/icons/private-internet-access/default.svg) | 與原圖具有相同 SVG Path、viewBox 與 `#1E811F`；僅填色屬性位置不同。圖示集合的開源聲明**不直接授予 PIA 商標權** |
| Surfshark（SS-ALL） | [theSVG / Surfshark](https://raw.githubusercontent.com/glincker/thesvg/bec352dd80ed68c597d57f3aa599b40eb9ecd4ee/public/icons/surfshark/default.svg) | 相同品牌符號與 `#1EBFBF` 填色，但上游 SVG 為簡化過的向量，**不是先前 SVG 的位元組／Path 精確副本**。官方[媒體使用政策](https://surfshark.com/press)限制商業用途、衍生作品等 |
| GitHub、OpenVPN、WARP 根目錄圖示 | 不再引用／不保留 | 既有品牌素材檔已自當前分支下架；商標與著作權分別適用官方政策：[GitHub](https://docs.github.com/en/site-policy/other-site-policies/github-logo-policy)、[OpenVPN](https://openvpn.net/legal/)、[Cloudflare](https://www.cloudflare.com/trademark/) |

**用途及風險邊界：** 以上外部圖示僅用於 Mihomo／Clash 策略群組的服務識別；它們並非本儲存庫作品，也不是品牌官方認可聲明。外部 URL 若被上游刪除、變更存取政策或遭網路阻擋，圖示顯示可能失效。Git 歷史、CDN 舊快取或既有第三方副本，不會因 `main` 刪除圖檔而自動全面消失。

## Third-party artwork

- `icons/fluent-emoji-flat/*.svg`：來源 [Microsoft Fluent UI Emoji](https://github.com/microsoft/fluentui-emoji)，經由 [Iconify Fluent Emoji Flat](https://icon-sets.iconify.design/fluent-emoji-flat/) 提供，**MIT License**，Copyright (c) Microsoft Corporation。
- SVG 會由 `tools/sync-fluent-emoji-flat.mjs` 比對與產生；品牌識別改由設定直接參照外部網址，**不屬於 Microsoft Fluent Emoji Flat 的 MIT 授權範圍**。
- 完整授權文字與來源：[FLUENT_EMOJI_ATTRIBUTION.md](FLUENT_EMOJI_ATTRIBUTION.md)。

<a id="third-party-rule-sources"></a>
## Third-party rule sources

`.github/workflows/update-third-party-mrs.yml` 透過 `tools/third-party-mrs-sources.json` 下載外部規則；`tools/build-third-party-mrs.py`、`tools/mrs_merge.py` 使用 Mihomo 轉成 MRS、依 security／privacy／ads 分類、正規化與合併部分規則，並把三份網域分類合併產物、一份安全 IPv4 合併產物 `security/mrs/combined-ip.mrs` 及 iOS 專用的獨立 `ads/mrs/antiad.mrs` 發布到 `rules/**/mrs/`；其他 20 份輸入只參與合併，不另行編譯或發布個別 MRS。**這是再散布經處理的第三方資料，而不是只有在本機查詢 API。**

| 上游 | 對應用途 | 上游授權 | 授權文字 |
| --- | --- | --- | --- |
| [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) | TIF Medium／Fake／DynDNS／TIF IPv4、Native Trackers、Popup Ads 等來源 | **GPL-3.0** | [GPL-3.0](licenses/GPL-3.0.txt) |
| [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) | `reject.txt` 廣告規則 | **GPL-3.0** | [GPL-3.0](licenses/GPL-3.0.txt) |
| [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) | Phishing domain／ACTIVE IPv4 feed | **MIT** | [原作者及 MIT 全文](licenses/MIT-Phishing.Database.txt) |
| [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) | Recommended Botnet C2 IPv4 feed | **CC0** | [服務條款 §3.4](https://abuse.ch/terms-of-use/)、[CC0 全文](https://creativecommons.org/publicdomain/zero/1.0/legalcode) |
| [anti-AD](https://github.com/privacy-protection-tools/anti-AD) | `anti-ad-clash.yaml` 廣告規則 | **MIT** | [原作者及 MIT 全文](licenses/MIT-anti-AD.txt) |

目前的合併 MRS 可能同時包含 GPL-3.0 與 MIT 上游規則及本地自訂項目；不能把整組輸出簡單標為 MIT。**GPL-3.0 涵蓋來源的修改／再散布必須遵循 GPL-3.0**；MIT 來源亦須保留其著作權及授權告知。合併後的法律邊界需依實際內容判斷，而不是因此自動認定同一 Repo 下所有獨立檔案都採 GPL。

**修改聲明：** 本專案使用腳本自動下載、擷取網域、過濾不能轉換的格式、分類／去重／合併並以 Mihomo 編譯為 `.mrs`，屬於對原始規則的格式轉換及編輯（2026 年起持續更新）。原始來源清單見 [third-party-mrs-sources.json](../tools/third-party-mrs-sources.json)，建置程序見 [MRS workflow](../.github/workflows/update-third-party-mrs.yml)、[build script](../tools/build-third-party-mrs.py)、[merge script](../tools/mrs_merge.py)。

**來源追溯機制：** MRS 建置先解析上游 GitHub commit，再從該 commit 對應的固定 Raw URL 下載原始輸入。Action 將 [來源追溯清單](../tools/third-party-mrs-provenance.json) **與當前原始來源及 MRS 產物放進同一個 commit**；清單包含原始 URL、固定版本 URL、上游 Commit 頁面、Commit SHA、當前來源檔路徑與 SHA-256、對應輸出路徑（`output_paths`）與實際發布產物 SHA-256。來源內容未變時不重寫舊檔案，避免每小時無謂提交。Feodo 為非 Git 版控即時來源，保存原始 URL、完整回應與 SHA-256，不捏造上游 commit 或固定 URL；同一 Repo commit 提供可重建的快照。IPv4 僅接受單一公網位址，排除非全球可路由位址後轉為 /32、去重合併。Feodo 合法空清單可接受，但格式或下載失敗不發布新產物。

**目前版本的原始來源：** 每次下載的 20 份第三方輸入檔會以**原始位元組**保存於 [sources/mrs/](../sources/mrs/)，並由相同輸入檔分類合併後轉換為 MRS；僅 anti-AD 另有獨立 MRS。Action 驗證檔案雜湊後，將來源檔、來源 commit 連結、追溯清單與編譯產物在**同一個 Git Commit** 發布。已淘汰的個別 MRS 不再於當前分支提供，舊版設定若仍使用其 URL 須更新。檔案以固定名稱覆蓋更新，不另建 Release、Tag 或逐次歷史封存。Git 歷史可能包含舊版，但不是額外維護的來源封存服務；倘若將來重建儲存庫，應先確認仍對外提供的舊版產物是否具有相應來源。

**授權邊界：** 保存本次下載輸入，有助於滿足可驗證的來源交付；但仍須依第三方作品實際 GPL 適用情況，確認「對應來源」是否還包含其他上游建置腳本、修改資訊或必要元件。

## Tools, build dependencies and downloaded inputs

以下依實際用途區分，避免誤稱執行時向第三方取得的程式都「已包含在本 Repo」。

| 專案／服務 | 使用位置與方式 | 來源及授權／權利狀態 |
| --- | --- | --- |
| [Mihomo](https://github.com/MetaCubeX/mihomo) | MRS Action 於建置時下載 Linux release，使用 `convert-ruleset`；**此工作流程不把 Linux Mihomo binary 加入 Repo** | 上游核心 **GPL-3.0**（非 MIT）；本專案僅在 CI 下載並執行上游 binary，不把該 binary 加入 Repo。若另行重新散布 binary，須履行適用的 GPL 授權義務與來源告知 |
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
- 外部品牌圖示僅提供使用來源，不宣稱因此取得相關商標／著作權人許可。
- 本文件僅整理已辨識的直接來源；Python／Node 套件及其**轉依賴**可能還有額外授權，正式散布二進位成果時應依實際安裝版本核對 third-party notices／SBOM。
- 本 Repo 的自行編寫檔案沒有因列出其他程式的 MIT、LGPL 或 GPL 而自動統一授權；請勿把第三方授權當作本 Repo 的根目錄 `LICENSE`。
