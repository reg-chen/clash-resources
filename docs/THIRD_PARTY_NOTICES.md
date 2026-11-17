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

**待釐清的散布義務：** 目前提供上游 URL、腳本與 GPL 授權全文，但不保證每份已發布 MRS 均可由上述動態 URL 還原到當時完全相同的來源版本。若要確保符合 GPL-3.0 對對應來源及修改內容的要求，仍應評估為發行版本保留可重建的原始輸入快照或等效來源交付方式；這不能單靠 README 聲明取代。

## Tools, build dependencies and downloaded inputs

以下依實際用途區分，避免誤稱執行時向第三方取得的程式都「已包含在本 Repo」。

| 專案／服務 | 使用位置與方式 | 來源及授權／權利狀態 |
| --- | --- | --- |
| [Mihomo](https://github.com/MetaCubeX/mihomo) | MRS Action 於建置時下載 Linux release，使用 `convert-ruleset`；**此工作流程不把 Linux Mihomo binary 加入 Repo** | 上游 **MIT**；若另行重新散布 binary 須留意其實際套件所含授權及告知 |
| [Iconify Utils](https://www.npmjs.com/package/@iconify/utils)／[@iconify-json/fluent-emoji-flat](https://www.npmjs.com/package/@iconify-json/fluent-emoji-flat) | SVG Action 的 `npm install` 安裝於 Runner，轉換並提交 SVG；**不提交 node_modules** | 工具及圖示資料為 **MIT**；產出圖示另見 Microsoft 授權 |
| [PySide6 / Qt for Python](https://pypi.org/project/PySide6/) | [Windows EXE workflow](../.github/workflows/build-vpn-generator.yml) 會安裝並透過 PyInstaller 打包至 `VPN-Mihomo-Generator.exe` | 開源選項為 **LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only**（依使用元件與適用選項）；參考 [Qt LGPL Obligations](https://www.qt.io/development/open-source-lgpl-obligations) |
| [PyInstaller](https://pyinstaller.org/en/stable/license.html) | 將 Python GUI 與其函式庫打包成 EXE | **GPL-2.0 with special exception**，部分檔案 Apache-2.0；官方例外允許產物採不同授權，不要求單為 PyInstaller 加入其授權檔，但其**相依函式庫**授權仍須遵守 |
| [Python cryptography](https://pypi.org/project/cryptography/) | 本地 DoH 憑證及相關 GUI 功能，並打包至 EXE | **Apache-2.0 OR BSD-3-Clause**；發行 EXE 時應核對打包相依套件所需的授權、歸屬／NOTICE |
| [PIA manual-connections](https://github.com/pia-foss/manual-connections) | `pia-wireguard-generator.py` 下載其 CA certificate 並呼叫 PIA API；另有 PIA OpenVPN profiles 作為產生設定的輸入 | 上游手動連線專案 **MIT**；PIA 的服務、API、帳號及連線設定不因此全面取得 MIT 授權，仍受服務條款約束 |
| [Surfshark](https://surfshark.com/) | `surfshark-openvpn-generator.py` 處理使用者取得的官方 OpenVPN ZIP | 服務與配置檔的再散布權利**未由本次審核確認**；本 Repo 不將該 ZIP 直接存放於來源樹 |
| [Cloudflare WARP](https://one.one.one.one/) | `warp-wireguard-generator.py` 透過 Cloudflare API 註冊並產生本機 WireGuard 設定 | 屬第三方服務/API，**不因呼叫 API 而取得程式或服務的 MIT 再散布授權** |
| [GitHub Actions](https://github.com/actions)、[jsDelivr](https://www.jsdelivr.com/) | CI 工作流程／CDN 清除和驗證 | 工作流程中引用第三方 CI 元件與線上服務，不代表將其完整程式碼重新散布於 Repo；各元件仍適用自己的授權／服務條款 |

**Windows EXE／Qt LGPL 特別注意：** Repo 中的授權說明只能提供歸屬，**不等於 EXE 已滿足 LGPL**。若將包含 PySide6／Qt 的 EXE 提供下載，仍須依實際打包版本與模式評估：附上必要授權條款及告知、提供對應 Qt 原始碼或合格的書面提供方式，以及讓使用者能替換／重新連結 LGPL 函式庫並運行修改後程式的能力。特別是 PyInstaller `--onefile` 的實際部署方式，不能僅靠「附上連結」認定符合要求。參見 [Qt 官方義務說明](https://www.qt.io/development/open-source-lgpl-obligations)。

## Scope and non-endorsement

- 商標標誌與著作權是不同問題：**標誌檔案即使能依某份開源授權使用，也不代表取得商標上的背書或識別使用權**。
- 對未驗證個別 SVG／PNG 原始下載網址及授權的品牌圖示，不宣稱「已取得商標／著作權人許可」。
- 本文件僅整理已辨識的直接來源；Python／Node 套件與 Qt 內含的**轉依賴**可能還有額外授權，正式散布二進位成果時應由實際安裝版本產生完整的 third-party notices / SBOM。
- 本 Repo 的自行編寫檔案沒有因列出其他程式的 MIT、LGPL 或 GPL 而自動統一授權；請勿把第三方授權當作本 Repo 的根目錄 `LICENSE`。
