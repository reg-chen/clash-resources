# clash-resources

個人使用的 Mihomo／Clash 設定、分流規則、圖示與輔助工具。

## 第三方素材、授權與商標

本儲存庫包含自行維護的設定與工具，也引用或重新發布不同授權的第三方素材。**請依資源類別分別適用其原始授權；本聲明不代表整個儲存庫均採 MIT 或 GPL。**

- **完整第三方聲明**：[第三方素材、相依套件與商標](docs/THIRD_PARTY_NOTICES.md) — 涵蓋品牌圖示、規則來源、下載型建置工具、Windows EXE 相依套件，以及相應授權注意事項。
- **Fluent Emoji Flat**：`icons/fluent-emoji-flat/` 來自 [Microsoft Fluent UI Emoji](https://github.com/microsoft/fluentui-emoji)，透過 [Iconify](https://icon-sets.iconify.design/fluent-emoji-flat/) 取得；採 **MIT License**。原作者及完整授權條款見 [Fluent Emoji 聲明](docs/FLUENT_EMOJI_ATTRIBUTION.md)。
- **第三方規則**：自動整合來源包含 **GPL-3.0** 的 HaGeZi、Loyalsoldier，以及 **MIT** 的 Phishing.Database、anti-AD。規則經轉換、分類或合併後發布，請見[規則來源與授權說明](docs/THIRD_PARTY_NOTICES.md#third-party-rule-sources)。
- **品牌圖示／商標**：GitHub、Cloudflare／WARP、Private Internet Access、Surfshark、OpenVPN 等名稱及相關標誌權利歸各自權利人；使用並不表示其對本儲存庫有任何贊助、合作或認可，也**不表示**這些品牌圖示獲得 MIT 授權。
- **Windows GUI／EXE**：現行版本採 **CustomTkinter 6.0.0（MIT）** 與 Tkinter／Tcl/Tk，使用 PyInstaller `--onefile` 建置；Pillow、cryptography 等隨附依賴仍適用各自授權。過去曾使用 PySide6／Qt、ttkbootstrap；**舊版 EXE Artifact 已清理，目前只提供 CustomTkinter 版**。詳見第三方聲明。
- **UWP Loopback**：僅備份 Windows UWP Loopback／WinConfig 已勾選的 AppContainer 豁免；還原時逐項預覽與勾選，未安裝的 App 跳過、已存在的豁免保留，不修改其他 Windows 防火牆規則。**JSON Schema 2 使用 Package Family Name（PFN）與 AppContainer 名稱辨識 App，不保存來源 SID；重灌／換電腦後會重新查詢目標 SID。** 舊 Schema 1 可讀，但缺少可辨識名稱的項目不會自動還原。先前的一般防火牆規則 JSON 不適用此功能。 **備份／還原須由目前登入的 Windows 帳號本身具備管理員身分；其中備份還須先以同一帳號提升程式權限，不支援標準使用者借用其他管理員帳號的 UAC 認證。** 還原時會核對提升權限前後的 Windows 使用者 SID，若發生帳號切換即中止，不會誤以另一個管理員帳號的 App 清單判斷安裝狀態。

## MRS Action 觸發規則

`.github/workflows/update-third-party-mrs.yml` 僅在 `main` 的 MRS 來源／建置／相關測試檔變更時由 push 觸發；另保留每小時 UTC 第 32 分的排程與 **Owner-only `workflow_dispatch`**。一般 EXE 或 README 修改不會啟動 MRS Action。先前的 `build: refresh mrs` 空 commit 及 `mrs-refresh-*` Tag 觸發均已停用。

需要自行補跑時，前往 [Update third-party MRS Actions](https://github.com/reg-chen/clash-resources/actions/workflows/update-third-party-mrs.yml)，選擇 **Run workflow**，指定 `main` 後執行；GPT 排程僅檢查 cron 健康狀態並提醒，不會代為觸發或修改儲存庫。

**僅使用本儲存庫的程式碼，與重新散布第三方規則、圖示或包含第三方函式庫的執行檔，授權義務並不相同。**

**下載範圍**：`rules/**/mrs/` 透過公開 GitHub／CDN 供 Mihomo 更新，不設 Owner-only；Windows EXE 僅保存於 Actions Artifact（未建立 Release），但本 Repo 為公開，因此 Artifact **不是 Owner-only**。限制 `workflow_dispatch` 的執行者，只限制誰能觸發建置，不限制其他具有 Repo 讀取權限的人下載成果。詳見[存取與散布說明](docs/THIRD_PARTY_NOTICES.md#distribution-access)。
