# clash-resources

## 授權、第三方素材與商標聲明

本儲存庫包含自行維護的程式碼與設定，以及引用、轉換或重新發布的第三方素材。**本儲存庫不適用單一統一授權；第三方內容各依其原始授權條款辦理。** 對第三方素材的引用或修改，不代表取得其著作權或商標權。

- **完整聲明**：[第三方素材、相依套件與商標](docs/THIRD_PARTY_NOTICES.md)。
- **Fluent Emoji Flat**：`icons/fluent-emoji-flat/` 來源為 [Microsoft Fluent UI Emoji](https://github.com/microsoft/fluentui-emoji)，透過 [Iconify](https://icon-sets.iconify.design/fluent-emoji-flat/) 取得，採 **MIT License**。著作權及授權條款見 [Fluent Emoji 聲明](docs/FLUENT_EMOJI_ATTRIBUTION.md)。
- **第三方規則**：包括採 **GPL-3.0** 的 HaGeZi、Loyalsoldier，以及採 **MIT** 的 Phishing.Database、anti-AD，採 **DBAD v1.2** 的 MetaMask eth-phishing-detect，以及採 **CC0** 的 Feodo Tracker；來源、修改及授權資訊詳見[規則來源聲明](docs/THIRD_PARTY_NOTICES.md#third-party-rule-sources)。
- **軟體與建置相依套件**：包括 CustomTkinter（MIT）、Tkinter／Tcl/Tk、PyInstaller、Pillow、cryptography 等。各套件依其個別授權適用；詳見[第三方聲明](docs/THIRD_PARTY_NOTICES.md)。
- **品牌商標**：GitHub、Cloudflare／WARP、Private Internet Access、Surfshark、OpenVPN 等名稱與標誌的權利歸各自權利人所有。本儲存庫不再保存品牌圖示；設定檔如引用外部品牌圖像，亦不表示贊助、合作、背書或取得商標授權。

## Windows 本機 MRS

VPN Network Toolkit 的「MRS 規則」分頁可選擇情報來源、Mihomo EXE、Clash 根目錄（預設 `P:\Clash`）與排程頻率（1／2／4／6／12／24 小時）。預設每 2 小時，於每小時 32 分對齊；每日模式為 03:20。至少保留每個網域類別及 IPv4 的一個來源。MRS 沿用 `rules/<分類>/mrs/` 原有路徑。接管既有 MRS 前，須先將 PC 配置的四個同名 provider 改為 `type: file`、移除 `url` 並保留原 path 與 RULE-SET 順序；新建目錄可於首次成功建置後套用產生的 `local-mrs.yaml`。輸出路徑須位於 Mihomo HomeDir 或 SAFE_PATHS。行動裝置仍使用公開 HTTP MRS。排程使用目前登入使用者，不要求管理員；移動 EXE 或變更頻率後須重新安裝排程。排程日誌位於 APPDATA 的工具設定目錄。來源目錄與產物不會上傳；來源目錄可編輯各類別 custom.txt，來源清單隨工具版本更新；目錄不可位於 Git 工作樹；已有 MRS 時須明確確認接管，避免與 HTTP provider 同時寫入。

MRS 分頁可選擇成功建置後通知本機 HTTPS Controller（預設 `https://127.0.0.1:9443`），手動及排程共用設定。Secret 選填並由 Windows DPAPI 以目前使用者加密保存，不放在命令列。使用系統信任及既有 Toolkit CA，不接受遠端 URL、HTTP 或轉址。首次通知四個 File Provider；後續僅通知尚未確認載入之雜湊，失敗不回滾 MRS，下一次成功檢查重試。排程結束碼 3 表示 MRS 有效但 Controller 通知尚待完成。
