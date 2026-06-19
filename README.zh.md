# Claude Network Guard

[![English](https://img.shields.io/badge/Language-English-blue)](README.md)
[![简体中文](https://img.shields.io/badge/语言-简体中文-green)](README.zh.md)

Claude Network Guard 是一个 Windows/macOS 桌面应用，用于 Claude 与 Anthropic API 的网络检测、请求时拦截、本地代理守卫、防火墙兜底、静态住宅 IP 校验和浏览器环境一致性检查。

如果你在找 **Claude 网络检测**、**Claude 请求拦截**、**Anthropic API 代理守卫**、**Claude Code 网络风控辅助**、**静态住宅 IP 校验** 或 **Claude 防封控网络检查工具**，这个项目就是为这类需求做的。

## 它解决什么问题

Claude Network Guard 会在本机启动一个守卫代理，并把 Claude / Anthropic 目标流量放进请求时校验流程。守卫开启后，匹配规则的请求会先被本地代理拦住；只有出口 IP、地区、代理风险、Claude 可达性、浏览器环境、请求频率和出口绑定等校验通过后，才会继续发往上游。

适合这些场景：

- 在使用 Claude、Claude Web、Claude Code 或 Anthropic API 前，确认当前网络是否适合访问。
- 当出口 IP 变化、地区不支持、检测源不可用，或 IP 呈现 VPN、代理、Tor、机房、黑名单、高共享风险时，自动阻断 Claude 目标流量。
- 将浏览器/系统信号和出口地区对齐，降低时区、语言、WebRTC 本地 IP 暴露带来的不一致风险。
- 对不遵守系统代理的客户端，通过 Windows Firewall 或 macOS pf 做兜底拦截。
- 生成本地诊断报告，排查 DNS、TCP、TLS、Claude Web、Ping0/Proxycheck、出口绑定、请求频率和环境问题。

## 功能亮点

- **一键守卫**：从主界面或托盘菜单开启/关闭保护。
- **请求时校验**：后台定时检测已停用，只有匹配 Claude / Anthropic 规则的请求触发校验。
- **Claude 目标规则**：内置 `claude.ai`、`*.claude.ai`、`*.anthropic.com`，可在界面新增、放行、编辑和保存规则。
- **本地代理**：默认本地代理为 `127.0.0.1:18089`。
- **防火墙兜底**：Windows 使用 `netsh advfirewall`，macOS 使用应用自有 `pf` anchor 阻断目标 IP。
- **静态住宅 IP 校验**：可要求当前出口精确匹配固定住宅 IPv4；跳过时需要明确确认 Claude 账号风险。
- **IP 情报检测**：免费检测源会判断 IP、地区、ASN、住宅/机房特征、代理风险、黑名单和共享人数；`PING0_API_KEY` 可启用 Ping0 付费字段。
- **环境一致性**：检查并可一键应用时区、语言和浏览器 WebRTC 策略，支持应用托管的备份与恢复。
- **出口绑定**：只保存出口 IP 指纹，出口变化时阻断并提示。
- **诊断报告**：一键复制脱敏 JSON 报告，方便排障或提交 issue。
- **紧急恢复**：关闭守卫并清理本应用管理的代理、防火墙、hosts 和环境设置。
- **本地最小日志**：只保留最小事件日志，IP 显示经过脱敏。

## 工作原理

Request-time validation 是核心机制：Claude / Anthropic 目标流量会在匹配请求出现的那一刻被检测，然后决定放行或阻断。

```text
Claude / Anthropic request
        |
        v
Local guard proxy 127.0.0.1:18089
        |
        v
Target rule match? ---- no ----> allow as normal
        |
       yes
        |
        v
Request-time checks:
DNS / TCP / TLS / Claude Web / IP type / region / proxy risk /
static residential IP / exit binding / usage rate / environment consistency
        |
        v
PASS -> forward upstream
BLOCK -> reject request + optional firewall fallback
```

守卫默认是 fail-closed：开启后，如果检测源不可用、Claude 强校验目标失败、出口地区无法确认、风险数据缺失或系统代理被覆盖，目标流量会保持阻断。

## 界面与控制项

当前界面包含 5 个主要视图：

- **总览**：当前判断、目标流量、出口 IP、静态住宅 IP、检测清单、修复建议和配置摘要。
- **拦截规则**：管理 Claude / Anthropic 域名规则，支持 `GUARD` 和 `ALLOW`。
- **可选配置**：校验项开关、静态住宅 IP、开机自启、环境一致性、出口绑定、恢复网络和当前生效目标。
- **检测报告**：查看并复制脱敏诊断报告。
- **事件日志**：查看本地最小守卫事件。

## 快速开始

环境要求：

- Node.js `>=22.12.0`
- pnpm `11.8.0`
- Windows 或 macOS

```bash
pnpm install
pnpm run make-icon
pnpm test
pnpm start
```

第一次启动时会出现首次设置向导。推荐先配置真实的静态住宅 IPv4；如果你明确知道自己要跳过静态 IP 校验，可以选择跳过，此时其他 Claude 网络检测和请求拦截仍会继续生效。

## 构建

macOS 打包，请在 macOS 上运行：

```bash
pnpm run pack:mac    # 未打包应用输出到 dist/mac/
pnpm run dist:mac    # 生成 DMG + PKG 安装包
```

Windows 打包，请在 Windows 上运行：

```powershell
pnpm run pack:win       # 未打包应用输出到 dist/win-unpacked/
pnpm run dist:win       # NSIS 安装包
pnpm run dist:win:msi   # MSI 安装包，需要构建机安装 WiX
```

`pnpm run make-icon` 会生成 Windows 安装包使用的图标资源。macOS 与 Windows 构建命令故意分开，避免跨平台产物混在一起。

## GitHub Releases

仓库已经加入 GitHub Actions 工作流：推送 `v*` tag 后会自动构建 Windows 和 macOS 安装包，并上传到对应的 GitHub Release。

发布第一个公开安装包版本：

```bash
git tag v0.0.2
git push origin v0.0.2
```

工作流会自动完成：

- 使用 pnpm 安装依赖；
- 运行测试；
- 构建 macOS `.dmg` 和 `.pkg` 安装包；
- 构建 Windows `.exe` 和 `.msi` 安装包；
- 为该 tag 创建或更新 GitHub Release；
- 将安装包作为 release assets 上传。

当前发布产物未签名。配置 Apple notarization 和 Windows code signing 之前，macOS Gatekeeper 与 Windows SmartScreen 可能会向用户展示安全提示。

## 目标配置

守卫目标从应用数据目录中的 `target-rules.json` 读取。你也可以通过 `NETWORK_GUARD_TARGET_CONFIG` 指向另一个文件。Targets view 可以新增、编辑、删除、重新载入、重置并保存目标规则，不需要手动编辑 JSON。

出于安全考虑，自定义规则、自定义校验主机和网页探测 URL 都限制在 `claude.ai` 与 `anthropic.com` 域名下。

默认配置：

```json
{
  "version": 1,
  "rules": [
    { "id": "anthropic-api", "domainPattern": "*.anthropic.com", "processNames": [], "action": "GUARD" },
    { "id": "claude-web", "domainPattern": "claude.ai", "processNames": [], "action": "GUARD" },
    { "id": "claude-subdomains", "domainPattern": "*.claude.ai", "processNames": [], "action": "GUARD" }
  ],
  "validation": {
    "services": { "claude": true },
    "checks": {
      "staticResidentialIp": true,
      "ipType": true,
      "region": true,
      "proxyRisk": true,
      "dns": true,
      "tcp": true,
      "tls": true,
      "controlHosts": true,
      "environment": true,
      "exitBinding": true,
      "usageRate": true
    },
    "webProbe": { "enabled": true, "url": "https://claude.ai/" },
    "useCustomHosts": false,
    "customHealthCheckHosts": [],
    "customControlHosts": []
  },
  "healthCheckHosts": ["claude.ai", "api.anthropic.com"],
  "controlHosts": ["claude.ai", "api.anthropic.com"],
  "firewallHosts": ["anthropic.com", "claude.ai"],
  "webProbeUrl": "https://claude.ai/",
  "staticResidentialIp": ""
}
```

`staticResidentialIp` 的行为：

- 留空：开启守卫前需要明确确认 Claude 账号风险。
- `0.0.0.0`：明确确认后跳过精确静态 IP 匹配。
- 真实 IPv4：只有当前出口 IP 与该值完全一致时，守卫请求才会放行。

## 校验矩阵

| 校验项 | 目的 |
| --- | --- |
| 静态住宅 IP | 要求固定出口 IP，或明确跳过 |
| IP 类型 | 判断住宅网络或机房/托管网络 |
| 地区 | 阻断 Claude 不支持或无法确认的出口地区 |
| 代理风险 | 检测 VPN、代理、Tor、黑名单、高风险 IP 和共享人数信号 |
| DNS | 验证目标域名解析 |
| TCP | 验证 HTTPS 端口可达 |
| TLS | 验证安全握手 |
| 强校验目标 | 要求核心 Claude / Anthropic 目标通过 |
| Claude Web 探测 | 探测 `https://claude.ai/` 或配置的 Claude URL |
| 环境一致性 | 检查时区、语言和浏览器 WebRTC 暴露 |
| 出口绑定 | 通过本地哈希识别出口 IP 变化 |
| 使用频率 | 阻断异常高频目标请求 |

## 平台说明

- Windows 默认不会应用系统代理，因为全局系统代理可能影响语言/输入法服务。应用仍会运行本地代理，并在需要时使用防火墙兜底。
- Windows 防火墙兜底使用 `netsh advfirewall` 为解析出的 Claude / Anthropic IP 添加出站阻断规则，可能需要管理员权限。
- macOS 代理设置使用 `networksetup`，默认网络服务是 `Wi-Fi`。如需指定其他服务，可设置 `NETWORK_GUARD_MAC_SERVICE`。
- macOS firewall fallback uses `/etc/pf.anchors/com.local.claude-network-guard` and a marked `pf.conf` block, and may request administrator authorization. 应用只管理自己的标记块和 anchor 文件。
- 环境一致性功能会在创建应用托管备份后，修改系统时区/语言和 Chrome/Edge WebRTC 偏好。
- 紧急恢复会尝试移除本应用管理的代理、防火墙、hosts 和环境设置。

## 环境变量

| 变量 | 作用 |
| --- | --- |
| `NETWORK_GUARD_DATA_DIR` | 使用自定义应用数据目录 |
| `NETWORK_GUARD_TARGET_CONFIG` | 使用自定义 `target-rules.json` 路径 |
| `NETWORK_GUARD_MAC_SERVICE` | 选择 macOS `networksetup` 使用的网络服务 |
| `NETWORK_GUARD_SKIP_SYSTEM_PROXY=1` | 不触碰系统代理设置 |
| `NETWORK_GUARD_USE_SYSTEM_PROXY=1` | 在支持的平台强制使用系统代理 |
| `NETWORK_GUARD_SKIP_FIREWALL=1` | 不触碰防火墙设置 |
| `NETWORK_GUARD_USE_HOSTS_BLOCK=1` | 在支持时启用应用管理的 hosts 兜底阻断 |
| `NETWORK_GUARD_USE_PROXYCHECK=1` | 即使没有 `PROXYCHECK_API_KEY` 也启用 Proxycheck 查询 |
| `PING0_API_KEY` | 启用 Ping0 付费 API，获取 IP 风险、纯净度和共享人数等字段 |
| `PROXYCHECK_API_KEY` | 启用 Proxycheck API 查询 |

没有 `PING0_API_KEY` 时，Ping0 免费 `/geo` 接口只提供 IP、位置、ASN 和组织信息。公开详情页可能要求 CAPTCHA，因此风险和共享人数等字段不一定可用。

## 安全与隐私

- Claude Network Guard 不购买、不切换、不管理代理/VPN 账号。
- 它不能保证 Claude 账号绝对安全。账号历史、付款地区、服务端风控决策和 Anthropic 侧策略无法在本地完全验证。
- 应用只保存脱敏 IP 展示数据和本地 IP 哈希用于出口绑定；诊断报告会清理 provider 结果。
- 防火墙兜底基于当前解析出的目标 IP。如果 Claude / Anthropic 在下一次请求时校验前轮换 IP，请运行 `立即检测` 或重新载入目标规则。
- 免费 IP 情报源可能误判住宅/静态状态。provider 层保留为后续付费源或更强检测源扩展的空间。

## 排障

**开启守卫后 Claude 请求被阻断**

打开 `检测报告` 查看 `reasons`。常见原因包括 `STATIC_RESIDENTIAL_IP_REQUIRED`、`STATIC_RESIDENTIAL_IP_MISMATCH`、`BLOCKED_REGION`、`DATACENTER_IP`、`VPN_OR_PROXY_RISK`、`IP_RISK_DATA_UNAVAILABLE`、`CLAUDE_WEB_CHECK_FAILED`、`ENVIRONMENT_MISMATCH` 和 `SYSTEM_PROXY_NOT_APPLIED`。

**CLI 客户端绕过了本地代理**

使用防火墙兜底路径。Windows 依赖 `netsh advfirewall`，macOS 依赖应用自有 `pf` anchor。如果特权变更失败，先执行 `恢复网络`，再以管理员权限重试。

**Ping0 风险数据缺失**

设置 `PING0_API_KEY`，或在应用中打开 Ping0 验证动作。没有付费/API 数据时，应用可能因为无法确认风险、纯净度或共享人数而阻断。

**环境一致性失败**

关闭正在运行的浏览器，执行 `重新备份`，然后重试 `一键对齐环境`。可用 `还原环境` 或 `恢复网络` 回滚应用管理的变更。

## 开发

```bash
pnpm test
pnpm start
```

测试套件使用 Node 内置 test runner，覆盖代理拦截、目标规则、provider 评分、网络检测、防火墙管理、环境一致性、诊断报告和 renderer wiring。

## GitHub 搜索关键词

本项目刻意覆盖以下 GitHub 用户可能搜索的短语：

- Claude network guard
- Claude network detector
- Claude request blocker
- Claude traffic firewall
- Claude Code proxy guard
- Anthropic API network check
- Anthropic API request blocking
- static residential IP checker
- Claude WebRTC leak check
- Claude environment consistency
- Claude 防封控网络检测
- Claude 网络拦截
- Claude 请求拦截
- Claude 静态住宅 IP 检测
- Claude Code 网络守卫

推荐 GitHub topics：`claude`、`anthropic`、`claude-code`、`network-guard`、`network-diagnostics`、`request-blocking`、`local-proxy`、`firewall`、`static-residential-ip`、`webrtc`、`electron`。

## 当前限制

- 这里还没有描述官方发布产物；目前请使用 Electron Builder 本地构建。
- 目标配置管理器只接受 Claude / Anthropic 域名。
- 防火墙兜底基于 IP 解析，目标服务轮换地址后可能需要重新校验。
- 当前未把 Linux 列为支持的桌面目标。
- 内置图标较简单，公开发布前建议替换。

## License

MIT
