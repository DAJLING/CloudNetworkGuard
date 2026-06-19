const { CheckReason } = require('./constants');

const action = (id, label, tone = 'secondary') => ({ id, label, tone });

const reasonCatalog = Object.freeze({
  [CheckReason.CHECK_PENDING]: {
    priority: 30,
    severity: 'info',
    title: '正在校验网络',
    explanation: '守卫正在确认 DNS、连接、出口 IP 和环境状态，校验完成前暂不放行目标流量。',
    actions: [action('retry-check', '重新检测')]
  },
  [CheckReason.STATIC_RESIDENTIAL_IP_REQUIRED]: {
    priority: 100,
    severity: 'block',
    title: '需要配置静态住宅 IP',
    explanation: '开启守卫前需要确认固定出口 IP，避免线路变化带来访问风险。',
    actions: [action('configure-static-ip', '配置静态 IP', 'primary'), action('skip-static-ip', '跳过此检查')]
  },
  [CheckReason.STATIC_RESIDENTIAL_IP_MISMATCH]: {
    priority: 100,
    severity: 'block',
    title: '当前出口 IP 与配置不一致',
    explanation: '当前网络出口和保存的静态住宅 IP 不一致。请确认代理线路或更新配置。',
    actions: [action('configure-static-ip', '更新静态 IP', 'primary'), action('retry-check', '重新检测')]
  },
  [CheckReason.IP_BINDING_MISMATCH]: {
    priority: 95,
    severity: 'block',
    title: '出口 IP 已变化',
    explanation: '守卫检测到当前出口 IP 指纹和之前绑定的出口不一致。',
    actions: [action('review-binding', '查看出口绑定', 'primary'), action('retry-check', '重新检测')]
  },
  [CheckReason.PROVIDER_UNAVAILABLE]: {
    priority: 90,
    severity: 'block',
    title: 'IP 检测源不可用',
    explanation: '当前无法从外部检测源确认 IP 类型、地区或代理风险。守卫会保持谨慎阻断。',
    actions: [action('retry-check', '稍后重试', 'primary'), action('view-report', '查看详情')]
  },
  [CheckReason.SYSTEM_PROXY_NOT_APPLIED]: {
    priority: 92,
    severity: 'block',
    title: '系统代理未被守卫接管',
    explanation: '系统代理被其他网络工具覆盖，Claude 流量可能绕过守卫。守卫会保持阻断保护。',
    actions: [action('retry-check', '重新接管', 'primary'), action('restore-network', '恢复网络')]
  },
  [CheckReason.BLOCKED_REGION]: {
    priority: 90,
    severity: 'block',
    title: '当前地区不符合策略',
    explanation: '检测结果显示当前出口地区属于被阻断区域，或地区无法被可靠确认。',
    actions: [action('retry-check', '重新检测'), action('view-report', '查看检测报告')]
  },
  [CheckReason.DATACENTER_IP]: {
    priority: 85,
    severity: 'warning',
    title: '检测到数据中心 IP',
    explanation: '当前出口更像云服务器或机房网络，而不是稳定住宅网络。',
    actions: [action('retry-check', '重新检测'), action('view-report', '查看来源')]
  },
  [CheckReason.IP_TYPE_UNCONFIRMED]: {
    priority: 84,
    severity: 'block',
    title: 'IP 类型未确认',
    explanation: '检测源无法确认当前出口是住宅 IP。为避免误放行，守卫会保持阻断。',
    actions: [action('retry-check', '重新检测'), action('view-report', '查看来源')]
  },
  [CheckReason.VPN_OR_PROXY_RISK]: {
    priority: 85,
    severity: 'block',
    title: '检测到代理或 VPN 风险',
    explanation: '检测源认为当前出口可能来自代理、VPN 或 Tor 网络。',
    actions: [action('retry-check', '重新检测'), action('view-report', '查看来源')]
  },
  [CheckReason.IP_SHARED_USERS_RISK]: {
    priority: 85,
    severity: 'block',
    title: '出口 IP 共享人数过高',
    explanation: '检测源显示当前出口 IP 可能被过多用户共享，超过了设定的纯净度要求。',
    actions: [action('retry-check', '重新检测'), action('view-report', '查看来源')]
  },
  [CheckReason.IP_RISK_DATA_UNAVAILABLE]: {
    priority: 88,
    severity: 'block',
    title: 'Ping0 风控数据不可用',
    explanation: '当前未能从 Ping0 拿到风控值、纯净度或 IP 共享人数。缺少这些字段时无法确认出口是否适合安全使用 Claude。',
    actions: [action('open-ping0-verify', '打开 Ping0 验证', 'primary'), action('retry-check', '重新检测'), action('view-report', '查看来源')]
  },
  [CheckReason.BLACKLISTED]: {
    priority: 85,
    severity: 'block',
    title: '出口 IP 命中黑名单',
    explanation: '检测源报告当前出口存在黑名单风险。',
    actions: [action('retry-check', '重新检测'), action('view-report', '查看来源')]
  },
  [CheckReason.NO_EXTERNAL_ACCESS]: {
    priority: 80,
    severity: 'block',
    title: '无法访问外部目标',
    explanation: '守卫无法确认目标服务的外部访问链路是否可用。',
    actions: [action('retry-check', '重新检测', 'primary'), action('restore-network', '恢复网络')]
  },
  [CheckReason.DNS_CHECK_FAILED]: {
    priority: 75,
    severity: 'block',
    title: 'DNS 校验失败',
    explanation: '一个或多个目标域名无法解析，可能是 DNS、hosts 或网络策略问题。',
    actions: [action('retry-check', '重新检测'), action('restore-network', '恢复网络')]
  },
  [CheckReason.TCP_CHECK_FAILED]: {
    priority: 75,
    severity: 'block',
    title: 'TCP 连接失败',
    explanation: '目标的 443 端口连接失败，可能是网络、防火墙或代理线路问题。',
    actions: [action('retry-check', '重新检测'), action('restore-network', '恢复网络')]
  },
  [CheckReason.TLS_CHECK_FAILED]: {
    priority: 75,
    severity: 'block',
    title: 'TLS 握手失败',
    explanation: '目标连接可建立，但 TLS 握手失败，可能存在证书、代理或中间网络问题。',
    actions: [action('retry-check', '重新检测'), action('view-report', '查看详情')]
  },
  [CheckReason.CLAUDE_CONTROL_CHECK_FAILED]: {
    priority: 75,
    severity: 'block',
    title: '强校验目标未通过',
    explanation: 'Claude 或 Anthropic 控制目标没有全部通过连接校验。',
    actions: [action('retry-check', '重新检测'), action('view-report', '查看目标')]
  },
  [CheckReason.CLAUDE_WEB_CHECK_FAILED]: {
    priority: 70,
    severity: 'block',
    title: 'Claude 网页探测失败',
    explanation: 'Claude 网页探测没有返回可接受结果，可能存在地区、账号或网络限制。',
    actions: [action('retry-check', '重新检测'), action('view-report', '查看 HTTP 状态')]
  },
  [CheckReason.ENVIRONMENT_MISMATCH]: {
    priority: 65,
    severity: 'block',
    title: '浏览器或系统环境不一致',
    explanation: '时区、语言或 WebRTC 暴露信息可能与期望网络姿态不一致。',
    actions: [
      action('fix-environment', '一键修复环境', 'primary'),
      action('view-report', '查看环境详情'),
      action('retry-check', '重新检测')
    ]
  },
  [CheckReason.USAGE_RATE_RISK]: {
    priority: 60,
    severity: 'block',
    title: '目标请求频率异常',
    explanation: '短时间内目标请求量超过阈值，守卫已临时阻断以降低风险。',
    actions: [action('retry-check', '稍后重试'), action('view-report', '查看频率')]
  },
  [CheckReason.STATIC_WINDOW_PENDING]: {
    priority: 55,
    severity: 'warning',
    title: '静态 IP 观察时间不足',
    explanation: '当前出口还没有满足稳定观察窗口，守卫会继续保持谨慎。',
    actions: [action('retry-check', '稍后重试')]
  },
  [CheckReason.IP_CHANGED]: {
    priority: 55,
    severity: 'block',
    title: '观察中的 IP 已变化',
    explanation: '静态 IP 观察期间出口发生变化，当前线路不够稳定。',
    actions: [action('retry-check', '重新检测'), action('configure-static-ip', '更新静态 IP')]
  },
  [CheckReason.STATIC_RESIDENTIAL_IP_SKIPPED]: {
    priority: 20,
    severity: 'info',
    title: '已跳过静态 IP 校验',
    explanation: '你已明确选择不校验静态住宅 IP，其他网络风险检查仍会继续执行。',
    actions: [action('configure-static-ip', '重新配置')]
  },
  [CheckReason.CLAUDE_ACCOUNT_RISK_ACK_REQUIRED]: {
    priority: 85,
    severity: 'warning',
    title: '需要确认账号风险',
    explanation: '未绑定静态住宅 IP 时，使用 Claude 可能因出口变化、代理地区或网络风险触发账号限制。确认风险后才会开启守卫。',
    actions: [action('configure-static-ip', '配置静态 IP', 'primary'), action('retry-check', '继续开启')]
  },
  [CheckReason.DNS_LEAK_RISK]: {
    priority: 60,
    severity: 'block',
    title: '可能存在 DNS 泄露风险',
    explanation: 'DNS 结果显示当前解析路径可能和期望网络姿态不一致。',
    actions: [action('retry-check', '重新检测'), action('view-report', '查看 DNS 详情')]
  }
});

function getReasonGuidance(reason) {
  const known = reasonCatalog[reason];
  if (known) return { reason, ...known };
  return {
    reason,
    priority: 0,
    severity: 'warning',
    title: '检测发现未知风险',
    explanation: '守卫返回了当前版本尚未识别的风险原因。建议查看检测报告并重新检测。',
    actions: [action('retry-check', '重新检测'), action('view-report', '查看报告')]
  };
}

function getTopReasonGuidance(reasons = []) {
  const guidance = reasons.length ? reasons.map(getReasonGuidance) : [getReasonGuidance(CheckReason.CHECK_PENDING)];
  const severityRank = { block: 3, warning: 2, info: 1 };
  return guidance.sort((a, b) => {
    const severityDelta = (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0);
    if (severityDelta) return severityDelta;
    return b.priority - a.priority;
  })[0];
}

module.exports = {
  reasonCatalog,
  getReasonGuidance,
  getTopReasonGuidance
};
