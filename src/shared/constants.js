const GuardState = Object.freeze({
  ENABLED: 'ENABLED',
  DISABLED: 'DISABLED'
});

const GuardMode = Object.freeze({
  AUTO: 'AUTO',
  STRICT_VALIDATE: 'STRICT_VALIDATE'
});

const NetworkVerdict = Object.freeze({
  PASS: 'PASS',
  WARN: 'WARN',
  BLOCK: 'BLOCK',
  OBSERVING: 'OBSERVING'
});

const CheckReason = Object.freeze({
  NO_EXTERNAL_ACCESS: 'NO_EXTERNAL_ACCESS',
  DNS_CHECK_FAILED: 'DNS_CHECK_FAILED',
  TCP_CHECK_FAILED: 'TCP_CHECK_FAILED',
  TLS_CHECK_FAILED: 'TLS_CHECK_FAILED',
  CLAUDE_CONTROL_CHECK_FAILED: 'CLAUDE_CONTROL_CHECK_FAILED',
  CLAUDE_WEB_CHECK_FAILED: 'CLAUDE_WEB_CHECK_FAILED',
  ENVIRONMENT_MISMATCH: 'ENVIRONMENT_MISMATCH',
  IP_BINDING_MISMATCH: 'IP_BINDING_MISMATCH',
  USAGE_RATE_RISK: 'USAGE_RATE_RISK',
  DATACENTER_IP: 'DATACENTER_IP',
  IP_TYPE_UNCONFIRMED: 'IP_TYPE_UNCONFIRMED',
  VPN_OR_PROXY_RISK: 'VPN_OR_PROXY_RISK',
  IP_SHARED_USERS_RISK: 'IP_SHARED_USERS_RISK',
  IP_RISK_DATA_UNAVAILABLE: 'IP_RISK_DATA_UNAVAILABLE',
  BLACKLISTED: 'BLACKLISTED',
  BLOCKED_REGION: 'BLOCKED_REGION',
  IP_CHANGED: 'IP_CHANGED',
  STATIC_WINDOW_PENDING: 'STATIC_WINDOW_PENDING',
  STATIC_RESIDENTIAL_IP_REQUIRED: 'STATIC_RESIDENTIAL_IP_REQUIRED',
  STATIC_RESIDENTIAL_IP_MISMATCH: 'STATIC_RESIDENTIAL_IP_MISMATCH',
  STATIC_RESIDENTIAL_IP_SKIPPED: 'STATIC_RESIDENTIAL_IP_SKIPPED',
  CLAUDE_ACCOUNT_RISK_ACK_REQUIRED: 'CLAUDE_ACCOUNT_RISK_ACK_REQUIRED',
  DNS_LEAK_RISK: 'DNS_LEAK_RISK',
  PROVIDER_UNAVAILABLE: 'PROVIDER_UNAVAILABLE',
  CHECK_PENDING: 'CHECK_PENDING'
});

const DEFAULT_TARGET_RULES = [
  { id: 'anthropic-api', domainPattern: '*.anthropic.com', processNames: [], action: 'GUARD' },
  { id: 'claude-web', domainPattern: 'claude.ai', processNames: [], action: 'GUARD' },
  { id: 'claude-subdomains', domainPattern: '*.claude.ai', processNames: [], action: 'GUARD' }
];

const DEFAULT_TARGET_HEALTH_HOSTS = ['claude.ai', 'api.anthropic.com'];
const DEFAULT_TARGET_CONTROL_HOSTS = ['claude.ai', 'api.anthropic.com'];
const DEFAULT_TARGET_WEB_PROBE_URL = 'https://claude.ai/';

const VALIDATION_SERVICES = Object.freeze({
  claude: Object.freeze({
    id: 'claude',
    label: 'Claude / Anthropic',
    healthCheckHosts: ['claude.ai', 'api.anthropic.com'],
    controlHosts: ['claude.ai', 'api.anthropic.com'],
    defaultWebProbeUrl: DEFAULT_TARGET_WEB_PROBE_URL
  })
});

module.exports = {
  GuardState,
  GuardMode,
  NetworkVerdict,
  CheckReason,
  DEFAULT_TARGET_RULES,
  DEFAULT_TARGET_HEALTH_HOSTS,
  DEFAULT_TARGET_CONTROL_HOSTS,
  DEFAULT_TARGET_WEB_PROBE_URL,
  VALIDATION_SERVICES
};
