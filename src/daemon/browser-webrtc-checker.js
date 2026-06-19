const { EnvironmentApplierMac, WEBRTC_POLICY: MAC_WEBRTC_POLICY } = require('./environment-applier-mac');
const { EnvironmentApplierWin, WEBRTC_POLICY: WIN_WEBRTC_POLICY } = require('./environment-applier-win');

const WEBRTC_POLICY = MAC_WEBRTC_POLICY || WIN_WEBRTC_POLICY || 'disable_non_proxied_udp';
const BROWSER_IDS = ['chrome', 'edge'];

function normalizeBrowserState(browserId, state = {}, error = null) {
  const installed = state.installed === true;
  const policy = state.webrtcPolicy || state.webrtcPreference || null;
  const policyApplied = installed ? state.webrtcPolicyApplied === true : true;
  return {
    id: browserId,
    installed,
    policy,
    policyApplied,
    error: error ? error.message || String(error) : null
  };
}

async function checkMacBrowsers({ applier = new EnvironmentApplierMac() } = {}) {
  return BROWSER_IDS.map((browserId) => {
    try {
      return normalizeBrowserState(browserId, applier.captureBrowserState(browserId));
    } catch (error) {
      return normalizeBrowserState(browserId, { installed: true }, error);
    }
  });
}

async function checkWinBrowsers({ applier = new EnvironmentApplierWin() } = {}) {
  const browsers = [];
  for (const browserId of BROWSER_IDS) {
    try {
      browsers.push(normalizeBrowserState(browserId, await applier.captureBrowserState(browserId)));
    } catch (error) {
      browsers.push(normalizeBrowserState(browserId, { installed: true }, error));
    }
  }
  return browsers;
}

async function checkBrowserWebRtcPolicies({ platform = process.platform, macApplier, winApplier } = {}) {
  if (platform === 'darwin') {
    const browsers = await checkMacBrowsers({ applier: macApplier || new EnvironmentApplierMac({ platform }) });
    return {
      supported: true,
      requiredPolicy: WEBRTC_POLICY,
      ok: browsers.every((browser) => !browser.installed || browser.policyApplied),
      browsers
    };
  }

  if (platform === 'win32') {
    const browsers = await checkWinBrowsers({ applier: winApplier || new EnvironmentApplierWin({ platform }) });
    return {
      supported: true,
      requiredPolicy: WEBRTC_POLICY,
      ok: browsers.every((browser) => !browser.installed || browser.policyApplied),
      browsers
    };
  }

  return {
    supported: false,
    requiredPolicy: WEBRTC_POLICY,
    ok: true,
    browsers: []
  };
}

module.exports = {
  WEBRTC_POLICY,
  checkBrowserWebRtcPolicies,
  normalizeBrowserState
};
