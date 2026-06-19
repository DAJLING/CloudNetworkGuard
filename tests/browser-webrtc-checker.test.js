const test = require('node:test');
const assert = require('node:assert/strict');
const { checkBrowserWebRtcPolicies, normalizeBrowserState, WEBRTC_POLICY } = require('../src/daemon/browser-webrtc-checker');

test('normalizeBrowserState marks installed browsers without WebRTC policy as unsafe', () => {
  const state = normalizeBrowserState('chrome', {
    installed: true,
    webrtcPreference: null,
    webrtcPolicyApplied: false
  });

  assert.equal(state.id, 'chrome');
  assert.equal(state.installed, true);
  assert.equal(state.policyApplied, false);
});

test('checkBrowserWebRtcPolicies passes mac browsers with disabled policy', async () => {
  const result = await checkBrowserWebRtcPolicies({
    platform: 'darwin',
    macApplier: {
      captureBrowserState: (browserId) => ({
        installed: true,
        webrtcPreference: WEBRTC_POLICY,
        webrtcPolicyApplied: true,
        browserId
      })
    }
  });

  assert.equal(result.supported, true);
  assert.equal(result.ok, true);
  assert.equal(result.browsers.length, 2);
});

test('checkBrowserWebRtcPolicies blocks windows browsers without disabled policy', async () => {
  const result = await checkBrowserWebRtcPolicies({
    platform: 'win32',
    winApplier: {
      captureBrowserState: async (browserId) => ({
        installed: true,
        webrtcPolicy: browserId === 'chrome' ? WEBRTC_POLICY : null,
        webrtcPolicyApplied: browserId === 'chrome'
      })
    }
  });

  assert.equal(result.supported, true);
  assert.equal(result.ok, false);
  assert.equal(result.browsers.find((browser) => browser.id === 'edge').policyApplied, false);
});

test('checkBrowserWebRtcPolicies skips unsupported platforms', async () => {
  const result = await checkBrowserWebRtcPolicies({ platform: 'linux' });

  assert.equal(result.supported, false);
  assert.equal(result.ok, true);
  assert.deepEqual(result.browsers, []);
});
