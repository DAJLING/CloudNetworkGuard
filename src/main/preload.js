const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('networkGuard', {
  getStatus: () => ipcRenderer.invoke('guard:get-status'),
  enable: (mode, options) => ipcRenderer.invoke('guard:enable', mode, options),
  disable: () => ipcRenderer.invoke('guard:disable'),
  emergencyRestore: () => ipcRenderer.invoke('guard:emergency-restore'),
  resetExitBinding: () => ipcRenderer.invoke('guard:reset-exit-binding'),
  rebindExitToCurrent: () => ipcRenderer.invoke('guard:rebind-exit-current'),
  completeSetup: (setup) => ipcRenderer.invoke('guard:complete-setup', setup),
  reopenSetup: () => ipcRenderer.invoke('guard:reopen-setup'),
  getDiagnosticReport: () => ipcRenderer.invoke('guard:get-diagnostic-report'),
  checkNow: () => ipcRenderer.invoke('guard:check-now'),
  reloadRules: () => ipcRenderer.invoke('guard:reload-rules'),
  saveValidationConfig: (validation) => ipcRenderer.invoke('guard:save-validation-config', validation),
  saveTargetRules: (rules) => ipcRenderer.invoke('guard:save-target-rules', rules),
  resetValidationDefaults: () => ipcRenderer.invoke('guard:reset-validation-defaults'),
  resetTargetConfigDefaults: () => ipcRenderer.invoke('guard:reset-target-config-defaults'),
  setStaticResidentialIp: (staticResidentialIp) => ipcRenderer.invoke('guard:set-static-residential-ip', staticResidentialIp),
  reportEnvironment: (environment) => ipcRenderer.invoke('guard:report-environment', environment),
  applyEnvironmentConsistency: () => ipcRenderer.invoke('guard:environment-consistency-apply'),
  restoreEnvironmentConsistency: () => ipcRenderer.invoke('guard:environment-consistency-restore'),
  setEnvironmentConsistencyConfig: (config) => ipcRenderer.invoke('guard:environment-consistency-set-config', config),
  backupEnvironmentNow: () => ipcRenderer.invoke('guard:environment-consistency-backup-now'),
  setMonitoringConfig: (config) => ipcRenderer.invoke('guard:set-monitoring-config', config),
  setLaunchAtLogin: (enabled) => ipcRenderer.invoke('guard:set-launch-at-login', enabled),
  onEvent: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('guard:event', listener);
    return () => ipcRenderer.removeListener('guard:event', listener);
  }
});
