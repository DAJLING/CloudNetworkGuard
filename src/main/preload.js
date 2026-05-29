const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('networkGuard', {
  getStatus: () => ipcRenderer.invoke('guard:get-status'),
  enable: (mode) => ipcRenderer.invoke('guard:enable', mode),
  disable: () => ipcRenderer.invoke('guard:disable'),
  checkNow: () => ipcRenderer.invoke('guard:check-now'),
  reloadRules: () => ipcRenderer.invoke('guard:reload-rules'),
  setStaticResidentialIp: (staticResidentialIp) => ipcRenderer.invoke('guard:set-static-residential-ip', staticResidentialIp),
  reportEnvironment: (environment) => ipcRenderer.invoke('guard:report-environment', environment),
  setLaunchAtLogin: (enabled) => ipcRenderer.invoke('guard:set-launch-at-login', enabled),
  onEvent: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on('guard:event', listener);
    return () => ipcRenderer.removeListener('guard:event', listener);
  }
});
