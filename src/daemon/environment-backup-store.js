const fs = require('fs');
const path = require('path');

class EnvironmentBackupStore {
  constructor(filePath) {
    this.filePath = filePath;
  }

  exists() {
    return fs.existsSync(this.filePath);
  }

  load() {
    const raw = fs.readFileSync(this.filePath, 'utf8');
    return JSON.parse(raw);
  }

  save(snapshot) {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(this.filePath, JSON.stringify(snapshot, null, 2));
    return snapshot;
  }

  getSummary() {
    if (!this.exists()) {
      return { hasBackup: false, createdAt: null, path: this.filePath };
    }
    const snapshot = this.load();
    return {
      hasBackup: true,
      createdAt: snapshot.createdAt || null,
      path: this.filePath
    };
  }
}

module.exports = {
  EnvironmentBackupStore
};
