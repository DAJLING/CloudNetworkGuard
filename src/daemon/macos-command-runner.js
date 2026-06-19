const { execFile } = require('child_process');

const DEFAULT_TIMEOUT_MS = 45000;

function execFilePromise(command, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer = null;

    const child = execFile(
      command,
      args,
      { windowsHide: true, ...options },
      (error, stdout, stderr) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);

        if (error) {
          reject(new Error(String(stderr || stdout || error.message).trim() || error.message));
          return;
        }
        resolve(stdout);
      }
    );

    if (options.timeoutMs) {
      timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        child.kill();
        reject(new Error('COMMAND_TIMEOUT'));
      }, options.timeoutMs);
      child.once('exit', () => clearTimeout(timer));
    }
  });
}

function quoteShellArg(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function escapeAppleScriptString(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function joinShellCommand(parts = []) {
  return parts.map(quoteShellArg).join(' ');
}

class MacCommandRunner {
  constructor({ execFile: customExecFile = null, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    this.execFile = customExecFile || ((command, args) => execFilePromise(command, args, { timeoutMs }));
    this.timeoutMs = timeoutMs;
  }

  async run(command, args = []) {
    return this.execFile(command, args);
  }

  async runCommand(parts = []) {
    if (!parts.length) throw new Error('COMMAND_EMPTY');
    const [command, ...args] = parts;
    return this.run(command, args);
  }

  async runPrivilegedScript(script) {
    const escaped = escapeAppleScriptString(script);
    return this.run('osascript', ['-e', `do shell script "${escaped}" with administrator privileges`]);
  }

  async runPrivilegedCommands(commands = []) {
    if (!commands.length) return '';
    const script = commands.map(joinShellCommand).join(' && ');
    return this.runPrivilegedScript(script);
  }

  async writeFilePrivileged(filePath, content) {
    const encoded = Buffer.from(String(content), 'utf8').toString('base64');
    const script = [
      'tmp=$(/usr/bin/mktemp -t network-guard.XXXXXX)',
      'trap \'rm -f "$tmp"\' EXIT',
      `printf %s ${quoteShellArg(encoded)} | base64 --decode > "$tmp"`,
      `mv "$tmp" ${quoteShellArg(filePath)}`,
      `chmod 0644 ${quoteShellArg(filePath)}`,
      'trap - EXIT'
    ].join(' && ');
    return this.runPrivilegedScript(script);
  }

  async removeFilePrivileged(filePath) {
    return this.runPrivilegedScript(`rm -f ${quoteShellArg(filePath)}`);
  }
}

module.exports = {
  MacCommandRunner,
  quoteShellArg,
  joinShellCommand,
  execFilePromise
};
