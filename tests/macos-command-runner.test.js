const test = require('node:test');
const assert = require('node:assert/strict');
const {
  MacCommandRunner,
  quoteShellArg,
  joinShellCommand
} = require('../src/daemon/macos-command-runner');

test('quoteShellArg wraps values safely for shell scripts', () => {
  assert.equal(quoteShellArg('/Library/Application Support/App'), "'/Library/Application Support/App'");
  assert.equal(quoteShellArg("Bob's Mac"), "'Bob'\\''s Mac'");
  assert.equal(quoteShellArg(''), "''");
});

test('joinShellCommand quotes command arguments', () => {
  assert.equal(
    joinShellCommand(['/usr/sbin/systemsetup', '-settimezone', 'America/Los_Angeles']),
    "'/usr/sbin/systemsetup' '-settimezone' 'America/Los_Angeles'"
  );
});

test('runPrivilegedScript invokes osascript with administrator privileges', async () => {
  const calls = [];
  const runner = new MacCommandRunner({
    execFile: async (command, args) => {
      calls.push({ command, args });
      return 'ok';
    }
  });

  const output = await runner.runPrivilegedScript('echo ready');

  assert.equal(output, 'ok');
  assert.equal(calls[0].command, 'osascript');
  assert.deepEqual(calls[0].args, [
    '-e',
    'do shell script "echo ready" with administrator privileges'
  ]);
});

test('writeFilePrivileged writes via a temporary base64 script', async () => {
  const calls = [];
  const runner = new MacCommandRunner({
    execFile: async (command, args) => {
      calls.push({ command, args });
      return '';
    }
  });

  await runner.writeFilePrivileged('/etc/pf.anchors/example', 'block drop out quick to 203.0.113.10\n');

  assert.equal(calls[0].command, 'osascript');
  assert.match(calls[0].args[1], /base64 --decode/);
  assert.match(calls[0].args[1], /mv/);
  assert.doesNotMatch(calls[0].args[1], /203\.0\.113\.10/);
});
