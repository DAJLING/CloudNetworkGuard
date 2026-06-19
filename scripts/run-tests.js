const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const rootDir = path.join(__dirname, '..');
const testsDir = path.join(rootDir, 'tests');
const testFiles = fs
  .readdirSync(testsDir)
  .filter((file) => file.endsWith('.test.js'))
  .sort()
  .map((file) => path.join('tests', file));

if (!testFiles.length) {
  console.error('No test files found.');
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...testFiles], {
  cwd: rootDir,
  stdio: 'inherit'
});

process.exit(result.status === null ? 1 : result.status);
