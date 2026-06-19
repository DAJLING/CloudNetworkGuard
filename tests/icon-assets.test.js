const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const rootDir = path.join(__dirname, '..');

function readProjectFile(relativePath) {
  return fs.readFileSync(path.join(rootDir, relativePath), 'utf8');
}

test('Electron build config declares platform app icons', () => {
  const packageJson = JSON.parse(readProjectFile('package.json'));

  assert.equal(packageJson.build.win.icon, 'assets/icon.ico');
  assert.equal(packageJson.build.mac.icon, 'assets/icon.icns');
});

test('test script is portable on Windows shells', () => {
  const packageJson = JSON.parse(readProjectFile('package.json'));

  assert.equal(packageJson.scripts.test, 'node scripts/run-tests.js');
});

test('main process uses bundled icon assets for windows and tray', () => {
  const mainSource = readProjectFile('src/main/main.js');

  assert.match(mainSource, /const appIconPath = path\.join\(__dirname, '\.\.\/\.\.\/assets\/app-icon\.png'\)/);
  assert.match(mainSource, /icon: appIconPath/);
  assert.match(mainSource, /nativeImage\.createFromPath\(appIconPath\)/);
});

test('renderer toolbar displays the shared app icon asset', () => {
  const html = readProjectFile('src/renderer/index.html');
  const css = readProjectFile('src/renderer/styles.css');

  assert.match(html, /<img class="brand-icon" src="\.\.\/\.\.\/assets\/app-icon\.png" alt="" \/>/);
  assert.match(css, /\.brand-lockup/);
  assert.match(css, /\.brand-icon/);
});
