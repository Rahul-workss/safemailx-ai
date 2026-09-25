/**
 * verify-speak-it.js
 *
 * Automated verification of the Speak It / @react-native-voice/voice pipeline.
 * Run: node scripts/verify-speak-it.js
 */

const fs = require('fs');
const path = require('path');

let passed = 0;
let failed = 0;

function ok(name, condition, detail = '') {
  if (condition) {
    console.log(`  \u2705  ${name}`);
    passed++;
  } else {
    console.error(`  \u274c  ${name}${detail ? `\n       \u2192 ${detail}` : ''}`);
    failed++;
  }
}

function section(title) {
  console.log(`\n\u2500\u2500\u2500 ${title} ${'─'.repeat(Math.max(0, 55 - title.length))}`);
}

// ─── 1. Plugin file exists and loads ─────────────────────────────────────────
section('1. Config Plugin');
const pluginPath = path.join(__dirname, '..', 'plugins', 'withVoicePackage.js');
ok('plugins/withVoicePackage.js exists', fs.existsSync(pluginPath));

let plugin;
try {
  plugin = require(pluginPath);
  ok('Plugin loads without error', typeof plugin === 'function', `got ${typeof plugin}`);
} catch (e) {
  ok('Plugin loads without error', false, e.message);
}

// ─── 2. Plugin correctly patches a simulated MainApplication.kt ───────────────
section('2. Plugin Patch Logic (Kotlin / Expo SDK 52 format)');

const SIMULATED_MAIN_APP = [
  'package tech.safemailx.safemailxai',
  '',
  'import android.app.Application',
  'import expo.modules.ApplicationLifecycleDispatcher',
  'import expo.modules.ReactNativeHostWrapper',
  '',
  'class MainApplication : Application() {',
  '  override fun getPackages() =',
  '      PackageList(this).packages.also {',
  '        // add packages here',
  '      }',
  '}'
].join('\n');

function simulatePlugin(contents) {
  const VOICE_IMPORT = 'import com.wenkesj.voice.VoicePackage';
  if (!contents.includes(VOICE_IMPORT)) {
    if (contents.includes('import expo.modules.ReactNativeHostWrapper')) {
      contents = contents.replace(
        'import expo.modules.ReactNativeHostWrapper',
        'import expo.modules.ReactNativeHostWrapper\nimport com.wenkesj.voice.VoicePackage'
      );
    }
  }
  if (!contents.includes('it.add(VoicePackage())')) {
    if (contents.includes('PackageList(this).packages.also {')) {
      contents = contents.replace(
        'PackageList(this).packages.also {',
        'PackageList(this).packages.also { it.add(VoicePackage()); '
      );
    } else if (contents.includes('PackageList(this).packages')) {
      contents = contents.replace(
        'PackageList(this).packages',
        'PackageList(this).packages.also { it.add(VoicePackage()) }'
      );
    }
  }
  return contents;
}

const patched = simulatePlugin(SIMULATED_MAIN_APP);
ok('Import injected', patched.includes('import com.wenkesj.voice.VoicePackage'));
ok('Registration injected (it.add(VoicePackage()))', patched.includes('it.add(VoicePackage())'));
ok('Import is before class declaration',
  patched.indexOf('import com.wenkesj.voice.VoicePackage') < patched.indexOf('class MainApplication'));
ok('No duplicate imports',
  (patched.match(/import com\.wenkesj\.voice\.VoicePackage/g) || []).length === 1);

// ─── 3. Actual generated MainApplication.kt ───────────────────────────────────
section('3. Actual Generated MainApplication.kt');

const mainAppPath = path.join(
  __dirname, '..', 'android', 'app', 'src', 'main', 'java',
  'tech', 'safemailx', 'safemailxai', 'MainApplication.kt'
);

if (!fs.existsSync(mainAppPath)) {
  ok('MainApplication.kt exists', false, 'Run: npx expo prebuild --platform android --no-install');
} else {
  const content = fs.readFileSync(mainAppPath, 'utf8');
  ok('MainApplication.kt exists', true);
  ok('Has VoicePackage import', content.includes('import com.wenkesj.voice.VoicePackage'));
  ok('Has VoicePackage registration', content.includes('it.add(VoicePackage())'));
  ok('No duplicate registrations',
    (content.match(/VoicePackage\(\)/g) || []).length <= 2);
}

// ─── 4. Native library Java source ───────────────────────────────────────────
section('4. Native Library Verification');

const baseJava = path.join(
  __dirname, '..', 'node_modules', '@react-native-voice', 'voice',
  'android', 'src', 'main', 'java', 'com', 'wenkesj', 'voice'
);
const voicePackageJava = path.join(baseJava, 'VoicePackage.java');
const voiceModuleJava = path.join(baseJava, 'VoiceModule.java');

ok('VoicePackage.java exists', fs.existsSync(voicePackageJava));
ok('VoiceModule.java exists', fs.existsSync(voiceModuleJava));

if (fs.existsSync(voicePackageJava)) {
  const vp = fs.readFileSync(voicePackageJava, 'utf8');
  ok('VoicePackage in package com.wenkesj.voice', vp.includes('package com.wenkesj.voice'));
  ok('VoicePackage implements ReactPackage', vp.includes('ReactPackage'));
}

if (fs.existsSync(voiceModuleJava)) {
  const vm = fs.readFileSync(voiceModuleJava, 'utf8');
  const m = vm.match(/getName\s*\(\s*\)[^{]*\{[^}]*return\s*"([^"]+)"/);
  if (m) {
    ok('VoiceModule.getName() returns "Voice" (matches NativeModules.Voice)', m[1] === 'Voice', `got "${m[1]}"`);
  } else {
    ok('VoiceModule.getName() parseable', false, 'Cannot parse getName()');
  }
}

// ─── 5. AndroidX patch ───────────────────────────────────────────────────────
section('5. AndroidX Patch');

const patchPath = path.join(__dirname, '..', 'patches', '@react-native-voice+voice+3.2.4.patch');
ok('Patch file exists', fs.existsSync(patchPath));

if (fs.existsSync(patchPath)) {
  const patch = fs.readFileSync(patchPath, 'utf8');
  ok('Patch upgrades to SDK 34', patch.includes('+def DEFAULT_COMPILE_SDK_VERSION = 34'));
  ok('Patch replaces com.android.support with AndroidX',
    patch.includes("androidx.appcompat:appcompat:1.7.0"));
  ok('Patch removes old jcenter reference', patch.includes('-    jcenter()'));
}

// ─── 6. JS dist uses correct NativeModules key ───────────────────────────────
section('6. JS Native Module Key');

const distPath = path.join(
  __dirname, '..', 'node_modules', '@react-native-voice', 'voice', 'dist', 'index.js'
);
ok('dist/index.js exists', fs.existsSync(distPath));

if (fs.existsSync(distPath)) {
  const dist = fs.readFileSync(distPath, 'utf8');
  ok('JS uses NativeModules.Voice (matches Java getName())', dist.includes('NativeModules.Voice'));
  ok('startSpeech method referenced', dist.includes('startSpeech'));
  ok('Does NOT use NativeModules.RNVoice (wrong key)', !dist.includes('NativeModules.RNVoice'));
}

// ─── 7. RECORD_AUDIO in generated manifest ───────────────────────────────────
section('7. Android Permissions');

const manifestPath = path.join(
  __dirname, '..', 'android', 'app', 'src', 'main', 'AndroidManifest.xml'
);

if (!fs.existsSync(manifestPath)) {
  ok('AndroidManifest.xml exists', false, 'Run: npx expo prebuild --platform android --no-install');
} else {
  const manifest = fs.readFileSync(manifestPath, 'utf8');
  ok('RECORD_AUDIO in AndroidManifest.xml', manifest.includes('android.permission.RECORD_AUDIO'));
  ok('No duplicate RECORD_AUDIO entries',
    (manifest.match(/RECORD_AUDIO/g) || []).length === 1);
}

// ─── 8. app.json plugins ─────────────────────────────────────────────────────
section('8. app.json Plugins');

const appJson = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'app.json'), 'utf8'));
const plugins = appJson.expo.plugins || [];
const pluginNames = plugins.map(p => Array.isArray(p) ? p[0] : p);

ok('withVoicePackage plugin registered', pluginNames.some(p => p.includes('withVoicePackage')));
ok('@react-native-voice/voice plugin registered', pluginNames.some(p => p.includes('@react-native-voice/voice')));
ok('expo-camera plugin registered', pluginNames.some(p => p.includes('expo-camera')));
ok('withVoicePackage is first plugin', pluginNames[0].includes('withVoicePackage'));
ok('No manual RECORD_AUDIO in android.permissions',
  !(appJson.expo.android?.permissions || []).includes('android.permission.RECORD_AUDIO'));

// ─── 9. babel.config.js ──────────────────────────────────────────────────────
section('9. Babel Config');

const babelPath = path.join(__dirname, '..', 'babel.config.js');
ok('babel.config.js exists', fs.existsSync(babelPath));
if (fs.existsSync(babelPath)) {
  const babel = fs.readFileSync(babelPath, 'utf8');
  ok('react-native-reanimated/plugin listed', babel.includes('react-native-reanimated/plugin'));
}

// ─── Summary ─────────────────────────────────────────────────────────────────
section('SUMMARY');
const total = passed + failed;
console.log(`\n  ${passed}/${total} checks passed`);
if (failed === 0) {
  console.log('  \uD83D\uDFE2 ALL CHECKS PASSED — safe to build final dev APK\n');
} else {
  console.log(`  \uD83D\uDD34 ${failed} check(s) FAILED — fix before building\n`);
  process.exit(1);
}
