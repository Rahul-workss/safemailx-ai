/**
 * withVoicePackage.js
 *
 * Custom Expo config plugin that manually registers com.wenkesj.voice.VoicePackage
 * in the generated MainApplication.kt.
 *
 * WHY THIS EXISTS:
 *   @react-native-voice/voice v3.2.4 has NO autolinking metadata:
 *   - No react-native.config.js
 *   - No codegenConfig in package.json
 *   - No "react-native" autolinking field in package.json
 *   Therefore expo prebuild never adds VoicePackage to MainApplication.kt,
 *   so NativeModules.Voice is always null at runtime regardless of JS changes.
 *
 *   This plugin patches MainApplication.kt directly during every prebuild.
 */

const { withMainApplication } = require('@expo/config-plugins');

// Exact import line to inject
const VOICE_IMPORT = 'import com.wenkesj.voice.VoicePackage';

const withVoicePackage = (config) => {
  return withMainApplication(config, (config) => {
    let contents = config.modResults.contents;

    // ── Step 1: Add import if missing ────────────────────────────────────────
    if (!contents.includes(VOICE_IMPORT)) {
      // Insert the import right after the last existing import block.
      // The generated MainApplication.kt always has "import expo.modules.ReactNativeHostWrapper"
      // as the last import — insert ours right after it.
      if (contents.includes('import expo.modules.ReactNativeHostWrapper')) {
        contents = contents.replace(
          'import expo.modules.ReactNativeHostWrapper',
          'import expo.modules.ReactNativeHostWrapper\nimport com.wenkesj.voice.VoicePackage'
        );
      } else {
        // Fallback: insert after any "import android.app.Application" line
        contents = contents.replace(
          'import android.app.Application',
          'import android.app.Application\nimport com.wenkesj.voice.VoicePackage'
        );
      }
    }

    // ── Step 2: Register the package in getPackages() if missing ─────────────
    // Expo SDK 52 / RN 0.81 generates this pattern in Kotlin:
    //   PackageList(this).packages.also { it.add(VoicePackage()) }.apply {
    // If our plugin already wrote it (from a previous run), skip.
    if (!contents.includes('it.add(VoicePackage())')) {
      // Pattern 1: Kotlin "also" block — Expo's default generated pattern
      if (contents.includes('PackageList(this).packages.also {')) {
        // Already has an .also block but without VoicePackage — inject inside it
        contents = contents.replace(
          'PackageList(this).packages.also {',
          'PackageList(this).packages.also { it.add(VoicePackage()); '
        );
      } else if (contents.includes('PackageList(this).packages')) {
        // Pattern 2: Plain PackageList — chain an .also block
        contents = contents.replace(
          'PackageList(this).packages',
          'PackageList(this).packages.also { it.add(VoicePackage()) }'
        );
      } else if (contents.includes('return packages')) {
        // Pattern 3: Kotlin-style explicit return
        contents = contents.replace(
          'return packages',
          'packages.add(VoicePackage())\n            return packages'
        );
      } else if (contents.includes('return packages;')) {
        // Pattern 4: Java-style explicit return
        contents = contents.replace(
          'return packages;',
          'packages.add(new VoicePackage());\n            return packages;'
        );
      } else {
        console.warn('[withVoicePackage] WARNING: Could not find insertion point for VoicePackage in MainApplication. Speech recognition may not work.');
      }
    }

    config.modResults.contents = contents;
    return config;
  });
};

module.exports = withVoicePackage;
