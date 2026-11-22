# openappcc

An open-source, on-device Android APK cloner built with raw Android SDK tools (zero Gradle, zero third-party runtime dependencies beyond Android's `apksig`).

## What This Project Does

`openappcc` (`io.openappcc`) lets you create independent, side-by-side copies of installed Android apps or external `.apk` files directly on an Android device (API 29+).

When cloning an APK, the on-device engine (`Cloner.java`) performs:

- **Manifest AST rewriting (`Axml.java`)**: Renames the package ID (same-length DEX-safe mutation, `.cloneN` suffix, or custom package ID), optionally overrides `versionName`, absolutizes relative component class names, resolves `@string/` provider authority references from `resources.arsc`, rebases `<application>` content provider authorities and `<manifest>` permissions/permission-trees/permission-groups (leaving `<queries>` intact), updates launcher `<activity>`/`<activity-alias>` labels and `taskAffinity`, strips `testOnly`, optionally strips `sharedUserId`/`sharedUserLabel`, adjusts `targetSdkVersion` / `android:exported`, and stamps `io.openappcc.*` metadata.
- **Resource table patching (`Arsc.java`)**: Updates the package name and equal-length global string pool references inside `resources.arsc`, and resolves launcher icon and authority resource paths.
- **In-place DEX string & class rebasing (`Dex.java`)**: Rewrites equal-length package/authority string constants in `classes*.dex`, supports optional **Deep Class Rename** (Dalvik class descriptors) with DEX `string_ids` sort-order verification, drops stale ART `baseline.prof`/`baseline.profm`, and recalculates DEX SHA-1 and native Adler-32 headers.
- **Optional Pure-Java Runtime Hooks (`BootstrapProvider.java` -> 9 KB `hook.dex`)**: Opt-in early-init `ContentProvider` (`initOrder=Integer.MAX_VALUE`, zero native `.so`) supporting original signature spoofing, randomized Android ID, `FLAG_SECURE` screenshot control, custom locale, and custom `Build.MODEL`.
- **Icon customization (`Icon.java`)**: Applies color tinting (12-color palette), horizontal flip, `0°`/`90°`/`180°`/`270°` rotation, and numbered or custom text badges (up to 4 chars) onto launcher icons, with live preview in Clone Studio.
- **Aligned ZIP repacking, ABI filter & V1/V2/V3 signing (`Cloner.java`)**: Supports `Keep Device ABI Only`, optional `Compress Native Libs` (`extractNativeLibs=true`), 16 KB `.so` alignment for Android 15/16, and V1/V2/V3 signing using `apksig`.
- **On-device APK Doctor (`Doctor.java`)**: Inspects any installed app or APK for real v1/v2/v3 signing schemes, SDK versions, ABIs, provider/permission counts, split APKs, and known packer signatures.
- **In-place Clone Updates & Split-aware Install (`MainActivity.java`, `InstallReceiver.java`)**: Updates existing clones in-place (keeping app data) from updated installed apps or external APKs, requests Android 14+ update ownership (`ENFORCE_UPDATE_OWNERSHIP`), and supports `Export APK Only`.

## App UI

- **Installed**: Searchable list of installed apps (`User Apps` / `All Apps` chips, launchable apps sorted first), batch copy stepper (`- 1 +`), batch clone number/range input (`2`, `1-3`), and external APK picker.
- **Clone Studio**: Tap any app to customize clone number, custom launcher label, custom package ID, custom `versionName`, custom badge text (up to 4 chars), live icon preview (tint, horizontal flip, `0°`/`90°`/`180°`/`270°` rotation), `Export APK Only` toggle, `DOCTOR` inspection, and manifest switches:
  - Same-Length Package ID, Tint & Badge Icon, In-Place DEX String Rebase, Strip `sharedUserId`, Min Target SDK (`Off`, `API 31`, `API 34`)
  - Standalone mode (neutralize `FirebaseInitProvider` / GMS version metadata), Disable Autostart (`BOOT_COMPLETED`), Disable Widgets, Disable Link/Share Defaults, Strip Watch / Leanback surfaces, Disable Crash Reporters, Exclude From Recents, Disable `allowBackup`, Enable `debuggable`, Rotation Lock (`Off` / `Portrait` / `Landscape`)
- **Clones**: Lists installed `openappcc` clones with colored `#n` badge and `Open`, `Doctor`, and `Uninstall` actions.
- **Settings**: Engine info, 12-color badge palette preview, persistent default batch switches, external APK picker, and staged cache cleaner.

## Project Structure

```text
AndroidManifest.xml          App manifest (package io.openappcc, minSdk 29, targetSdk 34)
build.ps1                    Zero-Gradle PowerShell build script (aapt2, javac, d8, zipalign, apksigner)
res/
  drawable/                  Rounded card, chip, pill, button, and launcher icon drawables
  layout/                    activity_main.xml, dialog_clone.xml, row_app.xml, row_clone.xml
  values/                    colors.xml, strings.xml, styles.xml
src/io/openappcc/
  MainActivity.java          3-tab UI controller, Clone Studio, APK Doctor dialog, PackageInstaller
  Cloner.java                End-to-end APK cloning pipeline and apksig V1/V2/V3 signing
  Axml.java                  Binary AndroidManifest.xml AST parser and serializer
  Arsc.java                  resources.arsc package renamer and resource path resolver
  Dex.java                   In-place DEX string patcher with checksum/SHA-1 recalculation
  Icon.java                  Raster/adaptive icon tinting, badge drawing, and live preview
  Doctor.java                Static APK inspector
  InstallReceiver.java       PackageInstaller session result BroadcastReceiver
```

## How to Compile

### Prerequisites

- **Windows PowerShell (`pwsh`)**
- **JDK 11+** (providing `javac.exe`, `jar.exe`, and `keytool.exe`; set `JAVA_HOME` if not in a standard install path)
- **Android SDK** (set `ANDROID_HOME` or `ANDROID_SDK_ROOT`) with:
  - `platforms/android-34` (`android.jar`)
  - `build-tools/36.1.0` (or compatible build-tools providing `aapt2.exe`, `d8.bat`, `zipalign.exe`, `apksigner.bat`, and `lib/apksigner.jar`)
    - *Note: On JDK 21+, use `build-tools` 35/36+; older `d8` builds such as `34.0.0` may crash on newer JDKs.*

### Build

```powershell
pwsh -File .\build.ps1
```

What `build.ps1` does automatically:
1. Auto-discovers JDK (`JAVA_HOME` or standard Java directories) and Android SDK (`ANDROID_HOME` / `ANDROID_SDK_ROOT`).
2. Generates a local self-signed PKCS12 keystore at `assets/openappcc.p12` if one does not exist (ignored by Git).
3. Runs `aapt2 compile` -> `aapt2 link` -> `javac --release 11` -> `jar` + `d8` -> `zipalign` -> `apksigner sign` (V1/V2/V3) -> `apksigner verify`.
4. Outputs the signed APK to `openappcc-release.apk`.

### Optional Build Arguments & Keystore Settings

- Run a single build stage (`res`, `link`, `javac`, `dex`, `package`, `sign`, or `all`):
  ```powershell
  pwsh -File .\build.ps1 -Stage sign
  ```
- Override local keystore alias/password (default `openappcc`; must match `KS_ALIAS` / `KS_PASS` in `Cloner.java` for on-device clone signing):
  ```powershell
  $env:OPENAPPCC_KS_ALIAS = "openappcc"
  $env:OPENAPPCC_KS_PASS  = "openappcc"
  pwsh -File .\build.ps1
  ```

### Install on a Device or Emulator

```powershell
adb install -r .\openappcc-release.apk
```

On Android 10+, allow "Install unknown apps" for `openappcc` when prompted (or via `adb shell appops set io.openappcc REQUEST_INSTALL_PACKAGES allow`).

## Automated GitHub Releases (Separate Hidden Release Key)

[`.github/workflows/release.yml`](.github/workflows/release.yml) builds `openappcc-release.apk` automatically on every `v*` tag push (or manual `workflow_dispatch`) using a **separate release signing key** that is never bundled inside the APK or committed to Git.

Add these **Repository Secrets** in GitHub (`Settings -> Secrets and variables -> Actions`):
- `RELEASE_KEYSTORE_B64`: Base64-encoded PKCS12 release keystore (signs `openappcc-release.apk`, kept hidden outside APK)
- `RELEASE_KS_ALIAS`: Release key alias (e.g. `release`)
- `RELEASE_KS_PASS`: Release keystore/key password
- `OPENAPPCC_KEYSTORE_B64` *(optional)*: Base64-encoded `assets/openappcc.p12` (signs cloned apps on-device so clone updates keep the same cert)

## Limitations

- Pure-Java runtime hooks (`sPackageManager`, `sNameValueCache`) rely on reflection and may be restricted by hidden-API enforcement on some Android 14–16 ROMs; `FLAG_SECURE` and `Locale` use public APIs.
- Apps enforcing Play Integrity, hardware-backed attestation, or native C/C++ signature checks may still fail login or push registration when cloned.

## License

See [LICENSE](LICENSE).
