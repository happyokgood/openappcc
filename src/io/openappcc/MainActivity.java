package io.openappcc;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * openappcc Android UI: 3-tab controller (Installed / Clones / Settings),
 * Clone Studio dialog with live icon preview, on-device APK Doctor, and split-aware PackageInstaller.
 */
public class MainActivity extends Activity {
    private static final int REQ_PICK_APK = 401;
    private static final int REQ_UNINSTALL = 402;
    private static final int REQ_EXPORT_APK = 403;
    private static final int REQ_PICK_UPDATE_APK = 404;
    private static final String PREFS = "openappcc_prefs";
    private File pendingExportApk;
    private CloneRow pendingUpdateClone;

    static final class AppRow {
        String label, pkg, versionName, sourceDir;
        long versionCode;
        String[] splitDirs;
        boolean isSystem;
        boolean launchable;
        Drawable icon;
        int existingClones;
        int highestCloneNum;
        int copies = 1;
        boolean selected;
    }

    static final class CloneRow {
        String label, pkg, origPkg, sourceDir, versionName;
        long versionCode;
        int cloneNum;
        boolean hasSpoofSig;
        Drawable icon;
    }

    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private SharedPreferences prefs;

    private final List<AppRow> allApps = new ArrayList<>();
    private final List<AppRow> shownApps = new ArrayList<>();
    private final List<CloneRow> cloneRows = new ArrayList<>();

    private boolean showAllApps = false;
    private String searchQuery = "";
    private int currentTab = 0;

    private TextView tabApps, tabClones, tabSettings;
    private View indApps, indClones, indSettings;
    private View pageApps, pageClones, pageSettings;
    private TextView summaryView, clonesSummaryView, clonesEmptyView;
    private EditText numbersInput;
    private AppsAdapter appsAdapter;
    private ClonesAdapter clonesAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);

        tabApps = findViewById(R.id.tabApps);
        tabClones = findViewById(R.id.tabClones);
        tabSettings = findViewById(R.id.tabSettings);
        indApps = findViewById(R.id.indApps);
        indClones = findViewById(R.id.indClones);
        indSettings = findViewById(R.id.indSettings);

        pageApps = findViewById(R.id.pageApps);
        pageClones = findViewById(R.id.pageClones);
        pageSettings = findViewById(R.id.pageSettings);

        summaryView = findViewById(R.id.summary);
        clonesSummaryView = findViewById(R.id.clonesSummary);
        clonesEmptyView = findViewById(R.id.clonesEmpty);
        numbersInput = findViewById(R.id.numbers);

        findViewById(R.id.tabAppsWrap).setOnClickListener(v -> selectTab(0));
        findViewById(R.id.tabClonesWrap).setOnClickListener(v -> selectTab(1));
        findViewById(R.id.tabSettingsWrap).setOnClickListener(v -> selectTab(2));

        findViewById(R.id.topPickApk).setOnClickListener(v -> openApkPicker());
        findViewById(R.id.pickApk).setOnClickListener(v -> openApkPicker());
        findViewById(R.id.settingsPickApk).setOnClickListener(v -> openApkPicker());
        findViewById(R.id.topRescan).setOnClickListener(v -> scanInstalled());
        findViewById(R.id.clonesRefresh).setOnClickListener(v -> scanInstalled());
        findViewById(R.id.cloneSelected).setOnClickListener(v -> cloneBatchSelected());
        findViewById(R.id.settingsClearCache).setOnClickListener(v -> clearCloneCache());

        TextView chipUser = findViewById(R.id.chipUser);
        TextView chipAll = findViewById(R.id.chipAll);
        chipUser.setOnClickListener(v -> {
            showAllApps = false;
            styleChip(chipUser, true);
            styleChip(chipAll, false);
            applyFilter();
        });
        chipAll.setOnClickListener(v -> {
            showAllApps = true;
            styleChip(chipUser, false);
            styleChip(chipAll, true);
            applyFilter();
        });

        EditText search = findViewById(R.id.search);
        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(Editable s) {
                searchQuery = s == null ? "" : s.toString().trim().toLowerCase(Locale.US);
                applyFilter();
            }
        });

        ListView appsList = findViewById(R.id.apps);
        appsAdapter = new AppsAdapter();
        appsList.setAdapter(appsAdapter);

        ListView clonesList = findViewById(R.id.clonesList);
        clonesAdapter = new ClonesAdapter();
        clonesList.setAdapter(clonesAdapter);

        setupSettings();
        selectTab(0);
        scanInstalled();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        worker.shutdownNow();
    }

    private int dp(int v) {
        return Math.round(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, getResources().getDisplayMetrics()));
    }

    private void styleChip(TextView tv, boolean active) {
        tv.setBackgroundResource(active ? R.drawable.bg_chip_active : R.drawable.bg_chip_idle);
        tv.setTextColor(active ? Color.WHITE : getColor(R.color.text_primary));
        tv.setTypeface(null, active ? Typeface.BOLD : Typeface.NORMAL);
    }

    private void selectTab(int tab) {
        currentTab = tab;
        pageApps.setVisibility(tab == 0 ? View.VISIBLE : View.GONE);
        pageClones.setVisibility(tab == 1 ? View.VISIBLE : View.GONE);
        pageSettings.setVisibility(tab == 2 ? View.VISIBLE : View.GONE);

        tabApps.setTextColor(tab == 0 ? Color.WHITE : getColor(R.color.text_muted));
        tabApps.setTypeface(null, tab == 0 ? Typeface.BOLD : Typeface.NORMAL);
        indApps.setBackgroundColor(tab == 0 ? getColor(R.color.accent) : Color.TRANSPARENT);

        tabClones.setTextColor(tab == 1 ? Color.WHITE : getColor(R.color.text_muted));
        tabClones.setTypeface(null, tab == 1 ? Typeface.BOLD : Typeface.NORMAL);
        indClones.setBackgroundColor(tab == 1 ? getColor(R.color.accent) : Color.TRANSPARENT);

        tabSettings.setTextColor(tab == 2 ? Color.WHITE : getColor(R.color.text_muted));
        tabSettings.setTypeface(null, tab == 2 ? Typeface.BOLD : Typeface.NORMAL);
        indSettings.setBackgroundColor(tab == 2 ? getColor(R.color.accent) : Color.TRANSPARENT);
    }

    private void setupSettings() {
        TextView about = findViewById(R.id.settingsAbout);
        about.setText("Package: io.openappcc v1.1.0\n"
                + "Engine: AST AXML + ARSC + In-Place DEX + V1/V2/V3 apksig\n"
                + "Keystore: embedded assets/openappcc.p12\n"
                + "Tip: Tap any installed app to customize switches or long-press for APK Doctor.");

        LinearLayout row1 = findViewById(R.id.paletteRow1);
        LinearLayout row2 = findViewById(R.id.paletteRow2);
        row1.removeAllViews();
        row2.removeAllViews();
        for (int i = 1; i <= 12; i++) {
            TextView swatch = new TextView(this);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(dp(36), dp(36));
            lp.setMargins(dp(4), dp(2), dp(4), dp(2));
            swatch.setLayoutParams(lp);
            swatch.setGravity(Gravity.CENTER);
            swatch.setText(String.valueOf(i));
            swatch.setTextColor(Color.WHITE);
            swatch.setTextSize(12f);
            swatch.setTypeface(null, Typeface.BOLD);
            GradientDrawable bg = new GradientDrawable();
            bg.setShape(GradientDrawable.OVAL);
            bg.setColor(Icon.color(i));
            swatch.setBackground(bg);
            (i <= 6 ? row1 : row2).addView(swatch);
        }

        bindPrefSwitch(R.id.defSameLength, "sameLength", true);
        bindPrefSwitch(R.id.defTintIcon, "tintIcon", true);
        bindPrefSwitch(R.id.defBadgeIcon, "badgeIcon", true);
        bindPrefSwitch(R.id.defMultiColor, "multiColor", true);
        bindPrefSwitch(R.id.defPatchDex, "patchDex", true);
        bindPrefSwitch(R.id.defRenameClasses, "renameClasses", false);
        bindPrefSwitch(R.id.defSpoofSig, "spoofSignature", false);
        bindPrefSwitch(R.id.defSpoofAndroidId, "spoofAndroidId", false);
        bindPrefSwitch(R.id.defKeepDeviceAbi, "keepDeviceAbiOnly", false);
        bindPrefSwitch(R.id.defCompressNative, "compressNativeLibs", false);
        bindPrefSwitch(R.id.defStandalone, "standalone", false);
        bindPrefSwitch(R.id.defNoAutostart, "noAutostart", false);
        bindPrefSwitch(R.id.defNoCrash, "noCrashReporters", false);
        findViewById(R.id.settingsResetDefaults).setOnClickListener(v -> {
            prefs.edit().clear().apply();
            setupSettings();
            Toast.makeText(this, "Default settings reset", Toast.LENGTH_SHORT).show();
        });
    }

    private void bindPrefSwitch(int viewId, String key, boolean defVal) {
        Switch sw = findViewById(viewId);
        sw.setOnCheckedChangeListener(null);
        sw.setChecked(prefs.getBoolean(key, defVal));
        sw.setOnCheckedChangeListener((btn, checked) -> prefs.edit().putBoolean(key, checked).apply());
    }

    private Cloner.Options defaultOptions() {
        Cloner.Options o = new Cloner.Options();
        o.sameLength = prefs.getBoolean("sameLength", true);
        o.tintIcon = prefs.getBoolean("tintIcon", true);
        o.badgeIcon = prefs.getBoolean("badgeIcon", true);
        o.multiColor = prefs.getBoolean("multiColor", true);
        o.patchDex = prefs.getBoolean("patchDex", true);
        o.renameClasses = prefs.getBoolean("renameClasses", false);
        o.spoofSignature = prefs.getBoolean("spoofSignature", false);
        o.spoofAndroidId = prefs.getBoolean("spoofAndroidId", false);
        o.keepDeviceAbiOnly = prefs.getBoolean("keepDeviceAbiOnly", false);
        o.compressNativeLibs = prefs.getBoolean("compressNativeLibs", false);
        o.standalone = prefs.getBoolean("standalone", false);
        o.noAutostart = prefs.getBoolean("noAutostart", false);
        o.noCrashReporters = prefs.getBoolean("noCrashReporters", false);
        return o;
    }

    private void scanInstalled() {
        summaryView.setText(R.string.summary_loading);
        worker.execute(() -> {
            PackageManager pm = getPackageManager();
            List<ApplicationInfo> apps = pm.getInstalledApplications(PackageManager.GET_META_DATA);

            List<AppRow> scannedApps = new ArrayList<>();
            List<CloneRow> scannedClones = new ArrayList<>();
            Map<String, Integer> cloneCountByOrig = new HashMap<>();
            Map<String, Integer> maxNumByOrig = new HashMap<>();

            for (ApplicationInfo ai : apps) {
                if (getPackageName().equals(ai.packageName)) continue;
                int cloneNum = 0;
                String origPkg = null;
                if (ai.metaData != null) {
                    cloneNum = ai.metaData.getInt("io.openappcc.CLONE", 0);
                    origPkg = ai.metaData.getString("io.openappcc.ORIGINAL");
                }
                if (cloneNum > 0) {
                    CloneRow cr = new CloneRow();
                    cr.pkg = ai.packageName;
                    cr.origPkg = origPkg != null ? origPkg : "(unknown)";
                    cr.cloneNum = cloneNum;
                    cr.sourceDir = ai.sourceDir;
                    cr.label = String.valueOf(ai.loadLabel(pm));
                    cr.icon = ai.loadIcon(pm);
                    cr.hasSpoofSig = ai.metaData != null && ai.metaData.containsKey("io.openappcc.ORIGINAL_SIG");
                    try {
                        PackageInfo cpi = pm.getPackageInfo(ai.packageName, 0);
                        cr.versionName = cpi.versionName != null ? cpi.versionName : "";
                        cr.versionCode = cpi.getLongVersionCode();
                    } catch (Exception ignored) {
                        cr.versionName = "";
                    }
                    scannedClones.add(cr);

                    if (origPkg != null) {
                        cloneCountByOrig.put(origPkg, cloneCountByOrig.getOrDefault(origPkg, 0) + 1);
                        maxNumByOrig.put(origPkg, Math.max(maxNumByOrig.getOrDefault(origPkg, 0), cloneNum));
                    }
                    continue;
                }

                AppRow row = new AppRow();
                row.pkg = ai.packageName;
                row.label = String.valueOf(ai.loadLabel(pm));
                row.sourceDir = ai.sourceDir;
                row.splitDirs = ai.splitSourceDirs;
                row.isSystem = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0
                        && (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0;
                row.launchable = pm.getLaunchIntentForPackage(ai.packageName) != null;
                row.icon = ai.loadIcon(pm);
                try {
                    PackageInfo pi = pm.getPackageInfo(ai.packageName, 0);
                    row.versionName = pi.versionName;
                    row.versionCode = pi.getLongVersionCode();
                } catch (Exception ignored) {
                    row.versionName = "";
                }
                scannedApps.add(row);
            }

            for (AppRow r : scannedApps) {
                r.existingClones = cloneCountByOrig.getOrDefault(r.pkg, 0);
                r.highestCloneNum = maxNumByOrig.getOrDefault(r.pkg, 0);
            }

            Collections.sort(scannedApps, (a, b) -> {
                int c = Boolean.compare(b.launchable, a.launchable);
                return c != 0 ? c : a.label.compareToIgnoreCase(b.label);
            });
            Collections.sort(scannedClones, (a, b) -> {
                int c = a.label.compareToIgnoreCase(b.label);
                return c != 0 ? c : Integer.compare(a.cloneNum, b.cloneNum);
            });

            runOnUiThread(() -> {
                allApps.clear();
                allApps.addAll(scannedApps);
                cloneRows.clear();
                cloneRows.addAll(scannedClones);
                boolean hasUserApp = false;
                for (AppRow r : allApps) {
                    if (!r.isSystem) {
                        hasUserApp = true;
                        break;
                    }
                }
                if (!showAllApps && !hasUserApp && !allApps.isEmpty()) {
                    showAllApps = true;
                    styleChip(findViewById(R.id.chipUser), false);
                    styleChip(findViewById(R.id.chipAll), true);
                }
                tabClones.setText(cloneRows.isEmpty() ? getString(R.string.tab_clones) : "Clones (" + cloneRows.size() + ")");
                clonesSummaryView.setText(cloneRows.size() + " installed clone(s)");
                clonesEmptyView.setVisibility(cloneRows.isEmpty() ? View.VISIBLE : View.GONE);
                clonesAdapter.notifyDataSetChanged();
                applyFilter();
            });
        });
    }

    private void applyFilter() {
        shownApps.clear();
        for (AppRow r : allApps) {
            if (!showAllApps && r.isSystem) continue;
            if (!searchQuery.isEmpty()) {
                boolean hit = r.label.toLowerCase(Locale.US).contains(searchQuery)
                        || r.pkg.toLowerCase(Locale.US).contains(searchQuery);
                if (!hit) continue;
            }
            shownApps.add(r);
        }
        appsAdapter.notifyDataSetChanged();
        summaryView.setText(shownApps.size() + " apps shown (" + cloneRows.size() + " clones installed)");
    }

    static List<Integer> parseNumbers(String raw, int nextFree, int fallbackCount) {
        LinkedHashSet<Integer> nums = new LinkedHashSet<>();
        String s = raw == null ? "" : raw.trim();
        if (s.isEmpty()) {
            for (int i = 0; i < Math.max(1, fallbackCount); i++) nums.add(nextFree + i);
            return new ArrayList<>(nums);
        }
        for (String part : s.split(",")) {
            String t = part.trim();
            if (t.isEmpty()) continue;
            int dash = t.indexOf('-');
            if (dash > 0) {
                try {
                    int a = Integer.parseInt(t.substring(0, dash).trim());
                    int b = Integer.parseInt(t.substring(dash + 1).trim());
                    int lo = Math.max(1, Math.min(a, b));
                    int hi = Math.min(lo + 19, Math.max(a, b));
                    for (int n = lo; n <= hi; n++) nums.add(n);
                } catch (NumberFormatException ignored) {
                }
            } else {
                try {
                    int v = Integer.parseInt(t);
                    if (v >= 1) nums.add(v);
                } catch (NumberFormatException ignored) {
                }
            }
        }
        if (nums.isEmpty()) nums.add(nextFree);
        return new ArrayList<>(nums);
    }

    private void openCloneStudio(AppRow app, File externalApk) {
        openCloneStudio(app, externalApk, null);
    }

    private void openCloneStudio(AppRow app, File externalApk, CloneRow updateTarget) {
        View view = getLayoutInflater().inflate(R.layout.dialog_clone, null);
        ImageView previewIcon = view.findViewById(R.id.dlgPreviewIcon);
        TextView appNameTv = view.findViewById(R.id.dlgAppName);
        TextView origPkgTv = view.findViewById(R.id.dlgOrigPkg);
        TextView targetPkgTv = view.findViewById(R.id.dlgTargetPkg);
        EditText rangeEt = view.findViewById(R.id.dlgNumberRange);
        EditText labelEt = view.findViewById(R.id.dlgLabel);
        EditText customPkgEt = view.findViewById(R.id.dlgCustomPkg);
        EditText versionNameEt = view.findViewById(R.id.dlgVersionName);
        EditText badgeTextEt = view.findViewById(R.id.dlgBadgeText);

        Switch swSameLength = view.findViewById(R.id.swSameLength);
        Switch swTintIcon = view.findViewById(R.id.swTintIcon);
        Switch swBadgeIcon = view.findViewById(R.id.swBadgeIcon);
        Switch swMultiColor = view.findViewById(R.id.swMultiColor);
        Switch swFlipIcon = view.findViewById(R.id.swFlipIcon);
        Spinner spRotateIcon = view.findViewById(R.id.spRotateIcon);
        Switch swPatchDex = view.findViewById(R.id.swPatchDex);
        Switch swRenameClasses = view.findViewById(R.id.swRenameClasses);
        Switch swSpoofSig = view.findViewById(R.id.swSpoofSig);
        Switch swKeepDeviceAbi = view.findViewById(R.id.swKeepDeviceAbi);
        Switch swCompressNative = view.findViewById(R.id.swCompressNative);
        Switch swExportOnly = view.findViewById(R.id.swExportOnly);
        Switch swStripUid = view.findViewById(R.id.swStripSharedUid);
        Spinner spMinSdk = view.findViewById(R.id.spMinSdk);

        Switch swStandalone = view.findViewById(R.id.swStandalone);
        Switch swNoAuto = view.findViewById(R.id.swNoAutostart);
        Switch swNoWid = view.findViewById(R.id.swNoWidgets);
        Switch swNoDef = view.findViewById(R.id.swNoAppDefaults);
        Switch swNoWear = view.findViewById(R.id.swNoWearable);
        Switch swNoCrash = view.findViewById(R.id.swNoCrash);
        Switch swExRec = view.findViewById(R.id.swExcludeRecents);
        Switch swNoBack = view.findViewById(R.id.swNoBackup);
        Switch swDebug = view.findViewById(R.id.swDebuggable);
        Switch swSpoofAndroidId = view.findViewById(R.id.swSpoofAndroidId);
        Spinner spScreenshots = view.findViewById(R.id.spScreenshots);
        EditText customLocaleEt = view.findViewById(R.id.dlgCustomLocale);
        EditText customModelEt = view.findViewById(R.id.dlgCustomModel);
        Spinner spRotation = view.findViewById(R.id.spRotation);

        ArrayAdapter<String> iconRotAdp = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item,
                new String[]{"0°", "90°", "180°", "270°"});
        iconRotAdp.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spRotateIcon.setAdapter(iconRotAdp);

        ArrayAdapter<String> sdkAdp = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item,
                new String[]{"Off (keep)", "API 31 (Android 12)", "API 34 (Android 14)"});
        sdkAdp.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spMinSdk.setAdapter(sdkAdp);

        ArrayAdapter<String> rotAdp = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item,
                new String[]{"Off", "Portrait", "Landscape"});
        rotAdp.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spRotation.setAdapter(rotAdp);

        ArrayAdapter<String> shotAdp = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item,
                new String[]{"Default", "Allow", "Block"});
        shotAdp.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spScreenshots.setAdapter(shotAdp);

        Cloner.Options defs = defaultOptions();
        swSameLength.setChecked(defs.sameLength);
        swTintIcon.setChecked(defs.tintIcon);
        swBadgeIcon.setChecked(defs.badgeIcon);
        swMultiColor.setChecked(defs.multiColor);
        swPatchDex.setChecked(defs.patchDex);
        swRenameClasses.setChecked(defs.renameClasses);
        swSpoofSig.setChecked(defs.spoofSignature);
        swSpoofAndroidId.setChecked(defs.spoofAndroidId);
        swKeepDeviceAbi.setChecked(defs.keepDeviceAbiOnly);
        swCompressNative.setChecked(defs.compressNativeLibs);
        swStandalone.setChecked(defs.standalone);
        swNoAuto.setChecked(defs.noAutostart);
        swNoCrash.setChecked(defs.noCrashReporters);
        if (updateTarget != null) {
            rangeEt.setText(String.valueOf(updateTarget.cloneNum));
            labelEt.setText(updateTarget.label);
            customPkgEt.setText(updateTarget.pkg);
            swSpoofSig.setChecked(updateTarget.hasSpoofSig);
        }

        int nextFree = updateTarget != null ? updateTarget.cloneNum : Math.max(1, app.highestCloneNum + 1);
        appNameTv.setText(app.label);
        origPkgTv.setText(app.pkg);

        Runnable refreshPreview = () -> {
            List<Integer> nums = parseNumbers(rangeEt.getText().toString(), nextFree, 1);
            int previewNum = nums.get(0);
            String customPkg = customPkgEt.getText().toString().trim();
            if (!customPkg.isEmpty()) {
                if (isValidPackage(customPkg)) {
                    targetPkgTv.setText("-> " + customPkg);
                } else {
                    targetPkgTv.setText("Invalid custom package ID");
                }
            } else {
                try {
                    String tgt = Cloner.generatePackage(app.pkg, previewNum, swSameLength.isChecked());
                    targetPkgTv.setText("-> " + tgt + (nums.size() > 1 ? " (+" + (nums.size() - 1) + " more)" : ""));
                } catch (Exception ex) {
                    targetPkgTv.setText("Invalid package: " + ex.getMessage());
                }
            }
            boolean tint = swTintIcon.isChecked();
            boolean badge = swBadgeIcon.isChecked();
            boolean multi = swMultiColor.isChecked();
            boolean flip = swFlipIcon.isChecked();
            int rotDeg = spRotateIcon.getSelectedItemPosition() * 90;
            String bText = badgeTextEt.getText().toString().trim();
            boolean drawBadge = badge || !bText.isEmpty();
            if ((tint || drawBadge || flip || rotDeg != 0) && app.icon != null) {
                Bitmap bmp = Icon.paintBitmap(app.icon, previewNum, Cloner.ICON_STRENGTH, drawBadge, tint, flip, rotDeg, bText, multi);
                if (bmp != null) previewIcon.setImageBitmap(bmp);
                else previewIcon.setImageDrawable(app.icon);
            } else {
                previewIcon.setImageDrawable(app.icon);
            }
        };

        TextView cNext = view.findViewById(R.id.dlgChipNext);
        TextView c1 = view.findViewById(R.id.dlgChip1);
        TextView c2 = view.findViewById(R.id.dlgChip2);
        TextView c3 = view.findViewById(R.id.dlgChip3);
        TextView c13 = view.findViewById(R.id.dlgChip13);
        TextView[] chips = {cNext, c1, c2, c3, c13};
        String[] chipVals = {"", "1", "2", "3", "1-3"};
        for (int i = 0; i < chips.length; i++) {
            final int idx = i;
            chips[i].setOnClickListener(v -> {
                for (int j = 0; j < chips.length; j++) styleChip(chips[j], j == idx);
                rangeEt.setText(chipVals[idx]);
                refreshPreview.run();
            });
        }

        TextWatcher previewWatcher = new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(Editable s) { refreshPreview.run(); }
        };
        rangeEt.addTextChangedListener(previewWatcher);
        customPkgEt.addTextChangedListener(previewWatcher);
        badgeTextEt.addTextChangedListener(previewWatcher);
        swSameLength.setOnCheckedChangeListener((b, c) -> refreshPreview.run());
        swTintIcon.setOnCheckedChangeListener((b, c) -> refreshPreview.run());
        swBadgeIcon.setOnCheckedChangeListener((b, c) -> refreshPreview.run());
        swMultiColor.setOnCheckedChangeListener((b, c) -> refreshPreview.run());
        swFlipIcon.setOnCheckedChangeListener((b, c) -> refreshPreview.run());
        spRotateIcon.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> parent, View v, int pos, long id) { refreshPreview.run(); }
            @Override public void onNothingSelected(AdapterView<?> parent) {}
        });
        refreshPreview.run();

        AlertDialog dlg = new AlertDialog.Builder(this)
                .setTitle(updateTarget != null ? "Update Clone #" + updateTarget.cloneNum : "Clone Studio")
                .setView(view)
                .setNegativeButton("Cancel", null)
                .setNeutralButton("Doctor", null)
                .setPositiveButton(updateTarget != null ? "Update & Install" : "Clone & Install", null)
                .create();

        dlg.setOnShowListener(d -> {
            dlg.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> {
                File f = externalApk != null ? externalApk : new File(app.sourceDir);
                showDoctorDialog(app.label, f);
            });
            dlg.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
                String customPkg = customPkgEt.getText().toString().trim();
                if (!customPkg.isEmpty() && !isValidPackage(customPkg)) {
                    Toast.makeText(this, "Invalid custom package ID: " + customPkg, Toast.LENGTH_LONG).show();
                    return;
                }
                List<Integer> nums = customPkg.isEmpty()
                        ? parseNumbers(rangeEt.getText().toString(), nextFree, 1)
                        : Collections.singletonList(parseNumbers(rangeEt.getText().toString(), nextFree, 1).get(0));
                String customLbl = labelEt.getText().toString().trim();
                Cloner.Options opts = new Cloner.Options();
                opts.sameLength = swSameLength.isChecked();
                opts.tintIcon = swTintIcon.isChecked();
                opts.badgeIcon = swBadgeIcon.isChecked();
                opts.multiColor = swMultiColor.isChecked();
                opts.flipIcon = swFlipIcon.isChecked();
                opts.rotateIcon = spRotateIcon.getSelectedItemPosition() * 90;
                opts.badgeText = badgeTextEt.getText().toString().trim();
                opts.customVersionName = versionNameEt.getText().toString().trim();
                if (!customPkg.isEmpty()) opts.overridePackage = customPkg;
                opts.patchDex = swPatchDex.isChecked();
                opts.renameClasses = swRenameClasses.isChecked();
                opts.spoofSignature = swSpoofSig.isChecked();
                opts.keepDeviceAbiOnly = swKeepDeviceAbi.isChecked();
                opts.compressNativeLibs = swCompressNative.isChecked();
                opts.stripSharedUid = swStripUid.isChecked();
                int sdkSel = spMinSdk.getSelectedItemPosition();
                opts.minTargetSdk = sdkSel == 1 ? 31 : (sdkSel == 2 ? 34 : 0);
                opts.standalone = swStandalone.isChecked();
                opts.noAutostart = swNoAuto.isChecked();
                opts.noWidgets = swNoWid.isChecked();
                opts.noAppDefaults = swNoDef.isChecked();
                opts.noWearable = swNoWear.isChecked();
                opts.noCrashReporters = swNoCrash.isChecked();
                opts.excludeRecents = swExRec.isChecked();
                opts.noBackup = swNoBack.isChecked();
                opts.debuggable = swDebug.isChecked();
                opts.spoofAndroidId = swSpoofAndroidId.isChecked();
                int shotSel = spScreenshots.getSelectedItemPosition();
                opts.screenshotMode = shotSel == 1 ? "allow" : (shotSel == 2 ? "block" : null);
                opts.customLocale = customLocaleEt.getText().toString().trim();
                opts.customModel = customModelEt.getText().toString().trim();
                int rotSel = spRotation.getSelectedItemPosition();
                opts.rotationLock = rotSel == 1 ? "portrait" : (rotSel == 2 ? "landscape" : null);
                opts.customLabel = customLbl;
                boolean exportOnly = swExportOnly.isChecked();
                dlg.dismiss();
                runCloneTasks(Collections.singletonList(app), nums, opts, externalApk, "", exportOnly);
            });
        });
        dlg.show();
    }

    private void cloneBatchSelected() {
        List<AppRow> chosen = new ArrayList<>();
        for (AppRow r : shownApps) {
            if (r.selected) chosen.add(r);
        }
        if (chosen.isEmpty()) {
            Toast.makeText(this, "Tick one or more apps, or tap a card for Clone Studio", Toast.LENGTH_SHORT).show();
            return;
        }
        String rangeText = numbersInput.getText().toString();
        Cloner.Options opts = defaultOptions();
        runCloneTasks(chosen, null, opts, null, rangeText);
    }

    private void runCloneTasks(List<AppRow> apps, List<Integer> explicitNums, Cloner.Options template, File externalApk) {
        runCloneTasks(apps, explicitNums, template, externalApk, "");
    }

    private static boolean isValidPackage(String pkg) {
        return pkg != null && pkg.matches("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+$");
    }

    private void runCloneTasks(List<AppRow> apps, List<Integer> explicitNums, Cloner.Options template,
                                File externalApk, String rangeText) {
        runCloneTasks(apps, explicitNums, template, externalApk, rangeText, false);
    }

    private void runCloneTasks(List<AppRow> apps, List<Integer> explicitNums, Cloner.Options template,
                                File externalApk, String rangeText, boolean exportOnly) {
        AlertDialog progress = new AlertDialog.Builder(this)
                .setTitle(exportOnly ? "Building APK" : "Cloning")
                .setMessage("Starting...")
                .setCancelable(false)
                .create();
        progress.show();

        worker.execute(() -> {
            File stageRoot = new File(getCacheDir(), "clones");
            stageRoot.mkdirs();
            int ok = 0;
            StringBuilder errors = new StringBuilder();
            File exportedFile = null;
            String exportedPkg = null;

            for (AppRow app : apps) {
                int nextFree = Math.max(1, app.highestCloneNum + 1);
                List<Integer> nums = explicitNums != null
                        ? explicitNums
                        : parseNumbers(rangeText, nextFree, app.copies);

                for (int num : nums) {
                    try {
                        Cloner.Options opts = copyOptions(template);
                        opts.cloneNumber = num;
                        if (opts.customLabel == null || opts.customLabel.isEmpty()) {
                            opts.customLabel = app.label + " " + num;
                        } else if (nums.size() > 1) {
                            opts.customLabel = opts.customLabel + " " + num;
                        }

                        runOnUiThread(() -> progress.setMessage(app.label + " #" + num + "\nStage: " + Cloner.Result.stage));

                        File srcBase = externalApk != null ? externalApk : new File(app.sourceDir);
                        File batchDir = new File(stageRoot, app.pkg + "_" + num + "_" + System.currentTimeMillis());
                        batchDir.mkdirs();

                        File outBase = new File(batchDir, "base.apk");
                        Cloner.Result res = Cloner.clone(this, srcBase, outBase, opts);
                        List<File> installFiles = new ArrayList<>();
                        installFiles.add(res.file);

                        if (!exportOnly && externalApk == null && app.splitDirs != null) {
                            int spIdx = 0;
                            for (String spPath : app.splitDirs) {
                                spIdx++;
                                Cloner.Options spOpts = copyOptions(opts);
                                spOpts.isSplit = true;
                                spOpts.tintIcon = false;
                                spOpts.badgeIcon = false;
                                spOpts.flipIcon = false;
                                spOpts.rotateIcon = 0;
                                spOpts.badgeText = null;
                                spOpts.customLabel = null;
                                spOpts.customVersionName = null;
                                spOpts.overridePackage = res.newPackage;
                                File outSp = new File(batchDir, "split" + spIdx + ".apk");
                                Cloner.Result spRes = Cloner.clone(this, new File(spPath), outSp, spOpts);
                                installFiles.add(spRes.file);
                            }
                        }

                        ok++;
                        if (exportOnly) {
                            exportedFile = res.file;
                            exportedPkg = res.newPackage;
                        } else {
                            String installedPkg = res.newPackage;
                            runOnUiThread(() -> installSet(installFiles, installedPkg));
                        }
                    } catch (Throwable t) {
                        errors.append(app.label).append(" #").append(num).append(" (")
                                .append(Cloner.Result.stage).append("): ").append(t.getMessage()).append('\n');
                    }
                }
            }

            final int okCount = ok;
            final String errText = errors.toString().trim();
            final File finalExportFile = exportedFile;
            final String finalExportPkg = exportedPkg;
            runOnUiThread(() -> {
                progress.dismiss();
                if (!errText.isEmpty()) {
                    new AlertDialog.Builder(this)
                            .setTitle("Clone Finished (" + okCount + " ok)")
                            .setMessage(errText)
                            .setPositiveButton("OK", null)
                            .show();
                } else if (exportOnly && finalExportFile != null) {
                    launchExportPicker(finalExportFile, finalExportPkg);
                } else {
                    Toast.makeText(this, "Staged " + okCount + " clone(s) for install", Toast.LENGTH_SHORT).show();
                }
                scanInstalled();
            });
        });
    }

    private void launchExportPicker(File apkFile, String pkgName) {
        pendingExportApk = apkFile;
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/vnd.android.package-archive")
                .putExtra(Intent.EXTRA_TITLE, (pkgName != null ? pkgName : "clone") + ".apk");
        startActivityForResult(i, REQ_EXPORT_APK);
    }

    private Cloner.Options copyOptions(Cloner.Options src) {
        Cloner.Options o = new Cloner.Options();
        o.cloneNumber = src.cloneNumber;
        o.customLabel = src.customLabel;
        o.sameLength = src.sameLength;
        o.tintIcon = src.tintIcon;
        o.badgeIcon = src.badgeIcon;
        o.multiColor = src.multiColor;
        o.flipIcon = src.flipIcon;
        o.rotateIcon = src.rotateIcon;
        o.badgeText = src.badgeText;
        o.customVersionName = src.customVersionName;
        o.patchDex = src.patchDex;
        o.renameClasses = src.renameClasses;
        o.spoofSignature = src.spoofSignature;
        o.spoofAndroidId = src.spoofAndroidId;
        o.screenshotMode = src.screenshotMode;
        o.customLocale = src.customLocale;
        o.customModel = src.customModel;
        o.keepDeviceAbiOnly = src.keepDeviceAbiOnly;
        o.compressNativeLibs = src.compressNativeLibs;
        o.keepAbi = src.keepAbi;
        o.standalone = src.standalone;
        o.stripSharedUid = src.stripSharedUid;
        o.minTargetSdk = src.minTargetSdk;
        o.noAutostart = src.noAutostart;
        o.noWidgets = src.noWidgets;
        o.noAppDefaults = src.noAppDefaults;
        o.noWearable = src.noWearable;
        o.noCrashReporters = src.noCrashReporters;
        o.rotationLock = src.rotationLock;
        o.excludeRecents = src.excludeRecents;
        o.debuggable = src.debuggable;
        o.noBackup = src.noBackup;
        o.isSplit = src.isSplit;
        o.overridePackage = src.overridePackage;
        return o;
    }

    private void installSet(List<File> files, String pkg) {
        try {
            PackageInstaller pi = getPackageManager().getPackageInstaller();
            PackageInstaller.SessionParams sp =
                    new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
            // Never call setAppPackageName(): PackageManager verifies against the APK manifest directly.
            long total = 0;
            for (File f : files) total += f.length();
            sp.setSize(total);
            if (android.os.Build.VERSION.SDK_INT >= 34) {
                sp.setRequestUpdateOwnership(true);
            }
            int id = pi.createSession(sp);
            PackageInstaller.Session session = pi.openSession(id);
            try {
                int n = 0;
                byte[] buf = new byte[65536];
                for (File f : files) {
                    n++;
                    String name = n == 1 ? "base.apk" : "split" + n + ".apk";
                    OutputStream out = session.openWrite(name, 0, f.length());
                    FileInputStream in = new FileInputStream(f);
                    try {
                        int r;
                        while ((r = in.read(buf)) > 0) out.write(buf, 0, r);
                        out.flush();
                        session.fsync(out);
                    } finally {
                        in.close();
                        out.close();
                    }
                }
                Intent cb = new Intent(this, InstallReceiver.class).setAction(InstallReceiver.ACTION);
                PendingIntent pending = PendingIntent.getBroadcast(
                        this, id, cb, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);
                session.commit(pending.getIntentSender());
            } finally {
                session.close();
            }
        } catch (Throwable t) {
            Toast.makeText(this, "Install session failed for " + pkg + ": " + t.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void showDoctorDialog(String title, File apkFile) {
        AlertDialog busy = new AlertDialog.Builder(this)
                .setTitle("APK Doctor")
                .setMessage("Inspecting " + title + "...")
                .create();
        busy.show();
        worker.execute(() -> {
            String report = Doctor.inspectReport(apkFile);
            runOnUiThread(() -> {
                busy.dismiss();
                TextView tv = new TextView(this);
                int p = dp(16);
                tv.setPadding(p, p, p, p);
                tv.setText(report);
                tv.setTextSize(12f);
                tv.setTypeface(Typeface.MONOSPACE);
                tv.setTextColor(getColor(R.color.text_primary));
                ScrollView sv = new ScrollView(this);
                sv.addView(tv);
                new AlertDialog.Builder(this)
                        .setTitle("Doctor: " + title)
                        .setView(sv)
                        .setPositiveButton("Close", null)
                        .show();
            });
        });
    }

    private void openApkPicker() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("*/*");
        startActivityForResult(i, REQ_PICK_APK);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_UNINSTALL) {
            scanInstalled();
            return;
        }
        if (requestCode == REQ_EXPORT_APK && resultCode == RESULT_OK && data != null && data.getData() != null) {
            final Uri dest = data.getData();
            final File srcFile = pendingExportApk;
            pendingExportApk = null;
            if (srcFile != null && srcFile.exists()) {
                worker.execute(() -> {
                    try (FileInputStream in = new FileInputStream(srcFile);
                         OutputStream out = getContentResolver().openOutputStream(dest)) {
                        if (out == null) throw new IllegalStateException("Cannot open export URI");
                        byte[] buf = new byte[65536];
                        int r;
                        while ((r = in.read(buf)) > 0) out.write(buf, 0, r);
                        out.flush();
                        runOnUiThread(() -> Toast.makeText(this, "Exported APK successfully", Toast.LENGTH_LONG).show());
                    } catch (Throwable t) {
                        runOnUiThread(() -> Toast.makeText(this, "Export failed: " + t.getMessage(), Toast.LENGTH_LONG).show());
                    }
                });
            }
            return;
        }
        if ((requestCode == REQ_PICK_APK || requestCode == REQ_PICK_UPDATE_APK)
                && resultCode == RESULT_OK && data != null && data.getData() != null) {
            final CloneRow updateTarget = requestCode == REQ_PICK_UPDATE_APK ? pendingUpdateClone : null;
            pendingUpdateClone = null;
            Uri uri = data.getData();
            worker.execute(() -> {
                try {
                    File picked = new File(getCacheDir(), "picked_" + System.currentTimeMillis() + ".apk");
                    try (InputStream in = getContentResolver().openInputStream(uri);
                         FileOutputStream out = new FileOutputStream(picked)) {
                        if (in == null) throw new IllegalStateException("Cannot open picked URI");
                        byte[] buf = new byte[65536];
                        int r;
                        while ((r = in.read(buf)) > 0) out.write(buf, 0, r);
                    }
                    String pkg = Cloner.packageOf(picked);
                    PackageInfo pi = getPackageManager().getPackageArchiveInfo(picked.getAbsolutePath(), 0);
                    AppRow extRow = new AppRow();
                    extRow.pkg = pkg;
                    extRow.sourceDir = picked.getAbsolutePath();
                    if (pi != null && pi.applicationInfo != null) {
                        pi.applicationInfo.sourceDir = picked.getAbsolutePath();
                        pi.applicationInfo.publicSourceDir = picked.getAbsolutePath();
                        extRow.label = String.valueOf(pi.applicationInfo.loadLabel(getPackageManager()));
                        extRow.icon = pi.applicationInfo.loadIcon(getPackageManager());
                    } else {
                        extRow.label = pkg;
                    }
                    runOnUiThread(() -> openCloneStudio(extRow, picked, updateTarget));
                } catch (Throwable t) {
                    runOnUiThread(() -> Toast.makeText(this, "Cannot read APK: " + t.getMessage(), Toast.LENGTH_LONG).show());
                }
            });
        }
    }

    private void clearCloneCache() {
        worker.execute(() -> {
            int deleted = deleteDir(new File(getCacheDir(), "clones"));
            File[] cacheFiles = getCacheDir().listFiles();
            if (cacheFiles != null) {
                for (File f : cacheFiles) {
                    if (f.getName().startsWith("picked_") && f.delete()) deleted++;
                }
            }
            final int total = deleted;
            runOnUiThread(() -> Toast.makeText(this, "Cleared " + total + " cached file(s)", Toast.LENGTH_SHORT).show());
        });
    }

    private int deleteDir(File dir) {
        if (dir == null || !dir.exists()) return 0;
        int count = 0;
        File[] kids = dir.listFiles();
        if (kids != null) {
            for (File k : kids) count += k.isDirectory() ? deleteDir(k) : (k.delete() ? 1 : 0);
        }
        if (dir.delete()) count++;
        return count;
    }

    final class AppsAdapter extends BaseAdapter {
        @Override public int getCount() { return shownApps.size(); }
        @Override public AppRow getItem(int pos) { return shownApps.get(pos); }
        @Override public long getItemId(int pos) { return pos; }

        @Override
        public View getView(int pos, View convertView, ViewGroup parent) {
            View row = convertView != null ? convertView : getLayoutInflater().inflate(R.layout.row_app, parent, false);
            AppRow app = getItem(pos);

            ImageView icon = row.findViewById(R.id.icon);
            TextView badge = row.findViewById(R.id.badge);
            TextView label = row.findViewById(R.id.label);
            TextView pkg = row.findViewById(R.id.pkg);
            TextView status = row.findViewById(R.id.status);
            TextView minus = row.findViewById(R.id.minus);
            TextView copies = row.findViewById(R.id.copies);
            TextView plus = row.findViewById(R.id.plus);
            CheckBox check = row.findViewById(R.id.check);

            icon.setImageDrawable(app.icon);
            if (app.existingClones > 0) {
                badge.setVisibility(View.VISIBLE);
                badge.setText(String.valueOf(app.existingClones));
            } else {
                badge.setVisibility(View.GONE);
            }

            label.setText(app.label);
            pkg.setText(app.pkg);

            StringBuilder st = new StringBuilder();
            if (app.versionName != null && !app.versionName.isEmpty()) st.append("v").append(app.versionName);
            if (app.splitDirs != null && app.splitDirs.length > 0) {
                if (st.length() > 0) st.append(" • ");
                st.append("Split (").append(app.splitDirs.length + 1).append(")");
            }
            if (app.existingClones > 0) {
                if (st.length() > 0) st.append(" • ");
                st.append("Cloned x").append(app.existingClones);
            }
            if (st.length() == 0) st.append(app.isSystem ? "System app" : "User app");
            status.setText(st.toString());

            copies.setText(String.valueOf(app.copies));
            minus.setOnClickListener(v -> {
                if (app.copies > 1) {
                    app.copies--;
                    copies.setText(String.valueOf(app.copies));
                }
            });
            plus.setOnClickListener(v -> {
                if (app.copies < 9) {
                    app.copies++;
                    copies.setText(String.valueOf(app.copies));
                }
            });

            check.setOnCheckedChangeListener(null);
            check.setChecked(app.selected);
            check.setOnCheckedChangeListener((btn, isChecked) -> app.selected = isChecked);

            row.setOnClickListener(v -> openCloneStudio(app, null));
            row.setOnLongClickListener(v -> {
                showDoctorDialog(app.label, new File(app.sourceDir));
                return true;
            });
            return row;
        }
    }

    final class ClonesAdapter extends BaseAdapter {
        @Override public int getCount() { return cloneRows.size(); }
        @Override public CloneRow getItem(int pos) { return cloneRows.get(pos); }
        @Override public long getItemId(int pos) { return pos; }

        @Override
        public View getView(int pos, View convertView, ViewGroup parent) {
            View row = convertView != null ? convertView : getLayoutInflater().inflate(R.layout.row_clone, parent, false);
            CloneRow cr = getItem(pos);

            ImageView icon = row.findViewById(R.id.cloneIcon);
            TextView label = row.findViewById(R.id.cloneLabel);
            TextView numPill = row.findViewById(R.id.cloneNumPill);
            TextView pkg = row.findViewById(R.id.clonePkg);
            TextView orig = row.findViewById(R.id.cloneOrigin);

            icon.setImageDrawable(cr.icon);
            label.setText(cr.label);
            numPill.setText("#" + cr.cloneNum);
            GradientDrawable pillBg = new GradientDrawable();
            pillBg.setCornerRadius(dp(10));
            pillBg.setColor(Icon.color(cr.cloneNum));
            numPill.setBackground(pillBg);

            pkg.setText(cr.pkg);
            AppRow origApp = null;
            for (AppRow a : allApps) {
                if (a.pkg.equals(cr.origPkg)) {
                    origApp = a;
                    break;
                }
            }
            if (origApp != null && origApp.versionCode > cr.versionCode) {
                orig.setText("From: " + cr.origPkg + " • Update v" + cr.versionName + " -> v" + origApp.versionName);
            } else {
                orig.setText("From: " + cr.origPkg + (cr.versionName != null && !cr.versionName.isEmpty() ? " (v" + cr.versionName + ")" : ""));
            }

            row.findViewById(R.id.btnOpenClone).setOnClickListener(v -> {
                Intent launch = getPackageManager().getLaunchIntentForPackage(cr.pkg);
                if (launch != null) {
                    startActivity(launch);
                } else {
                    Toast.makeText(MainActivity.this, "No launcher activity in " + cr.pkg, Toast.LENGTH_SHORT).show();
                }
            });
            final AppRow matchedOrig = origApp;
            row.findViewById(R.id.btnUpdateClone).setOnClickListener(v -> {
                if (matchedOrig != null) {
                    openCloneStudio(matchedOrig, null, cr);
                } else {
                    pendingUpdateClone = cr;
                    Toast.makeText(MainActivity.this, "Original app not installed — pick updated APK", Toast.LENGTH_SHORT).show();
                    Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT)
                            .addCategory(Intent.CATEGORY_OPENABLE)
                            .setType("*/*");
                    startActivityForResult(i, REQ_PICK_UPDATE_APK);
                }
            });
            row.findViewById(R.id.btnDoctorClone).setOnClickListener(v ->
                    showDoctorDialog(cr.label, new File(cr.sourceDir)));
            row.findViewById(R.id.btnUninstallClone).setOnClickListener(v ->
                    startActivityForResult(new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + cr.pkg)), REQ_UNINSTALL));
            return row;
        }
    }
}
