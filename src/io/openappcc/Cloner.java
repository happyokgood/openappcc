package io.openappcc;

import android.content.Context;
import android.util.Log;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * APK cloning pipeline: AST manifest rewrite, resources.arsc rename, icon tint/badge,
 * in-place DEX rebase, streaming aligned ZIP repack, and V1/V2/V3 apksig signing.
 */
public final class Cloner {
    static final int ICON_STRENGTH = 210;
    static final String KS_ASSET = "openappcc.p12";
    static final char[] KS_PASS = "openappcc".toCharArray();
    static final String KS_ALIAS = "openappcc";
    static final String ANDROID_NS = Axml.ANDROID_NS;
    private static final String SAME_LEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_";

    private Cloner() {
    }

    public static final class Options {
        public int cloneNumber = 1;
        public String customLabel;
        public boolean sameLength = true;
        public boolean tintIcon = true;
        public boolean badgeIcon = true;
        public boolean multiColor = true;
        public boolean flipIcon = false;
        public int rotateIcon = 0;
        public String badgeText;
        public String customVersionName;
        public boolean patchDex = true;
        public boolean renameClasses = false;
        public boolean spoofSignature = false;
        public boolean spoofAndroidId = false;
        public String screenshotMode; // null, "allow", "block"
        public String customLocale;
        public String customModel;
        public boolean keepDeviceAbiOnly = false;
        public boolean compressNativeLibs = false;
        public String keepAbi;
        public byte[] hookDex;
        public boolean standalone = false;
        public boolean stripSharedUid = false;
        public int minTargetSdk = 0;
        public boolean noAutostart = false;
        public boolean noWidgets = false;
        public boolean noAppDefaults = false;
        public boolean noWearable = false;
        public boolean noCrashReporters = false;
        public String rotationLock; // null, "portrait", "landscape"
        public boolean excludeRecents = false;
        public boolean debuggable = false;
        public boolean noBackup = false;
        public boolean isSplit = false;
        public String overridePackage;
    }

    public static final class Result {
        public String oldPackage, newPackage, oldLabel;
        public int targetSdkFrom, targetSdkTo;
        public int renamedAttributes;
        public int absolutizedClassNames;
        public int dexStringsPatched, dexStringsSkipped;
        public int iconFiles;
        public final List<String[]> forcedPairs = new ArrayList<>();
        public final List<String> warnings = new ArrayList<>();
        public File file;
        public static volatile String stage = "start";
    }

    static final class Counting extends OutputStream {
        long count;
        final OutputStream target;

        Counting(OutputStream target) {
            this.target = target;
        }

        @Override
        public void write(int b) throws java.io.IOException {
            target.write(b);
            count++;
        }

        @Override
        public void write(byte[] b, int off, int len) throws java.io.IOException {
            target.write(b, off, len);
            count += len;
        }

        @Override
        public void flush() throws java.io.IOException {
            target.flush();
        }

        @Override
        public void close() throws java.io.IOException {
            target.close();
        }
    }

    public static String generatePackage(String oldPkg, int cloneIndex, boolean sameLength) {
        if (!sameLength) return oldPkg + ".clone" + cloneIndex;
        int dot = oldPkg.lastIndexOf('.');
        String prefix = dot >= 0 ? oldPkg.substring(0, dot + 1) : "";
        String tail = dot >= 0 ? oldPkg.substring(dot + 1) : oldPkg;
        if (tail.length() < 2) throw new IllegalArgumentException("Package tail too short: " + tail);

        char[] mut = tail.substring(1).toCharArray();
        int base = SAME_LEN_ALPHABET.length();
        int carry = Math.max(1, cloneIndex);
        for (int pos = mut.length - 1; pos >= 0 && carry > 0; pos--) {
            int cur = SAME_LEN_ALPHABET.indexOf(Character.toLowerCase(mut[pos]));
            if (cur < 0) cur = 0;
            int total = cur + carry;
            mut[pos] = SAME_LEN_ALPHABET.charAt(total % base);
            carry = total / base;
        }
        String candidate = tail.charAt(0) + new String(mut);
        if (candidate.equals(tail)) {
            throw new IllegalArgumentException("Same-length namespace exhausted at #" + cloneIndex);
        }
        return prefix + candidate;
    }

    static Object[] loadKey(Context ctx) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = ctx.getAssets().open(KS_ASSET)) {
            ks.load(in, KS_PASS);
        }
        PrivateKey key = (PrivateKey) ks.getKey(KS_ALIAS, KS_PASS);
        Certificate cert = ks.getCertificate(KS_ALIAS);
        return new Object[]{key, cert};
    }

    static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        return out.toByteArray();
    }

    static boolean isSignatureFile(String name) {
        if (!name.startsWith("META-INF/")) return false;
        String rest = name.substring(9);
        if (rest.contains("/")) return false;
        String upper = rest.toUpperCase(Locale.US);
        return upper.equals("MANIFEST.MF") || upper.endsWith(".SF") || upper.endsWith(".RSA")
                || upper.endsWith(".DSA") || upper.endsWith(".EC");
    }

    public static String packageOf(File apk) throws Exception {
        try (ZipFile zip = new ZipFile(apk)) {
            ZipEntry man = zip.getEntry("AndroidManifest.xml");
            if (man == null) throw new IllegalStateException("AndroidManifest.xml missing");
            Axml ax;
            try (InputStream in = zip.getInputStream(man)) {
                ax = Axml.parse(readAll(in));
            }
            Axml.Node manifest = ax.element("manifest");
            Axml.Attr pkg = manifest == null ? null : Axml.attr(manifest, "package");
            if (pkg == null || pkg.raw == null) throw new IllegalStateException("manifest has no package");
            return pkg.raw;
        }
    }

    static int absolutizeClassNames(Axml ax, String oldPkg) {
        int fixed = 0;
        for (Axml.Node n : ax.nodes) {
            if (n.kind != Axml.START || n.name == null) continue;
            String allowed;
            switch (n.name) {
                case "application":
                    allowed = ",name,backupAgent,manageSpaceActivity,settingsActivity,zygotePreloadName,appComponentFactory,backupService,";
                    break;
                case "activity":
                case "activity-alias":
                    allowed = ",name,parentActivityName,targetActivity,";
                    break;
                case "service":
                case "receiver":
                case "provider":
                case "instrumentation":
                    allowed = ",name,";
                    break;
                default:
                    continue;
            }
            for (Axml.Attr a : n.attrs) {
                if (a.type != 0x03 || a.raw == null || !a.raw.startsWith(".")) continue;
                if (!allowed.contains("," + a.name + ",")) continue;
                a.raw = oldPkg + a.raw;
                a.data = 0;
                fixed++;
            }
        }
        return fixed;
    }

    static void renameManifestClasses(Axml ax, String oldPkg, String newPkg) {
        if (oldPkg.length() != newPkg.length() || oldPkg.equals(newPkg)) return;
        for (Axml.Node n : ax.nodes) {
            if (n.kind != Axml.START || n.name == null) continue;
            String allowed;
            switch (n.name) {
                case "application":
                    allowed = ",name,backupAgent,manageSpaceActivity,settingsActivity,zygotePreloadName,appComponentFactory,backupService,";
                    break;
                case "activity":
                case "activity-alias":
                    allowed = ",name,parentActivityName,targetActivity,";
                    break;
                case "service":
                case "receiver":
                case "provider":
                case "instrumentation":
                    allowed = ",name,";
                    break;
                default:
                    continue;
            }
            for (Axml.Attr a : n.attrs) {
                if (a.type != 0x03 || a.raw == null || !allowed.contains("," + a.name + ",")) continue;
                if (a.raw.equals(oldPkg) || a.raw.startsWith(oldPkg + ".")) {
                    a.raw = newPkg + a.raw.substring(oldPkg.length());
                    a.data = 0;
                }
            }
        }
    }

    static String identifierAttrs(String tag) {
        switch (tag) {
            case "manifest": return "package,sharedUserId";
            case "provider": return "authorities,permission,readPermission,writePermission,process";
            case "permission":
            case "permission-group":
            case "permission-tree":
            case "uses-permission":
            case "uses-permission-sdk-23":
            case "action":
            case "category": return "name";
            case "instrumentation": return "targetPackage";
            case "data": return "scheme";
            case "application":
            case "activity":
            case "activity-alias": return "taskAffinity,process,sharedUserId,permission";
            case "service":
            case "receiver": return "process,permission";
            default: return null;
        }
    }

    static String rebaseIdentity(String value, String oldPkg, String newPkg) {
        if (value.equals(oldPkg)) return newPkg;
        if (value.startsWith(oldPkg + ".") || value.startsWith(oldPkg + ":")) {
            return newPkg + value.substring(oldPkg.length());
        }
        int dot = oldPkg.lastIndexOf('.');
        String seg = dot >= 0 ? oldPkg.substring(dot + 1) : oldPkg;
        if (seg.length() < 4) return null;
        int i = value.indexOf("." + seg);
        if (i < 0) return null;
        String rest = value.substring(i + 1 + seg.length());
        if (!rest.isEmpty() && !rest.startsWith(".") && !rest.startsWith(":")) return null;
        return newPkg + rest;
    }

    static int renameIdentity(Axml ax, String oldPkg, String newPkg) {
        int changed = 0;
        int queriesDepth = 0;
        for (Axml.Node n : ax.nodes) {
            if (n.kind == Axml.START) {
                if ("queries".equals(n.name)) {
                    queriesDepth++;
                    continue;
                }
                if (queriesDepth > 0 || n.name == null) continue;
            } else if (n.kind == Axml.END) {
                if ("queries".equals(n.name) && queriesDepth > 0) queriesDepth--;
                continue;
            } else {
                continue;
            }
            String allowed = identifierAttrs(n.name);
            if (allowed == null) continue;
            List<String> names = Arrays.asList(allowed.split(","));
            for (Axml.Attr a : n.attrs) {
                if (a.type != 0x03 || a.raw == null) continue;
                if (a.ns != null && !a.ns.isEmpty() && !ANDROID_NS.equals(a.ns)) continue;
                if (!names.contains(a.name)) continue;
                String next;
                if ("authorities".equals(a.name) && a.raw.indexOf(';') >= 0) {
                    StringBuilder sb = new StringBuilder();
                    for (String part : a.raw.split(";", -1)) {
                        if (sb.length() > 0) sb.append(';');
                        String r = rebaseIdentity(part, oldPkg, newPkg);
                        sb.append(r == null ? part : r);
                    }
                    next = sb.toString();
                } else {
                    String r = rebaseIdentity(a.raw, oldPkg, newPkg);
                    next = r == null ? a.raw : r;
                }
                if (next.equals(a.raw)) continue;
                a.raw = next;
                a.data = 0;
                changed++;
            }
        }
        return changed;
    }

    static void resolveAuthorityRefs(Axml ax, byte[] arscBytes) {
        if (arscBytes == null) return;
        ArrayDeque<String> stack = new ArrayDeque<>();
        for (Axml.Node n : ax.nodes) {
            if (n.kind == Axml.START) {
                String parent = stack.isEmpty() ? "" : stack.peek();
                String tag = n.name == null ? "" : n.name;
                stack.push(tag);
                if ("provider".equals(tag) && "application".equals(parent)) {
                    for (Axml.Attr a : n.attrs) {
                        if ("authorities".equals(a.name) && a.type == 0x01 && a.data != 0) {
                            List<String> vals = Arsc.paths(arscBytes, a.data);
                            if (!vals.isEmpty() && vals.get(0) != null && !vals.get(0).isEmpty()) {
                                a.raw = vals.get(0);
                                a.type = 0x03;
                                a.data = 0;
                            }
                        }
                    }
                }
            } else if (n.kind == Axml.END && !stack.isEmpty()) {
                stack.pop();
            }
        }
    }

    static void setLauncherLabels(Axml ax, String label) {
        for (int i = 0; i < ax.nodes.size(); i++) {
            Axml.Node n = ax.nodes.get(i);
            if (n.kind != Axml.START) continue;
            if (!"activity".equals(n.name) && !"activity-alias".equals(n.name)) continue;
            if (Axml.attr(n, "label") == null) continue;
            boolean hasMain = false, hasLauncher = false;
            int depth = 1;
            for (int j = i + 1; j < ax.nodes.size() && depth > 0; j++) {
                Axml.Node c = ax.nodes.get(j);
                if (c.kind == Axml.START) {
                    depth++;
                    if ("action".equals(c.name)) {
                        Axml.Attr an = Axml.attr(c, "name");
                        if (an != null && "android.intent.action.MAIN".equals(an.raw)) hasMain = true;
                    } else if ("category".equals(c.name)) {
                        Axml.Attr cn = Axml.attr(c, "name");
                        if (cn != null && "android.intent.category.LAUNCHER".equals(cn.raw)) hasLauncher = true;
                    }
                } else if (c.kind == Axml.END) {
                    depth--;
                }
            }
            if (hasMain && hasLauncher) Axml.setAttr(n, "label", label);
        }
    }

    static void forceRebase(Axml ax, String newPkg, List<String> warnings, List<String[]> pairs) {
        ArrayDeque<String> stack = new ArrayDeque<>();
        for (Axml.Node n : ax.nodes) {
            if (n.kind == Axml.START) {
                String parent = stack.isEmpty() ? "" : stack.peek();
                String tag = n.name == null ? "" : n.name;
                stack.push(tag);
                if ("provider".equals(tag) && "application".equals(parent)) {
                    for (Axml.Attr a : n.attrs) {
                        if (!"authorities".equals(a.name) || a.raw == null) continue;
                        StringBuilder sb = new StringBuilder();
                        boolean changed = false;
                        for (String part : a.raw.split(";", -1)) {
                            if (sb.length() > 0) sb.append(';');
                            if (part.equals(newPkg) || part.startsWith(newPkg + ".")) {
                                sb.append(part);
                            } else {
                                sb.append(newPkg).append('.').append(part);
                                changed = true;
                            }
                        }
                        if (!changed) continue;
                        String next = sb.toString();
                        warnings.add("authority renamed: " + a.raw + " -> " + next);
                        pairs.add(new String[]{a.raw, next});
                        a.raw = next;
                        a.data = 0;
                    }
                } else if (("permission".equals(tag) || "permission-tree".equals(tag) || "permission-group".equals(tag))
                        && "manifest".equals(parent)) {
                    for (Axml.Attr a : n.attrs) {
                        if (!"name".equals(a.name) || a.raw == null) continue;
                        if (a.raw.startsWith("android.") || a.raw.startsWith(newPkg + ".")) continue;
                        String next = newPkg + "." + a.raw;
                        warnings.add("permission renamed: " + a.raw + " -> " + next);
                        pairs.add(new String[]{a.raw, next});
                        a.raw = next;
                        a.data = 0;
                    }
                }
            } else if (n.kind == Axml.END && !stack.isEmpty()) {
                stack.pop();
            }
        }
    }

    static void stripSharedUid(Axml ax) {
        for (Axml.Node n : ax.nodes) {
            if (n.kind != Axml.START) continue;
            if ("manifest".equals(n.name) || "application".equals(n.name)) {
                n.attrs.removeIf(a -> "sharedUserId".equals(a.name)
                        || "sharedUserLabel".equals(a.name)
                        || "sharedUserMaxSdkVersion".equals(a.name));
            }
        }
    }

    static void stampClone(Axml ax, int index, String originalPackage) {
        int appEnd = -1;
        for (int i = 0; i < ax.nodes.size(); i++) {
            Axml.Node n = ax.nodes.get(i);
            if (n.kind == Axml.END && "application".equals(n.name)) {
                appEnd = i;
                break;
            }
        }
        if (appEnd < 0) return;

        upsertMetaInt(ax, "io.openappcc.CLONE", index);
        if (originalPackage != null) upsertMetaStr(ax, "io.openappcc.ORIGINAL", originalPackage);
        upsertMetaStr(ax, "io.openappcc.CREATED_BY", "openappcc");
    }

    static Axml.Node findMetaNode(Axml ax, String key) {
        int depth = 0;
        String parent = "";
        for (Axml.Node n : ax.nodes) {
            if (n.kind == Axml.START) {
                if ("meta-data".equals(n.name) && depth == 2 && "application".equals(parent)) {
                    Axml.Attr name = Axml.attr(n, "name");
                    if (name != null && key.equals(name.raw)) return n;
                }
                if (depth == 1) parent = n.name == null ? "" : n.name;
                depth++;
            } else if (n.kind == Axml.END) {
                depth--;
            }
        }
        return null;
    }

    static int appEndIndex(Axml ax) {
        for (int i = 0; i < ax.nodes.size(); i++) {
            Axml.Node n = ax.nodes.get(i);
            if (n.kind == Axml.END && "application".equals(n.name)) return i;
        }
        return -1;
    }

    static void upsertMetaStr(Axml ax, String key, String value) {
        Axml.Node existing = findMetaNode(ax, key);
        if (existing != null) {
            Axml.setAttr(existing, "value", value);
            return;
        }
        int at = appEndIndex(ax);
        if (at < 0) return;
        Axml.Node start = new Axml.Node();
        start.kind = Axml.START;
        start.name = "meta-data";
        start.line = 1;
        Axml.setAttr(start, "name", key);
        Axml.setAttr(start, "value", value);
        Axml.Node stop = new Axml.Node();
        stop.kind = Axml.END;
        stop.name = "meta-data";
        stop.line = 1;
        ax.nodes.add(at, stop);
        ax.nodes.add(at, start);
    }

    static void upsertMetaInt(Axml ax, String key, int value) {
        Axml.Node existing = findMetaNode(ax, key);
        if (existing != null) {
            Axml.setInt(existing, "value", value);
            return;
        }
        int at = appEndIndex(ax);
        if (at < 0) return;
        Axml.Node start = new Axml.Node();
        start.kind = Axml.START;
        start.name = "meta-data";
        start.line = 1;
        Axml.setAttr(start, "name", key);
        Axml.setInt(start, "value", value);
        Axml.Node stop = new Axml.Node();
        stop.kind = Axml.END;
        stop.name = "meta-data";
        stop.line = 1;
        ax.nodes.add(at, stop);
        ax.nodes.add(at, start);
    }

    static void addExportedForFilters(Axml ax) {
        Set<String> exportable = new HashSet<>(Arrays.asList("activity", "activity-alias", "service", "receiver", "provider"));
        ArrayDeque<Axml.Node> open = new ArrayDeque<>();
        ArrayDeque<Boolean> filtered = new ArrayDeque<>();
        for (Axml.Node n : ax.nodes) {
            if (n.kind == Axml.START) {
                if ("intent-filter".equals(n.name) && !filtered.isEmpty()) {
                    filtered.pop();
                    filtered.push(Boolean.TRUE);
                }
                open.push(n);
                filtered.push(Boolean.FALSE);
            } else if (n.kind == Axml.END && !open.isEmpty()) {
                Axml.Node start = open.pop();
                boolean hasFilter = filtered.pop();
                if (!hasFilter || !exportable.contains(start.name)) continue;
                if (Axml.attr(start, "exported") == null) Axml.setBool(start, "exported", true);
            }
        }
    }

    static void neutralizeCloudInit(Axml ax) {
        for (Axml.Node n : ax.nodes) {
            if (n.kind != Axml.START) continue;
            if ("provider".equals(n.name)) {
                Axml.Attr a = Axml.attr(n, "name");
                if (a != null && "com.google.firebase.provider.FirebaseInitProvider".equals(a.raw)) {
                    // shortcut: redirect init provider to base class to prevent startup crash, upgrade to full tag removal if manifest schema enforces
                    a.raw = "android.content.ContentProvider";
                    a.data = 0;
                }
            } else if ("meta-data".equals(n.name)) {
                Axml.Attr a = Axml.attr(n, "name");
                if (a != null && "com.google.android.gms.version".equals(a.raw)) {
                    a.raw = "disabled.gms.version";
                    a.data = 0;
                }
            }
        }
    }

    static void disableReceivers(Axml ax, boolean autostart, boolean widgets) {
        if (!autostart && !widgets) return;
        Set<String> bootActions = new HashSet<>(Arrays.asList(
                "android.intent.action.BOOT_COMPLETED",
                "android.intent.action.LOCKED_BOOT_COMPLETED",
                "android.intent.action.QUICKBOOT_POWERON"
        ));
        ArrayDeque<Axml.Node> rxStack = new ArrayDeque<>();
        ArrayDeque<Set<String>> actStack = new ArrayDeque<>();
        for (Axml.Node n : ax.nodes) {
            if (n.kind == Axml.START && "receiver".equals(n.name)) {
                rxStack.push(n);
                actStack.push(new HashSet<>());
            } else if (n.kind == Axml.START && "action".equals(n.name) && !actStack.isEmpty()) {
                Axml.Attr a = Axml.attr(n, "name");
                if (a != null && a.raw != null) actStack.peek().add(a.raw);
            } else if (n.kind == Axml.END && "receiver".equals(n.name) && !rxStack.isEmpty()) {
                Axml.Node rx = rxStack.pop();
                Set<String> actions = actStack.pop();
                boolean boot = autostart && !Collections.disjoint(actions, bootActions);
                boolean wid = widgets && actions.contains("android.appwidget.action.APPWIDGET_UPDATE");
                if (boot || wid) Axml.setBool(rx, "enabled", false);
            }
        }
    }

    static void disableAppDefaults(Axml ax) {
        Set<String> shared = new HashSet<>(Arrays.asList(
                "android.intent.action.VIEW",
                "android.intent.action.SEND",
                "android.intent.action.SEND_MULTIPLE"
        ));
        List<Axml.Node> filters = new ArrayList<>();
        for (Axml.Node n : ax.nodes) if (n.kind == Axml.START && "intent-filter".equals(n.name)) filters.add(n);
        for (Axml.Node f : filters) {
            List<Axml.Node> sub = ax.subtree(f);
            boolean hasMain = false, hasLauncher = false, hasShared = false;
            for (Axml.Node n : sub) {
                if (n.kind != Axml.START) continue;
                Axml.Attr a = Axml.attr(n, "name");
                String v = a != null ? a.raw : null;
                if ("action".equals(n.name) && v != null) {
                    if ("android.intent.action.MAIN".equals(v)) hasMain = true;
                    if (shared.contains(v)) hasShared = true;
                } else if ("category".equals(n.name) && "android.intent.category.LAUNCHER".equals(v)) {
                    hasLauncher = true;
                }
            }
            if (!(hasMain && hasLauncher) && hasShared) ax.removeElement(f);
        }
    }

    static void disableWearable(Axml ax) {
        List<Axml.Node> snapshot = new ArrayList<>();
        for (Axml.Node n : ax.nodes) if (n.kind == Axml.START) snapshot.add(n);
        for (Axml.Node n : snapshot) {
            if ("uses-feature".equals(n.name)) {
                Axml.Attr a = Axml.attr(n, "name");
                if (a != null && ("android.hardware.type.watch".equals(a.raw) || "android.software.leanback".equals(a.raw))) {
                    ax.removeElement(n);
                }
            } else if ("meta-data".equals(n.name)) {
                Axml.Attr a = Axml.attr(n, "name");
                if (a != null && a.raw != null && a.raw.startsWith("com.google.android.wearable.")) {
                    ax.removeElement(n);
                }
            } else if ("intent-filter".equals(n.name)) {
                for (Axml.Node c : ax.subtree(n)) {
                    if (c.kind == Axml.START && "category".equals(c.name)) {
                        Axml.Attr a = Axml.attr(c, "name");
                        if (a != null && "android.intent.category.LEANBACK_LAUNCHER".equals(a.raw)) {
                            ax.removeElement(n);
                            break;
                        }
                    }
                }
            } else if ("service".equals(n.name)) {
                for (Axml.Node c : ax.subtree(n)) {
                    if (c.kind == Axml.START && "action".equals(c.name)) {
                        Axml.Attr a = Axml.attr(c, "name");
                        if (a != null && a.raw != null && a.raw.startsWith("com.google.android.gms.wearable.")) {
                            Axml.setBool(n, "enabled", false);
                            break;
                        }
                    }
                }
            }
        }
    }

    static boolean isCrashName(String s) {
        if (s == null) return false;
        String low = s.toLowerCase(Locale.US);
        return low.contains("crashlytics") || low.contains("crashreport") || low.contains("acra")
                || low.contains("bugsnag") || low.contains("sentry") || low.contains("instabug")
                || low.contains("apteligent") || low.contains("newrelic") || low.contains("counteragent");
    }

    static void disableCrashReporters(Axml ax) {
        for (Axml.Node n : ax.nodes) {
            if (n.kind != Axml.START) continue;
            if ("meta-data".equals(n.name)) {
                Axml.Attr a = Axml.attr(n, "name");
                if (a != null && ("firebase_crashlytics_collection_enabled".equals(a.raw) || isCrashName(a.raw))) {
                    Axml.setBool(n, "value", false);
                }
            } else if ("service".equals(n.name) || "provider".equals(n.name) || "receiver".equals(n.name)) {
                Axml.Attr cls = Axml.attr(n, "name");
                Axml.Attr auth = Axml.attr(n, "authorities");
                if (isCrashName(cls != null ? cls.raw : null) || isCrashName(auth != null ? auth.raw : null)) {
                    Axml.setBool(n, "enabled", false);
                }
            }
        }
    }

    static void patchIcons(ZipFile zip, Axml ax, byte[] arsc, Options opts, Map<String, byte[]> out) throws Exception {
        Axml.Node app = ax.element("application");
        LinkedHashMap<String, String> wanted = new LinkedHashMap<>();
        if (app != null && arsc != null) {
            for (String attribute : new String[]{"icon", "roundIcon", "logo"}) {
                Axml.Attr at = Axml.attr(app, attribute);
                if (at == null || at.type != 0x01) continue;
                for (String path : Arsc.paths(arsc, at.data)) {
                    if (path == null) continue;
                    if (Icon.isRaster(path)) wanted.putIfAbsent(path, "icon");
                    else if (path.toLowerCase(Locale.US).endsWith(".xml")) addLayers(zip, arsc, path, wanted);
                }
            }
        }
        boolean hasBadgeText = opts.badgeText != null && !opts.badgeText.trim().isEmpty();
        boolean drawBadge = opts.badgeIcon || hasBadgeText;
        for (Map.Entry<String, String> e : wanted.entrySet()) {
            String path = e.getKey();
            String role = e.getValue();
            if ("monochrome".equals(role)) continue;
            ZipEntry entry = zip.getEntry(path);
            if (entry == null) continue;
            byte[] bytes;
            try (InputStream in = zip.getInputStream(entry)) {
                bytes = readAll(in);
            }
            boolean tintOnly = "background".equals(role);
            boolean layer = "foreground".equals(role);
            byte[] painted = Icon.paint(bytes, opts.cloneNumber, ICON_STRENGTH,
                    drawBadge && !tintOnly, layer, opts.tintIcon, opts.flipIcon, opts.rotateIcon, opts.badgeText, opts.multiColor);
            if (painted != bytes) out.put(path, painted);
        }
        Log.i("openappcc", "icons painted=" + out.size() + "/" + wanted.size());
    }

    static void addLayers(ZipFile zip, byte[] arsc, String xmlPath, Map<String, String> wanted) {
        ZipEntry entry = zip.getEntry(xmlPath);
        if (entry == null) return;
        try (InputStream in = zip.getInputStream(entry)) {
            Axml doc = Axml.parse(readAll(in));
            for (Axml.Node n : doc.nodes) {
                String role = n.name;
                if (!"background".equals(role) && !"foreground".equals(role) && !"monochrome".equals(role)) continue;
                Axml.Attr d = Axml.attr(n, "drawable");
                if (d == null) continue;
                if (d.type == 0x01 && arsc != null) {
                    for (String sub : Arsc.paths(arsc, d.data)) {
                        if (sub != null && Icon.isRaster(sub)) wanted.putIfAbsent(sub, role);
                    }
                } else if (d.type == 0x03 && d.raw != null && Icon.isRaster(d.raw)) {
                    wanted.putIfAbsent(d.raw, role);
                }
            }
        } catch (Exception ignored) {
        }
    }

    static String extractOriginalCertBase64(File srcApk) {
        try {
            com.android.apksig.ApkVerifier.Result vr = new com.android.apksig.ApkVerifier.Builder(srcApk).build().verify();
            List<X509Certificate> certs = vr.getSignerCertificates();
            if (certs != null && !certs.isEmpty()) {
                return java.util.Base64.getEncoder().encodeToString(certs.get(0).getEncoded());
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    static void injectBootstrapProvider(Axml ax, String newPackage) {
        int appEnd = -1;
        for (int i = 0; i < ax.nodes.size(); i++) {
            Axml.Node n = ax.nodes.get(i);
            if (n.kind == Axml.START && "provider".equals(n.name)) {
                Axml.Attr nm = Axml.attr(n, "name");
                if (nm != null && "io.openappcc.hook.BootstrapProvider".equals(nm.raw)) return;
            }
            if (n.kind == Axml.END && "application".equals(n.name)) {
                appEnd = i;
                break;
            }
        }
        if (appEnd < 0) return;

        Axml.Node start = new Axml.Node();
        start.kind = Axml.START;
        start.line = 1;
        start.name = "provider";
        Axml.setAttr(start, "name", "io.openappcc.hook.BootstrapProvider");
        Axml.setAttr(start, "authorities", newPackage + ".openappcc.bootstrap");
        Axml.setBool(start, "exported", false);
        Axml.setInt(start, "initOrder", Integer.MAX_VALUE);

        Axml.Node end = new Axml.Node();
        end.kind = Axml.END;
        end.line = 1;
        end.name = "provider";

        ax.nodes.add(appEnd, end);
        ax.nodes.add(appEnd, start);
    }

    static boolean needsBootstrapHook(Options opts) {
        return opts != null && !opts.isSplit && (
                opts.spoofSignature
                || opts.spoofAndroidId
                || (opts.screenshotMode != null && !opts.screenshotMode.isEmpty())
                || (opts.customLocale != null && !opts.customLocale.isEmpty())
                || (opts.customModel != null && !opts.customModel.isEmpty())
        );
    }

    static String randomAndroidIdHex() {
        byte[] buf = new byte[8];
        new java.security.SecureRandom().nextBytes(buf);
        StringBuilder sb = new StringBuilder(16);
        for (byte b : buf) sb.append(String.format(Locale.US, "%02x", b & 0xff));
        return sb.toString();
    }

    public static Result clone(Context ctx, File srcApk, File outFile, Options opts) throws Exception {
        Object[] ks = loadKey(ctx);
        if (needsBootstrapHook(opts) && opts.hookDex == null) {
            try (InputStream in = ctx.getAssets().open("hook.dex")) {
                opts.hookDex = readAll(in);
            }
        }
        return cloneWith(srcApk, outFile, (PrivateKey) ks[0], (X509Certificate) ks[1], opts);
    }

    public static Result cloneWith(File srcApk, File outFile, PrivateKey key, X509Certificate cert, Options opts)
            throws Exception {
        if (opts == null) opts = new Options();
        Result result = new Result();
        Result.stage = "open zip";
        ZipFile zip = new ZipFile(srcApk);
        File unsignedFile = null;
        try {
            ZipEntry manEntry = zip.getEntry("AndroidManifest.xml");
            if (manEntry == null) throw new IllegalStateException("AndroidManifest.xml missing");
            byte[] manBytes;
            try (InputStream in = zip.getInputStream(manEntry)) {
                manBytes = readAll(in);
            }

            Result.stage = "parse manifest";
            Axml ax = Axml.parse(manBytes);
            Axml.Node manifest = ax.element("manifest");
            if (manifest == null) throw new IllegalStateException("manifest element missing");
            Axml.Attr pkgAttr = Axml.attr(manifest, "package");
            if (pkgAttr == null || pkgAttr.raw == null) throw new IllegalStateException("manifest has no package");

            String oldPackage = pkgAttr.raw;
            String newPackage = opts.overridePackage != null && !opts.overridePackage.isEmpty()
                    ? opts.overridePackage
                    : generatePackage(oldPackage, opts.cloneNumber, opts.sameLength);
            result.oldPackage = oldPackage;
            result.newPackage = newPackage;

            ZipEntry arscEntry = zip.getEntry("resources.arsc");
            byte[] arscBytes = null;
            if (arscEntry != null) {
                try (InputStream in = zip.getInputStream(arscEntry)) {
                    arscBytes = readAll(in);
                }
            }

            result.absolutizedClassNames = absolutizeClassNames(ax, oldPackage);
            if (opts.renameClasses) renameManifestClasses(ax, oldPackage, newPackage);
            resolveAuthorityRefs(ax, arscBytes);
            result.renamedAttributes = renameIdentity(ax, oldPackage, newPackage);
            if (opts.stripSharedUid) stripSharedUid(ax);

            boolean hookReady = false;
            if (!opts.isSplit) {
                forceRebase(ax, newPackage, result.warnings, result.forcedPairs);
                stampClone(ax, opts.cloneNumber, oldPackage);
                if (needsBootstrapHook(opts) && opts.hookDex != null) {
                    if (opts.spoofSignature) {
                        String sigB64 = extractOriginalCertBase64(srcApk);
                        if (sigB64 != null) {
                            upsertMetaStr(ax, "io.openappcc.ORIGINAL_SIG", sigB64);
                            hookReady = true;
                        } else {
                            result.warnings.add("spoofSignature skipped: could not read original signer cert");
                        }
                    }
                    if (opts.spoofAndroidId) {
                        upsertMetaStr(ax, "io.openappcc.ANDROID_ID", randomAndroidIdHex());
                        hookReady = true;
                    }
                    if (opts.screenshotMode != null && !opts.screenshotMode.isEmpty()) {
                        upsertMetaStr(ax, "io.openappcc.SCREENSHOTS", opts.screenshotMode);
                        hookReady = true;
                    }
                    if (opts.customLocale != null && !opts.customLocale.isEmpty()) {
                        upsertMetaStr(ax, "io.openappcc.LOCALE", opts.customLocale);
                        hookReady = true;
                    }
                    if (opts.customModel != null && !opts.customModel.isEmpty()) {
                        upsertMetaStr(ax, "io.openappcc.BUILD_MODEL", opts.customModel);
                        hookReady = true;
                    }
                    if (hookReady) {
                        injectBootstrapProvider(ax, newPackage);
                    }
                }

                if (opts.customLabel != null && !opts.customLabel.isEmpty()) {
                    Axml.Node app = ax.element("application");
                    if (app != null) {
                        Axml.Attr before = Axml.attr(app, "label");
                        result.oldLabel = before == null ? null : before.raw;
                        Axml.setAttr(app, "label", opts.customLabel);
                    }
                    setLauncherLabels(ax, opts.customLabel);
                }
                if (opts.customVersionName != null && !opts.customVersionName.isEmpty()) {
                    Axml.setAttr(manifest, "versionName", opts.customVersionName);
                }

                Axml.Node sdk = ax.element("uses-sdk");
                Axml.Attr sdkAttr = sdk == null ? null : Axml.attr(sdk, "targetSdkVersion");
                int effectiveSdk = sdkAttr != null ? sdkAttr.data : 0;
                result.targetSdkFrom = effectiveSdk;
                result.targetSdkTo = effectiveSdk;
                if (opts.minTargetSdk > 0 && effectiveSdk > 0 && effectiveSdk < opts.minTargetSdk && sdk != null) {
                    Axml.setInt(sdk, "targetSdkVersion", opts.minTargetSdk);
                    effectiveSdk = opts.minTargetSdk;
                    result.targetSdkTo = effectiveSdk;
                }
                if (effectiveSdk >= 31) addExportedForFilters(ax);
                if (opts.standalone) neutralizeCloudInit(ax);
                disableReceivers(ax, opts.noAutostart, opts.noWidgets);
                if (opts.rotationLock != null) {
                    int orient = "landscape".equals(opts.rotationLock) ? 0 : 1;
                    for (Axml.Node n : ax.nodes) {
                        if (n.kind == Axml.START && ("activity".equals(n.name) || "activity-alias".equals(n.name))) {
                            Axml.setInt(n, "screenOrientation", orient);
                        }
                    }
                }
                if (opts.excludeRecents) {
                    for (Axml.Node n : ax.nodes) {
                        if (n.kind == Axml.START && ("activity".equals(n.name) || "activity-alias".equals(n.name))) {
                            Axml.setBool(n, "excludeFromRecents", true);
                        }
                    }
                }
                Axml.Node app = ax.element("application");
                if (app != null) {
                    app.attrs.removeIf(a -> "testOnly".equals(a.name));
                    if (opts.debuggable) Axml.setBool(app, "debuggable", true);
                    if (opts.noBackup) Axml.setBool(app, "allowBackup", false);
                    if (opts.compressNativeLibs) Axml.setBool(app, "extractNativeLibs", true);
                }
                if (opts.noAppDefaults) disableAppDefaults(ax);
                if (opts.noWearable) disableWearable(ax);
                if (opts.noCrashReporters) disableCrashReporters(ax);
            }

            Result.stage = "serialize manifest";
            byte[] newManifest = ax.toBytes();

            Map<String, byte[]> iconPatches = new LinkedHashMap<>();
            boolean wantsIconEdit = opts.tintIcon || opts.badgeIcon || opts.flipIcon || (opts.rotateIcon % 360 != 0)
                    || (opts.badgeText != null && !opts.badgeText.trim().isEmpty());
            if (!opts.isSplit && wantsIconEdit && arscBytes != null) {
                Result.stage = "paint icons";
                patchIcons(zip, ax, arscBytes, opts, iconPatches);
                result.iconFiles = iconPatches.size();
            }

            if (outFile.getParentFile() != null && !outFile.getParentFile().exists()) {
                outFile.getParentFile().mkdirs();
            }
            unsignedFile = new File(outFile.getParentFile(), outFile.getName() + ".unsigned");
            Counting counting = new Counting(new BufferedOutputStream(new FileOutputStream(unsignedFile), 1 << 16));
            ZipOutputStream out = new ZipOutputStream(counting);
            out.setLevel(9);

            byte[] copyBuf = new byte[65536];
            int maxDexIdx = 0;
            boolean injectHook = hookReady;
            String targetAbi = opts.keepAbi;
            if ((targetAbi == null || targetAbi.isEmpty()) && opts.keepDeviceAbiOnly) {
                String[] abis = android.os.Build.SUPPORTED_ABIS;
                if (abis != null && abis.length > 0) targetAbi = abis[0];
            }
            boolean filterAbi = false;
            if (targetAbi != null && !targetAbi.isEmpty()) {
                String wantPrefix = "lib/" + targetAbi + "/";
                Enumeration<? extends ZipEntry> scan = zip.entries();
                while (scan.hasMoreElements()) {
                    if (scan.nextElement().getName().startsWith(wantPrefix)) {
                        filterAbi = true;
                        break;
                    }
                }
            }
            String keepAbiPrefix = filterAbi ? "lib/" + targetAbi + "/" : null;
            Enumeration<? extends ZipEntry> it = zip.entries();
            while (it.hasMoreElements()) {
                ZipEntry e = it.nextElement();
                String name = e.getName();
                if (name.endsWith("/") || isSignatureFile(name)) continue;
                if ((opts.patchDex || injectHook)
                        && ("assets/dexopt/baseline.prof".equals(name) || "assets/dexopt/baseline.profm".equals(name))) {
                    continue;
                }
                if (keepAbiPrefix != null && name.startsWith("lib/") && !name.startsWith(keepAbiPrefix)) {
                    continue;
                }
                if (name.matches("classes\\d*\\.dex")) {
                    String num = name.substring(7, name.length() - 4);
                    int idx = num.isEmpty() ? 1 : Integer.parseInt(num);
                    if (idx > maxDexIdx) maxDexIdx = idx;
                }

                boolean isManifest = "AndroidManifest.xml".equals(name);
                boolean isArsc = "resources.arsc".equals(name);
                boolean isDex = opts.patchDex && name.matches("classes\\d*\\.dex");
                boolean deflateSo = opts.compressNativeLibs && name.startsWith("lib/") && name.endsWith(".so");
                boolean store = isArsc || (!deflateSo && e.getMethod() == ZipEntry.STORED);

                byte[] data = null;
                if (isManifest) {
                    data = newManifest;
                } else if (isArsc) {
                    Result.stage = "resources.arsc";
                    data = Arsc.renamePackage(arscBytes, oldPackage, newPackage);
                } else if (isDex) {
                    Result.stage = "dex " + name;
                    try (InputStream in = zip.getInputStream(e)) {
                        data = readAll(in);
                    }
                    Dex.Result dr = Dex.patch(data, oldPackage, newPackage, result.forcedPairs, opts.renameClasses);
                    data = dr.bytes;
                    result.dexStringsPatched += dr.replaced;
                    result.dexStringsSkipped += dr.skipped;
                }

                byte[] iconPatch = iconPatches.get(name);
                if (iconPatch != null) data = iconPatch;

                ZipEntry ne = new ZipEntry(name);
                Result.stage = "zip " + name;
                if (store) {
                    long size;
                    CRC32 crc = new CRC32();
                    if (data != null) {
                        size = data.length;
                        crc.update(data);
                    } else {
                        size = 0;
                        try (InputStream in = zip.getInputStream(e)) {
                            int r;
                            while ((r = in.read(copyBuf)) > 0) {
                                crc.update(copyBuf, 0, r);
                                size += r;
                            }
                        }
                    }
                    ne.setMethod(ZipEntry.STORED);
                    ne.setSize(size);
                    ne.setCompressedSize(size);
                    ne.setCrc(crc.getValue());
                    int align = name.endsWith(".so") ? 16384 : 4;
                    long base = counting.count + 30 + name.getBytes(StandardCharsets.UTF_8).length;
                    int pad = (int) ((align - (base % align)) % align);
                    if (pad > 0 && pad < 4) pad += align;
                    if (pad >= 4) {
                        byte[] extra = new byte[pad];
                        int len = pad - 4;
                        extra[2] = (byte) (len & 0xff);
                        extra[3] = (byte) ((len >>> 8) & 0xff);
                        ne.setExtra(extra);
                    }
                }
                out.putNextEntry(ne);
                if (data != null) {
                    out.write(data);
                } else {
                    try (InputStream in = zip.getInputStream(e)) {
                        int r;
                        while ((r = in.read(copyBuf)) > 0) out.write(copyBuf, 0, r);
                    }
                }
                out.closeEntry();
            }
            if (injectHook) {
                String hookName = "classes" + (maxDexIdx + 1) + ".dex";
                Result.stage = "zip " + hookName;
                out.putNextEntry(new ZipEntry(hookName));
                out.write(opts.hookDex);
                out.closeEntry();
            }
            out.finish();
            out.flush();
            out.close();
            zip.close();
            zip = null;

            Result.stage = "sign";
            com.android.apksig.ApkSigner.SignerConfig signerConfig =
                    new com.android.apksig.ApkSigner.SignerConfig.Builder(KS_ALIAS, key, Collections.singletonList(cert))
                            .build();
            new com.android.apksig.ApkSigner.Builder(Collections.singletonList(signerConfig))
                    .setInputApk(unsignedFile)
                    .setOutputApk(outFile)
                    .setV1SigningEnabled(true)
                    .setV2SigningEnabled(true)
                    .setV3SigningEnabled(true)
                    .build()
                    .sign();
            Result.stage = "signed";
            if (!unsignedFile.delete()) unsignedFile.deleteOnExit();

            result.file = outFile;
            return result;
        } finally {
            if (zip != null) {
                try {
                    zip.close();
                } catch (Exception ignored) {
                }
            }
            if (unsignedFile != null && unsignedFile.exists() && !unsignedFile.delete()) {
                unsignedFile.deleteOnExit();
            }
        }
    }
}
