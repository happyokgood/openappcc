package io.openappcc;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * On-device APK Inspector & Compatibility Doctor.
 */
public final class Doctor {
    private static final byte[] SIG_MAGIC = "APK Sig Block 42".getBytes(StandardCharsets.US_ASCII);

    private static String d(String tail) { return "L" + tail; }

    private static final String[][] PACKER_MARKERS = {
            {"Qihoo 360 (jiagu)", d("com/qihoo/util/"), d("com/stub/StubApp;"), "libjiagu"},
            {"DexProtector", d("com/dprot/"), d("com/wrapper/proxyapplication/"), "libdexprotector"},
            {"Bangcle (SecShell)", d("com/secneo/apkwrapper/"), d("com/bangcle/"), "libsecexe", "libdexhelper"},
            {"Tencent Legu", d("com/tencent/StubShell/"), "libshella", "libshellx"},
            {"Alibaba (mobisec)", d("com/ali/mobisecenhance/"), "libmobisec"},
            {"Baidu (protect)", d("com/baidu/protect/"), "libbaiduprotect", "libexecmain"},
            {"NetQin", d("com/netqin/"), "libnqshield"},
            {"LIAPP", d("com/liapp/"), "libliapp"},
    };

    private Doctor() {
    }

    static byte[] readEntry(ZipFile zip, ZipEntry entry) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[32768];
        try (InputStream in = zip.getInputStream(entry)) {
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    static boolean[] detectV2V3(File apkFile) {
        boolean v2 = false, v3 = false;
        try (RandomAccessFile raf = new RandomAccessFile(apkFile, "r")) {
            long len = raf.length();
            if (len < 22) return new boolean[]{false, false};
            int tailLen = (int) Math.min(len, 65557L);
            byte[] tail = new byte[tailLen];
            raf.seek(len - tailLen);
            raf.readFully(tail);
            for (int i = tailLen - 22; i >= 0; i--) {
                if (tail[i] == 0x50 && tail[i + 1] == 0x4b && tail[i + 2] == 0x05 && tail[i + 3] == 0x06) {
                    int commentLen = (tail[i + 20] & 0xff) | ((tail[i + 21] & 0xff) << 8);
                    if (i + 22 + commentLen != tailLen) continue;
                    long cdOff = (tail[i + 16] & 0xffL)
                            | ((tail[i + 17] & 0xffL) << 8)
                            | ((tail[i + 18] & 0xffL) << 16)
                            | ((tail[i + 19] & 0xffL) << 24);
                    if (cdOff < 24 || cdOff > len) return new boolean[]{false, false};
                    byte[] footer = new byte[24];
                    raf.seek(cdOff - 24);
                    raf.readFully(footer);
                    boolean magicOk = true;
                    for (int m = 0; m < 16; m++) {
                        if (footer[8 + m] != SIG_MAGIC[m]) { magicOk = false; break; }
                    }
                    if (!magicOk) return new boolean[]{false, false};
                    long blockSize = 0;
                    for (int b = 0; b < 8; b++) blockSize |= (footer[b] & 0xffL) << (b * 8);
                    long blockStart = cdOff - blockSize - 8;
                    if (blockStart < 0 || blockStart >= cdOff - 24) return new boolean[]{false, false};
                    raf.seek(blockStart + 8);
                    long pos = 0, pairsLen = blockSize - 24;
                    byte[] hdr = new byte[12];
                    while (pos + 12 <= pairsLen) {
                        raf.readFully(hdr);
                        long pairLen = 0;
                        for (int b = 0; b < 8; b++) pairLen |= (hdr[b] & 0xffL) << (b * 8);
                        int pairId = (hdr[8] & 0xff) | ((hdr[9] & 0xff) << 8)
                                | ((hdr[10] & 0xff) << 16) | ((hdr[11] & 0xff) << 24);
                        if (pairLen < 4 || pos + 8 + pairLen > pairsLen) break;
                        if (pairId == 0x7109871a) v2 = true;
                        else if (pairId == 0xf05368c0 || pairId == 0x1b93ad61) v3 = true;
                        raf.seek(raf.getFilePointer() + pairLen - 4);
                        pos += 8 + pairLen;
                    }
                    break;
                }
            }
        } catch (Exception ignored) {
        }
        return new boolean[]{v2, v3};
    }

    static boolean containsAscii(byte[] data, String needle) {
        byte[] pat = needle.getBytes(StandardCharsets.ISO_8859_1);
        if (pat.length == 0 || data.length < pat.length) return false;
        outer:
        for (int i = 0; i <= data.length - pat.length; i++) {
            for (int j = 0; j < pat.length; j++) {
                if (data[i + j] != pat[j]) continue outer;
            }
            return true;
        }
        return false;
    }

    public static String inspectReport(File apkFile) {
        if (apkFile == null || !apkFile.isFile()) return "APK file not found.";
        try (ZipFile probe = new ZipFile(apkFile)) {
            if (probe.getEntry("AndroidManifest.xml") == null) {
                File tmpDir = new File(apkFile.getParentFile(), "doc_bundle_" + System.currentTimeMillis());
                try {
                    File[] parts = Cloner.unpackApkOrBundle(apkFile, tmpDir);
                    String baseRep = inspectReport(parts[0]);
                    if (parts.length > 1) {
                        StringBuilder b = new StringBuilder("Bundle Splits (").append(parts.length).append(" APKs): ");
                        for (int i = 0; i < parts.length; i++) {
                            if (i > 0) b.append(", ");
                            b.append(parts[i].getName());
                        }
                        b.append("\n").append(baseRep);
                        return b.toString();
                    }
                    return baseRep;
                } finally {
                    File[] kids = tmpDir.listFiles();
                    if (kids != null) for (File k : kids) k.delete();
                    tmpDir.delete();
                }
            }
        } catch (Exception ignored) {
        }
        StringBuilder sb = new StringBuilder();
        try (ZipFile zip = new ZipFile(apkFile)) {
            ZipEntry man = zip.getEntry("AndroidManifest.xml");
            if (man == null) return "Invalid APK: AndroidManifest.xml missing.";
            Axml ax = Axml.parse(readEntry(zip, man));
            Axml.Node manifest = ax.element("manifest");
            String pkg = manifest != null && Axml.attr(manifest, "package") != null
                    ? Axml.attr(manifest, "package").raw : "(unknown)";
            Axml.Attr vc = manifest != null ? Axml.attr(manifest, "versionCode") : null;
            Axml.Attr vn = manifest != null ? Axml.attr(manifest, "versionName") : null;
            Axml.Attr uid = manifest != null ? Axml.attr(manifest, "sharedUserId") : null;
            Axml.Attr split = manifest != null ? Axml.attr(manifest, "split") : null;

            Axml.Node sdk = ax.element("uses-sdk");
            int minSdk = sdk != null && Axml.attr(sdk, "minSdkVersion") != null
                    ? Axml.attr(sdk, "minSdkVersion").data : -1;
            int targetSdk = sdk != null && Axml.attr(sdk, "targetSdkVersion") != null
                    ? Axml.attr(sdk, "targetSdkVersion").data : -1;

            Axml.Node app = ax.element("application");
            Axml.Attr splitReqAttr = app != null ? Axml.attr(app, "isSplitRequired") : null;
            boolean splitReq = splitReqAttr != null && (splitReqAttr.data == -1 || splitReqAttr.data == 1);

            int providers = 0, perms = 0;
            String cloneNum = null, cloneOrig = null;
            List<String> stack = new ArrayList<>();
            for (Axml.Node n : ax.nodes) {
                if (n.kind == Axml.START) {
                    String parent = stack.isEmpty() ? null : stack.get(stack.size() - 1);
                    stack.add(n.name);
                    if ("provider".equals(n.name) && "application".equals(parent)) providers++;
                    else if ("permission".equals(n.name) && "manifest".equals(parent)) perms++;
                    else if ("meta-data".equals(n.name) && "application".equals(parent)) {
                        Axml.Attr k = Axml.attr(n, "name");
                        Axml.Attr v = Axml.attr(n, "value");
                        if (k != null && v != null) {
                            if ("io.openappcc.CLONE".equals(k.raw)) cloneNum = String.valueOf(v.data);
                            else if ("io.openappcc.ORIGINAL".equals(k.raw)) cloneOrig = v.raw;
                        }
                    }
                } else if (n.kind == Axml.END && !stack.isEmpty()) {
                    stack.remove(stack.size() - 1);
                }
            }

            boolean v1 = false;
            Set<String> abis = new LinkedHashSet<>();
            Set<String> packers = new LinkedHashSet<>();
            int encryptedAssets = 0;
            boolean stubDex = false;

            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();
                String low = name.toLowerCase(Locale.US);
                if (low.startsWith("meta-inf/") && (low.endsWith(".rsa") || low.endsWith(".dsa") || low.endsWith(".ec"))) {
                    v1 = true;
                }
                if (name.startsWith("lib/")) {
                    int sl = name.indexOf('/', 4);
                    if (sl > 4) abis.add(name.substring(4, sl));
                }
                for (String[] pm : PACKER_MARKERS) {
                    for (int idx = 1; idx < pm.length; idx++) {
                        if (!pm[idx].startsWith("L") && low.contains(pm[idx])) packers.add(pm[0]);
                    }
                }
                if (name.matches("classes\\d*\\.dex")) {
                    byte[] dex = readEntry(zip, e);
                    if (dex.length > 1_000_000 && dex[0] == 'd' && dex[1] == 'e' && dex[2] == 'x') {
                        int classCount = Dex.u32(dex, 96);
                        if (classCount < 100) stubDex = true;
                    }
                    for (String[] pm : PACKER_MARKERS) {
                        for (int idx = 1; idx < pm.length; idx++) {
                            if (pm[idx].startsWith("L") && containsAscii(dex, pm[idx])) packers.add(pm[0]);
                        }
                    }
                }
                if (low.startsWith("assets/") && (low.endsWith(".dat") || low.endsWith(".dex") || low.endsWith(".zip"))) {
                    byte[] head = new byte[4];
                    try (InputStream in = zip.getInputStream(e)) {
                        int r = in.read(head);
                        boolean plain = r >= 4 && ((head[0] == 'd' && head[1] == 'e' && head[2] == 'x' && head[3] == '\n')
                                || (head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4));
                        if (!plain) encryptedAssets++;
                    }
                }
            }

            boolean[] v2v3 = detectV2V3(apkFile);
            boolean v2 = v2v3[0], v3 = v2v3[1];

            sb.append("Package: ").append(pkg).append('\n');
            sb.append("Version: ").append(vn != null ? vn.raw : "?").append(" (code ")
                    .append(vc != null ? vc.data : -1).append(")\n");
            sb.append("SDK: minSdk=").append(minSdk).append(", targetSdk=").append(targetSdk).append('\n');
            sb.append("ABIs: ").append(abis.isEmpty() ? "none (pure DEX)" : String.join(", ", abis)).append('\n');
            sb.append("Signing: v1=").append(v1).append(", v2=").append(v2).append(", v3=").append(v3).append('\n');
            sb.append("Providers: ").append(providers).append(" | Permissions: ").append(perms).append('\n');
            if (cloneNum != null || cloneOrig != null) {
                sb.append("Clone Stamp: #").append(cloneNum).append(" from ").append(cloneOrig).append('\n');
            }
            if (!packers.isEmpty() || stubDex || encryptedAssets > 0) {
                sb.append("Packers: ").append(packers.isEmpty() ? "stub" : String.join(", ", packers))
                        .append(" (encrypted assets: ").append(encryptedAssets).append(")\n");
            }

            List<String> findings = new ArrayList<>();
            if (targetSdk > 0 && targetSdk < 24) {
                findings.add("[BLOCKER] targetSdk " + targetSdk + " < 24 (raise Min Target SDK)");
            }
            if (splitReq) {
                findings.add("[INFO] App uses split APKs (isSplitRequired=true) - cloned as split set");
            }
            if (split != null && split.raw != null) {
                findings.add("[INFO] Split module: " + split.raw);
            }
            if (!abis.isEmpty() && !abis.contains("arm64-v8a") && !abis.contains("x86_64")) {
                findings.add("[WARN] 32-bit only ABIs (" + String.join(", ", abis) + ")");
            }
            if (!v1 && !v2 && !v3) {
                findings.add("[BLOCKER] Unsigned APK");
            }
            if (uid != null && uid.raw != null) {
                findings.add("[WARN] sharedUserId=" + uid.raw + " (enable Strip sharedUserId)");
            }
            if (!packers.isEmpty() || stubDex) {
                findings.add("[WARN] Protected/packed app may self-abort on repackaged signature");
            }

            sb.append('\n');
            if (findings.isEmpty()) {
                sb.append("Verdict: Ready (no blockers detected)");
            } else {
                sb.append("Findings:\n");
                for (String f : findings) sb.append("  ").append(f).append('\n');
            }
        } catch (Exception e) {
            return "Doctor inspect error: " + e.getMessage();
        }
        return sb.toString().trim();
    }
}
