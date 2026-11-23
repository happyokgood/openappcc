package io.openappcc;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.Adler32;

/**
 * In-place DEX string patcher with SHA-1 and Adler32 resealing.
 */
public final class Dex {
    private Dex() {
    }

    public static final class Result {
        public byte[] bytes;
        public int replaced;
        public int skipped;
        public final List<String> changes = new ArrayList<>();
    }

    static int u32(byte[] b, int p) {
        return (b[p] & 0xff) | ((b[p + 1] & 0xff) << 8)
                | ((b[p + 2] & 0xff) << 16) | ((b[p + 3] & 0xff) << 24);
    }

    static void put32(byte[] b, int p, int v) {
        b[p] = (byte) v;
        b[p + 1] = (byte) (v >>> 8);
        b[p + 2] = (byte) (v >>> 16);
        b[p + 3] = (byte) (v >>> 24);
    }

    static int ulebEnd(byte[] b, int at) {
        while ((b[at] & 0x80) != 0) at++;
        return at + 1;
    }

    static byte[] mutf8(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); i++) {
            int c = s.charAt(i);
            if (c != 0 && c < 0x80) out.write(c);
            else if (c < 0x800) {
                out.write(0xc0 | (c >> 6));
                out.write(0x80 | (c & 0x3f));
            } else {
                out.write(0xe0 | (c >> 12));
                out.write(0x80 | ((c >> 6) & 0x3f));
                out.write(0x80 | (c & 0x3f));
            }
        }
        return out.toByteArray();
    }

    static String readString(byte[] b, int at) {
        int p = ulebEnd(b, at);
        int end = p;
        while (end < b.length && b[end] != 0) end++;
        StringBuilder sb = new StringBuilder(end - p);
        while (p < end) {
            int c = b[p++] & 0xff;
            if (c < 0x80) sb.append((char) c);
            else if ((c & 0xe0) == 0xc0 && p < end) sb.append((char) (((c & 0x1f) << 6) | (b[p++] & 0x3f)));
            else if ((c & 0xf0) == 0xe0 && p + 1 < end) sb.append((char) (((c & 0x0f) << 12) | ((b[p++] & 0x3f) << 6) | (b[p++] & 0x3f)));
            else sb.append('\ufffd');
        }
        return sb.toString();
    }

    static boolean isCodeShape(String s) {
        return (s.startsWith("L") && s.endsWith(";")) || s.indexOf('/') >= 0 || s.indexOf('(') >= 0;
    }

    static String replacePkgBoundary(String s, String oldPkg, String newPkg, boolean renameClasses) {
        if (s.equals(oldPkg)) return newPkg;
        if (s.startsWith(oldPkg + ".") || s.startsWith(oldPkg + ":")) {
            if (!renameClasses && s.endsWith(".")) return s;
            return newPkg + s.substring(oldPkg.length());
        }
        String vndOld = "vnd." + oldPkg + ".";
        if (s.contains(vndOld)) {
            return s.replace(vndOld, "vnd." + newPkg + ".");
        }
        String marker = "://" + oldPkg;
        int idx = s.indexOf(marker);
        if (idx >= 0) {
            int after = idx + marker.length();
            if (after == s.length() || s.charAt(after) == '.' || s.charAt(after) == '/' || s.charAt(after) == ':') {
                return s.substring(0, idx + 3) + newPkg + s.substring(after);
            }
        }
        return s;
    }

    static int adler32(byte[] b, int from, int to) {
        Adler32 adler = new Adler32();
        adler.update(b, from, to - from);
        return (int) adler.getValue();
    }

    static byte[] reseal(byte[] b) {
        int fileSize = u32(b, 0x20);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(b, 32, fileSize - 32);
            byte[] sig = md.digest();
            System.arraycopy(sig, 0, b, 0x0c, 20);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        put32(b, 0x08, adler32(b, 12, fileSize));
        return b;
    }

    public static Result patch(byte[] src, String oldPkg, String newPkg, List<String[]> forced) {
        return patch(src, oldPkg, newPkg, forced, false, null, null);
    }

    public static Result patch(byte[] src, String oldPkg, String newPkg, List<String[]> forced, boolean renameClasses) {
        return patch(src, oldPkg, newPkg, forced, renameClasses, null, null);
    }

    public static Result patch(byte[] src, String oldPkg, String newPkg, List<String[]> forced,
                               boolean renameClasses, Set<String> protectedClasses, Set<String> authorityNames) {
        Result r = new Result();
        r.bytes = src;
        if (src.length < 0x70 || src[0] != 'd' || src[1] != 'e' || src[2] != 'x') return r;

        byte[] out = src.clone();
        int count = u32(out, 0x38);
        int idsOff = u32(out, 0x3c);
        int typeCount = u32(out, 0x40);
        int typeOff = u32(out, 0x44);
        boolean changed = false;
        boolean doDesc = renameClasses && oldPkg.length() == newPkg.length() && !oldPkg.equals(newPkg);
        String oldSlash = doDesc ? oldPkg.replace('.', '/') : null;
        String newSlash = doDesc ? newPkg.replace('.', '/') : null;
        byte[] prevBytes = null;

        Set<String> skipClasses = null;
        if (!doDesc) {
            skipClasses = new HashSet<>();
            if (protectedClasses != null) skipClasses.addAll(protectedClasses);
            for (int t = 0; t < typeCount; t++) {
                int tp = typeOff + t * 4;
                if (tp + 4 > out.length) break;
                int sIdx = u32(out, tp);
                if (sIdx < 0 || sIdx >= count) continue;
                int at = u32(out, idsOff + sIdx * 4);
                if (at <= 0 || at >= out.length) continue;
                String desc = readString(out, at);
                if (desc.length() > 2 && desc.charAt(0) == 'L' && desc.charAt(desc.length() - 1) == ';') {
                    skipClasses.add(desc.substring(1, desc.length() - 1).replace('/', '.'));
                }
            }
            if (authorityNames != null) skipClasses.removeAll(authorityNames);
        }

        for (int i = 0; i < count; i++) {
            int at = u32(out, idsOff + i * 4);
            if (at <= 0 || at >= out.length) continue;
            String s = readString(out, at);
            if (s.isEmpty() || (!doDesc && !s.contains("://") && (isCodeShape(s) || (skipClasses != null && skipClasses.contains(s))))) {
                if (doDesc) prevBytes = mutf8(s);
                continue;
            }

            String next = null;
            for (String[] f : forced) {
                if (f[0].equals(s)) {
                    next = f[1];
                    break;
                }
            }
            if (next == null) {
                String cand = replacePkgBoundary(s, oldPkg, newPkg, doDesc);
                if (!cand.equals(s)) {
                    next = cand;
                } else if (doDesc && (s.contains(oldSlash + "/") || s.endsWith("L" + oldSlash + ";") || s.equals(oldSlash))) {
                    cand = s.replace("L" + oldSlash + "/", "L" + newSlash + "/")
                            .replace("L" + oldSlash + ";", "L" + newSlash + ";");
                    if (cand.equals(s) && (s.equals(oldSlash) || s.startsWith(oldSlash + "/"))) {
                        cand = newSlash + s.substring(oldSlash.length());
                    }
                    if (!cand.equals(s)) next = cand;
                }
            }
            if (next == null || next.equals(s)) {
                if (doDesc) prevBytes = mutf8(s);
                continue;
            }

            byte[] from = mutf8(s);
            byte[] to = mutf8(next);
            if (s.length() != next.length() || from.length != to.length) {
                r.skipped++;
                if (doDesc) prevBytes = from;
                continue;
            }
            if (doDesc && prevBytes != null && compareUnsigned(prevBytes, to) > 0) {
                // Sort order would violate ART DEX verifier; abort descriptor patching for this DEX.
                r.bytes = src;
                r.replaced = 0;
                return r;
            }
            if (doDesc) prevBytes = to;
            System.arraycopy(to, 0, out, ulebEnd(out, at), to.length);
            r.replaced++;
            changed = true;
            if (r.changes.size() < 20) r.changes.add(s + " -> " + next);
        }

        if (changed) r.bytes = reseal(out);
        return r;
    }

    private static int compareUnsigned(byte[] a, byte[] b) {
        int lim = Math.min(a.length, b.length);
        for (int i = 0; i < lim; i++) {
            int d = (a[i] & 0xff) - (b[i] & 0xff);
            if (d != 0) return d;
        }
        return a.length - b.length;
    }
}
