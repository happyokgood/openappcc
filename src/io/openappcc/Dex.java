package io.openappcc;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
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

    public static void collectTypeClasses(byte[] src, Set<String> outClasses) {
        if (src == null || src.length < 0x70 || src[0] != 'd' || src[1] != 'e' || src[2] != 'x') return;
        int count = u32(src, 0x38);
        int idsOff = u32(src, 0x3c);
        int typeCount = u32(src, 0x40);
        int typeOff = u32(src, 0x44);
        for (int t = 0; t < typeCount; t++) {
            int tp = typeOff + t * 4;
            if (tp + 4 > src.length) break;
            int sIdx = u32(src, tp);
            if (sIdx < 0 || sIdx >= count) continue;
            int at = u32(src, idsOff + sIdx * 4);
            if (at <= 0 || at >= src.length) continue;
            String desc = readString(src, at);
            if (desc.length() > 2 && desc.charAt(0) == 'L' && desc.charAt(desc.length() - 1) == ';') {
                String cls = desc.substring(1, desc.length() - 1).replace('/', '.');
                outClasses.add(cls);
                if (cls.indexOf('$') >= 0) outClasses.add(cls.replace('$', '.'));
            }
        }
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
        boolean changed = false;
        boolean doDesc = renameClasses && oldPkg.length() == newPkg.length() && !oldPkg.equals(newPkg);
        String oldSlash = doDesc ? oldPkg.replace('.', '/') : null;
        String newSlash = doDesc ? newPkg.replace('.', '/') : null;

        Set<String> skipClasses = null;
        if (!doDesc) {
            if (protectedClasses != null) {
                skipClasses = protectedClasses;
            } else {
                skipClasses = new HashSet<>();
                collectTypeClasses(out, skipClasses);
                if (authorityNames != null) skipClasses.removeAll(authorityNames);
            }
        }

        String[] strings = new String[count];
        Set<String> allStrings = new HashSet<>(count * 2);
        for (int i = 0; i < count; i++) {
            int at = u32(out, idsOff + i * 4);
            strings[i] = (at > 0 && at < out.length) ? readString(out, at) : "";
            allStrings.add(strings[i]);
        }

        for (int i = 0; i < count; i++) {
            int at = u32(out, idsOff + i * 4);
            if (at <= 0 || at >= out.length) continue;
            String s = strings[i];
            if (s.isEmpty() || (!doDesc && !s.contains("://") && (isCodeShape(s) || isProtectedClass(s, skipClasses, authorityNames)))) {
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
                continue;
            }

            byte[] from = mutf8(s);
            byte[] to = mutf8(next);
            if (s.length() != next.length() || from.length != to.length || allStrings.contains(next)) {
                r.skipped++;
                continue;
            }
            allStrings.remove(s);
            allStrings.add(next);
            strings[i] = next;
            System.arraycopy(to, 0, out, ulebEnd(out, at), to.length);
            r.replaced++;
            changed = true;
            if (r.changes.size() < 20) r.changes.add(s + " -> " + next);
        }

        if (changed) {
            if (!resortAndRemapStrings(out, count, idsOff, strings)) {
                r.bytes = src;
                r.replaced = 0;
                r.changes.clear();
                return r;
            }
            r.bytes = reseal(out);
        }
        return r;
    }

    private static boolean isProtectedClass(String s, Set<String> skipClasses, Set<String> authorityNames) {
        if (authorityNames != null && authorityNames.contains(s)) return false;
        if (skipClasses == null || skipClasses.isEmpty()) return false;
        if (skipClasses.contains(s)) return true;
        int dot = s.lastIndexOf('.');
        while (dot > 0) {
            if (skipClasses.contains(s.substring(0, dot))) {
                String tail = s.substring(dot + 1);
                if (!tail.isEmpty() && Character.isUpperCase(tail.charAt(0)) && !tail.equals(tail.toUpperCase())) {
                    return true;
                }
            }
            dot = s.lastIndexOf('.', dot - 1);
        }
        return false;
    }

    private static final byte[] INSN_UNITS = {
        1,1,2,3,1,2,3,1,2,3,1,1,1,1,1,1, // 00..0f
        1,1,1,2,3,2,2,3,5,2,2,3,2,1,1,2, // 10..1f
        2,1,2,2,3,3,3,1,1,2,3,3,3,2,2,2, // 20..2f
        2,2,2,2,2,2,2,2,2,2,2,2,2,2,1,1, // 30..3f
        1,1,1,1,2,2,2,2,2,2,2,2,2,2,2,2, // 40..4f
        2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // 50..5f
        2,2,2,2,2,2,2,2,2,2,2,2,2,2,3,3, // 60..6f
        3,3,3,1,3,3,3,3,3,1,1,1,1,1,1,1, // 70..7f
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // 80..8f
        2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // 90..9f
        2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // a0..af
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // b0..bf
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // c0..cf
        2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // d0..df
        2,2,2,1,1,1,1,1,1,1,1,1,1,1,1,1, // e0..ef
        1,1,1,1,1,1,1,1,1,1,4,4,3,3,2,2  // f0..ff
    };

    private static int u16(byte[] b, int p) {
        return (b[p] & 0xff) | ((b[p + 1] & 0xff) << 8);
    }

    private static void put16(byte[] b, int p, int v) {
        b[p] = (byte) v;
        b[p + 1] = (byte) (v >>> 8);
    }

    private static int ulebLen(int v) {
        int n = 1;
        while ((v >>>= 7) != 0) n++;
        return n;
    }

    private static int readUleb(byte[] b, int[] pos) {
        int p = pos[0], v = 0, s = 0;
        while (true) {
            int c = b[p++] & 0xff;
            v |= (c & 0x7f) << s;
            if ((c & 0x80) == 0) {
                pos[0] = p;
                return v;
            }
            s += 7;
        }
    }

    private static void skipSleb(byte[] b, int[] pos) {
        int p = pos[0];
        while ((b[p++] & 0x80) != 0) {}
        pos[0] = p;
    }

    private static void writeUleb(byte[] b, int at, int v) {
        while (v >= 0x80) {
            b[at++] = (byte) ((v & 0x7f) | 0x80);
            v >>>= 7;
        }
        b[at] = (byte) v;
    }

    private static boolean remapUlebStringIdx(byte[] out, int[] pos, int[] oldToNew, boolean plusOne, boolean dryRun) {
        int start = pos[0];
        int raw = readUleb(out, pos);
        int oldIdx = plusOne ? raw - 1 : raw;
        if (oldIdx < 0 || oldIdx >= oldToNew.length) return true;
        int newIdx = oldToNew[oldIdx];
        if (newIdx == oldIdx) return true;
        int newRaw = plusOne ? newIdx + 1 : newIdx;
        int oldLen = pos[0] - start;
        if (ulebLen(newRaw) != oldLen) return false;
        if (!dryRun) writeUleb(out, start, newRaw);
        return true;
    }

    private static boolean resortAndRemapStrings(byte[] out, int count, int idsOff, String[] strings) {
        Integer[] order = new Integer[count];
        for (int i = 0; i < count; i++) order[i] = i;
        Arrays.sort(order, (a, b) -> strings[a].compareTo(strings[b]));
        boolean identity = true;
        for (int i = 0; i < count; i++) {
            if (order[i] != i) {
                identity = false;
                break;
            }
        }
        if (identity) return true;

        int[] oldToNew = new int[count];
        for (int newIdx = 0; newIdx < count; newIdx++) {
            oldToNew[order[newIdx]] = newIdx;
        }
        if (!remapStrings(out, oldToNew, true)) return false;

        int[] oldOffs = new int[count];
        for (int i = 0; i < count; i++) oldOffs[i] = u32(out, idsOff + i * 4);
        for (int newIdx = 0; newIdx < count; newIdx++) {
            put32(out, idsOff + newIdx * 4, oldOffs[order[newIdx]]);
        }
        return remapStrings(out, oldToNew, false);
    }

    private static boolean remapStrings(byte[] out, int[] oldToNew, boolean dryRun) {
        int typeCount = u32(out, 0x40), typeOff = u32(out, 0x44);
        for (int i = 0; i < typeCount; i++) {
            int p = typeOff + i * 4;
            int idx = u32(out, p);
            if (idx >= 0 && idx < oldToNew.length && oldToNew[idx] != idx && !dryRun) put32(out, p, oldToNew[idx]);
        }
        int protoCount = u32(out, 0x48), protoOff = u32(out, 0x4c);
        for (int i = 0; i < protoCount; i++) {
            int p = protoOff + i * 12;
            int idx = u32(out, p);
            if (idx >= 0 && idx < oldToNew.length && oldToNew[idx] != idx && !dryRun) put32(out, p, oldToNew[idx]);
        }
        int fieldCount = u32(out, 0x50), fieldOff = u32(out, 0x54);
        for (int i = 0; i < fieldCount; i++) {
            int p = fieldOff + i * 8 + 4;
            int idx = u32(out, p);
            if (idx >= 0 && idx < oldToNew.length && oldToNew[idx] != idx && !dryRun) put32(out, p, oldToNew[idx]);
        }
        int methodCount = u32(out, 0x58), methodOff = u32(out, 0x5c);
        for (int i = 0; i < methodCount; i++) {
            int p = methodOff + i * 8 + 4;
            int idx = u32(out, p);
            if (idx >= 0 && idx < oldToNew.length && oldToNew[idx] != idx && !dryRun) put32(out, p, oldToNew[idx]);
        }
        int classCount = u32(out, 0x60), classOff = u32(out, 0x64);
        Set<Integer> visited = new HashSet<>();
        for (int i = 0; i < classCount; i++) {
            int cOff = classOff + i * 32;
            int sfP = cOff + 16;
            int sfIdx = u32(out, sfP);
            if (sfIdx >= 0 && sfIdx < oldToNew.length && oldToNew[sfIdx] != sfIdx && !dryRun) put32(out, sfP, oldToNew[sfIdx]);

            int annOff = u32(out, cOff + 20);
            if (annOff != 0 && visited.add(annOff)) {
                if (!remapAnnotationsDir(out, annOff, oldToNew, visited, dryRun)) return false;
            }
            int dataOff = u32(out, cOff + 24);
            if (dataOff != 0 && visited.add(dataOff)) {
                if (!remapClassData(out, dataOff, oldToNew, visited, dryRun)) return false;
            }
            int svOff = u32(out, cOff + 28);
            if (svOff != 0 && visited.add(svOff)) {
                int[] pos = {svOff};
                if (!remapEncodedArray(out, pos, oldToNew, dryRun)) return false;
            }
        }
        return true;
    }

    private static boolean remapClassData(byte[] out, int off, int[] oldToNew, Set<Integer> visited, boolean dryRun) {
        int[] pos = {off};
        int sf = readUleb(out, pos), inf = readUleb(out, pos), dm = readUleb(out, pos), vm = readUleb(out, pos);
        for (int i = 0; i < sf + inf; i++) {
            readUleb(out, pos);
            readUleb(out, pos);
        }
        for (int i = 0; i < dm + vm; i++) {
            readUleb(out, pos);
            readUleb(out, pos);
            int codeOff = readUleb(out, pos);
            if (codeOff != 0 && visited.add(codeOff)) {
                if (!remapCodeItem(out, codeOff, oldToNew, visited, dryRun)) return false;
            }
        }
        return true;
    }

    private static boolean remapCodeItem(byte[] out, int codeOff, int[] oldToNew, Set<Integer> visited, boolean dryRun) {
        int dbgOff = u32(out, codeOff + 8);
        if (dbgOff != 0 && visited.add(dbgOff)) {
            if (!remapDebugInfo(out, dbgOff, oldToNew, dryRun)) return false;
        }
        int insnsSize = u32(out, codeOff + 12);
        int insnsStart = codeOff + 16;
        int pc = 0;
        while (pc < insnsSize) {
            int p = insnsStart + pc * 2;
            int op = out[p] & 0xff;
            if (op == 0x00) {
                int sub = u16(out, p);
                if (sub == 0x0100) {
                    int sz = u16(out, p + 2);
                    pc += 4 + sz * 2;
                    continue;
                } else if (sub == 0x0200) {
                    int sz = u16(out, p + 2);
                    pc += 2 + sz * 4;
                    continue;
                } else if (sub == 0x0300) {
                    int ew = u16(out, p + 2);
                    int sz = u32(out, p + 4);
                    pc += 4 + ((sz * ew + 1) / 2);
                    continue;
                }
            } else if (op == 0x1a) {
                int oldIdx = u16(out, p + 2);
                if (oldIdx < oldToNew.length && oldToNew[oldIdx] != oldIdx) {
                    int newIdx = oldToNew[oldIdx];
                    if (newIdx > 0xffff) return false;
                    if (!dryRun) put16(out, p + 2, newIdx);
                }
            } else if (op == 0x1b) {
                int oldIdx = u32(out, p + 2);
                if (oldIdx >= 0 && oldIdx < oldToNew.length && oldToNew[oldIdx] != oldIdx && !dryRun) {
                    put32(out, p + 2, oldToNew[oldIdx]);
                }
            }
            pc += INSN_UNITS[op];
        }
        return true;
    }

    private static boolean remapDebugInfo(byte[] out, int off, int[] oldToNew, boolean dryRun) {
        int[] pos = {off};
        readUleb(out, pos); // line_start
        int paramSize = readUleb(out, pos);
        for (int i = 0; i < paramSize; i++) {
            if (!remapUlebStringIdx(out, pos, oldToNew, true, dryRun)) return false;
        }
        while (pos[0] < out.length) {
            int op = out[pos[0]++] & 0xff;
            if (op == 0x00) break;
            switch (op) {
                case 0x01: readUleb(out, pos); break;
                case 0x02: skipSleb(out, pos); break;
                case 0x03:
                    readUleb(out, pos);
                    if (!remapUlebStringIdx(out, pos, oldToNew, true, dryRun)) return false;
                    readUleb(out, pos);
                    break;
                case 0x04:
                    readUleb(out, pos);
                    if (!remapUlebStringIdx(out, pos, oldToNew, true, dryRun)) return false;
                    readUleb(out, pos);
                    if (!remapUlebStringIdx(out, pos, oldToNew, true, dryRun)) return false;
                    break;
                case 0x05:
                case 0x06:
                    readUleb(out, pos);
                    break;
                case 0x09:
                    if (!remapUlebStringIdx(out, pos, oldToNew, true, dryRun)) return false;
                    break;
                default:
                    break;
            }
        }
        return true;
    }

    private static boolean remapAnnotationsDir(byte[] out, int off, int[] oldToNew, Set<Integer> visited, boolean dryRun) {
        int classAnnOff = u32(out, off);
        int fieldsSize = u32(out, off + 4);
        int methodsSize = u32(out, off + 8);
        int paramsSize = u32(out, off + 12);
        if (classAnnOff != 0 && visited.add(classAnnOff)) {
            if (!remapAnnotationSet(out, classAnnOff, oldToNew, visited, dryRun)) return false;
        }
        int p = off + 16;
        for (int i = 0; i < fieldsSize + methodsSize; i++, p += 8) {
            int setOff = u32(out, p + 4);
            if (setOff != 0 && visited.add(setOff)) {
                if (!remapAnnotationSet(out, setOff, oldToNew, visited, dryRun)) return false;
            }
        }
        for (int i = 0; i < paramsSize; i++, p += 8) {
            int refOff = u32(out, p + 4);
            if (refOff != 0 && visited.add(refOff)) {
                int cnt = u32(out, refOff);
                for (int j = 0; j < cnt; j++) {
                    int setOff = u32(out, refOff + 4 + j * 4);
                    if (setOff != 0 && visited.add(setOff)) {
                        if (!remapAnnotationSet(out, setOff, oldToNew, visited, dryRun)) return false;
                    }
                }
            }
        }
        return true;
    }

    private static boolean remapAnnotationSet(byte[] out, int off, int[] oldToNew, Set<Integer> visited, boolean dryRun) {
        int cnt = u32(out, off);
        for (int i = 0; i < cnt; i++) {
            int annOff = u32(out, off + 4 + i * 4);
            if (annOff != 0 && visited.add(annOff)) {
                int[] pos = {annOff + 1}; // skip visibility byte
                if (!remapEncodedAnnotation(out, pos, oldToNew, dryRun)) return false;
            }
        }
        return true;
    }

    private static boolean remapEncodedAnnotation(byte[] out, int[] pos, int[] oldToNew, boolean dryRun) {
        readUleb(out, pos); // type_idx
        int size = readUleb(out, pos);
        for (int i = 0; i < size; i++) {
            if (!remapUlebStringIdx(out, pos, oldToNew, false, dryRun)) return false;
            if (!remapEncodedValue(out, pos, oldToNew, dryRun)) return false;
        }
        return true;
    }

    private static boolean remapEncodedArray(byte[] out, int[] pos, int[] oldToNew, boolean dryRun) {
        int size = readUleb(out, pos);
        for (int i = 0; i < size; i++) {
            if (!remapEncodedValue(out, pos, oldToNew, dryRun)) return false;
        }
        return true;
    }

    private static boolean remapEncodedValue(byte[] out, int[] pos, int[] oldToNew, boolean dryRun) {
        int hdr = out[pos[0]++] & 0xff;
        int type = hdr & 0x1f;
        int arg = hdr >>> 5;
        if (type == 0x17) { // VALUE_STRING
            int sz = arg + 1;
            int at = pos[0];
            int oldIdx = 0;
            for (int i = 0; i < sz; i++) oldIdx |= (out[at + i] & 0xff) << (i * 8);
            pos[0] = at + sz;
            if (oldIdx >= 0 && oldIdx < oldToNew.length && oldToNew[oldIdx] != oldIdx) {
                int newIdx = oldToNew[oldIdx];
                if (sz < 4 && (newIdx >>> (sz * 8)) != 0) return false;
                if (!dryRun) {
                    for (int i = 0; i < sz; i++) out[at + i] = (byte) (newIdx >>> (i * 8));
                }
            }
            return true;
        } else if (type == 0x1c) {
            return remapEncodedArray(out, pos, oldToNew, dryRun);
        } else if (type == 0x1d) {
            return remapEncodedAnnotation(out, pos, oldToNew, dryRun);
        } else if (type == 0x1e || type == 0x1f) {
            return true;
        } else {
            pos[0] += arg + 1;
            return true;
        }
    }
}
