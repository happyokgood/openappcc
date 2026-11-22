package io.openappcc;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * resources.arsc package renamer and resource-ID path resolver.
 */
public final class Arsc {
    private Arsc() {
    }

    public static byte[] renamePackage(byte[] arsc, String newPackage) {
        return renamePackage(arsc, null, newPackage);
    }

    public static byte[] renamePackage(byte[] arsc, String oldPackage, String newPackage) {
        if (arsc.length < 12) return arsc;
        ByteBuffer in = ByteBuffer.wrap(arsc).order(ByteOrder.LITTLE_ENDIAN);
        if ((in.getShort(0) & 0xffff) != 0x0002) return arsc;
        int total = Math.min(in.getInt(4), arsc.length);
        int headerSize = in.getShort(2) & 0xffff;
        byte[] out = arsc.clone();
        boolean patched = false;
        int p = headerSize;
        while (p + 8 <= total) {
            int type = in.getShort(p) & 0xffff;
            int size = in.getInt(p + 4);
            if (size < 8 || p + size > total) break;
            if (type == 0x0001 && oldPackage != null && oldPackage.length() == newPackage.length()
                    && !oldPackage.equals(newPackage)) {
                // shortcut: equal-length in-place global pool patch, upgrade to full pool rewriter for variable lengths
                if (replaceInRange(out, p, p + size, oldPackage.getBytes(StandardCharsets.UTF_8),
                        newPackage.getBytes(StandardCharsets.UTF_8))) patched = true;
                if (replaceInRange(out, p, p + size, oldPackage.getBytes(StandardCharsets.UTF_16LE),
                        newPackage.getBytes(StandardCharsets.UTF_16LE))) patched = true;
            } else if (type == 0x0200 && p + 268 <= total) {
                byte[] name = newPackage.getBytes(StandardCharsets.UTF_16LE);
                if (name.length > 256) throw new IllegalArgumentException("package name too long");
                if (oldPackage != null) {
                    String cur = new String(out, p + 12, 256, StandardCharsets.UTF_16LE);
                    int z = cur.indexOf('\0');
                    if (z >= 0) cur = cur.substring(0, z);
                    if (!oldPackage.equals(cur)) {
                        p += size;
                        continue;
                    }
                }
                for (int i = p + 12; i < p + 12 + 256; i++) out[i] = 0;
                System.arraycopy(name, 0, out, p + 12, name.length);
                patched = true;
                if (oldPackage == null) break;
            }
            p += size;
        }
        return patched ? out : arsc;
    }

    private static boolean replaceInRange(byte[] buf, int from, int to, byte[] needle, byte[] repl) {
        if (needle.length == 0 || needle.length != repl.length || to - from < needle.length) return false;
        boolean hit = false;
        int limit = to - needle.length;
        outer:
        for (int i = from; i <= limit; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (buf[i + j] != needle[j]) continue outer;
            }
            System.arraycopy(repl, 0, buf, i, repl.length);
            i += repl.length - 1;
            hit = true;
        }
        return hit;
    }

    public static List<String> paths(byte[] arsc, int resId) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (arsc == null || arsc.length < 12 || resId == 0) return new ArrayList<>(out);
        try {
            ByteBuffer b = ByteBuffer.wrap(arsc).order(ByteOrder.LITTLE_ENDIAN);
            if ((b.getShort(0) & 0xffff) != 0x0002) return new ArrayList<>(out);
            int total = Math.min(b.getInt(4), arsc.length);
            int pool = globalPool(b, total);
            if (pool > 0) collectPaths(b, total, pool, resId & 0xffffffffL, out, 0);
        } catch (Exception ignored) {
        }
        return new ArrayList<>(out);
    }

    private static int globalPool(ByteBuffer b, int total) {
        int p = b.getShort(2) & 0xffff;
        while (p + 8 <= total) {
            int type = b.getShort(p) & 0xffff;
            int size = b.getInt(p + 4);
            if (size < 8) break;
            if (type == 0x0001) return p;
            p += size;
        }
        return -1;
    }

    private static void collectPaths(ByteBuffer b, int total, int pool, long id,
                                     Set<String> out, int depth) {
        if (depth > 8) return;
        int wantPkg = (int) ((id >>> 24) & 0xff);
        int wantType = (int) ((id >>> 16) & 0xff);
        int wantEntry = (int) (id & 0xffff);
        int p = b.getShort(2) & 0xffff;
        while (p + 8 <= total) {
            int type = b.getShort(p) & 0xffff;
            int size = b.getInt(p + 4);
            if (size < 8) break;
            if (type == 0x0200) {
                if (b.getInt(p + 8) != wantPkg) {
                    p += size;
                    continue;
                }
                int q = p + (b.getShort(p + 2) & 0xffff);
                int end = Math.min(p + size, total);
                while (q + 8 <= end) {
                    int ctype = b.getShort(q) & 0xffff;
                    int csize = b.getInt(q + 4);
                    if (csize < 8) break;
                    if (ctype == 0x0201 && (b.get(q + 8) & 0xff) == wantType) {
                        long off = entryOffset(b, q, wantEntry);
                        if (off >= 0) {
                            int e = q + b.getInt(q + 16) + (int) off;
                            if (e + 8 <= q + csize) {
                                if ((b.getShort(e + 2) & 0x0001) != 0) {
                                    q += csize;
                                    continue;
                                }
                                int valueAt = e + (b.getShort(e) & 0xffff);
                                if (valueAt + 8 <= q + csize) {
                                    int vtype = b.get(valueAt + 3) & 0xff;
                                    long vdata = b.getInt(valueAt + 4) & 0xffffffffL;
                                    if (vtype == 0x03) {
                                        String s = string(b, pool, (int) vdata);
                                        if (s != null) out.add(s);
                                    } else if (vtype == 0x01 && vdata != 0) {
                                        collectPaths(b, total, pool, vdata, out, depth + 1);
                                    }
                                }
                            }
                        }
                    }
                    q += csize;
                }
                return;
            }
            p += size;
        }
    }

    private static long entryOffset(ByteBuffer b, int chunk, int entryIdx) {
        try {
            int flags = b.get(chunk + 9) & 0xff;
            int count = b.getInt(chunk + 12);
            int config = chunk + 20;
            int configSize = b.getInt(config);
            if (configSize < 4) return -1;
            int offsets = config + configSize;
            if ((flags & 0x01) != 0) {
                for (int i = 0; i < count; i++) {
                    if ((b.getShort(offsets + i * 4) & 0xffff) == entryIdx) {
                        return (b.getShort(offsets + i * 4 + 2) & 0xffff) * 4L;
                    }
                }
                return -1;
            }
            if (entryIdx >= count) return -1;
            if ((flags & 0x02) != 0) {
                int o = b.getShort(offsets + entryIdx * 2) & 0xffff;
                return o == 0xffff ? -1 : o * 4L;
            }
            long o = b.getInt(offsets + entryIdx * 4) & 0xffffffffL;
            return o == 0xffffffffL ? -1 : o;
        } catch (Exception e) {
            return -1;
        }
    }

    static String string(ByteBuffer b, int pool, int index) {
        try {
            if (pool <= 0 || pool + 28 > b.capacity()) return null;
            int count = b.getInt(pool + 8);
            if (index < 0 || index >= count) return null;
            int flags = b.getInt(pool + 16);
            int stringsStart = pool + b.getInt(pool + 20);
            int at = stringsStart + b.getInt(pool + 28 + index * 4);
            boolean utf8 = (flags & 0x100) != 0;
            int n = b.get(at) & 0xff;
            at++;
            if ((n & 0x80) != 0) {
                n = ((n & 0x7f) << 8) | (b.get(at) & 0xff);
                at++;
            }
            if (utf8) {
                int n2 = b.get(at) & 0xff;
                at++;
                if ((n2 & 0x80) != 0) {
                    n2 = ((n2 & 0x7f) << 8) | (b.get(at) & 0xff);
                    at++;
                }
                byte[] s = new byte[n2];
                for (int i = 0; i < n2; i++) s[i] = b.get(at + i);
                return new String(s, StandardCharsets.UTF_8);
            }
            byte[] s = new byte[n * 2];
            for (int i = 0; i < n * 2; i++) s[i] = b.get(at + i);
            return new String(s, StandardCharsets.UTF_16LE);
        } catch (Exception e) {
            return null;
        }
    }
}
