package io.openappcc;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Binary AndroidManifest.xml (AXML) reader, AST helper, and writer.
 * Extends resourceMap when new android.R.attr attributes are inserted so PackageParser resolves them.
 */
public final class Axml {
    public static final int XML_TYPE = 0x0003, POOL = 0x0001, RESMAP = 0x0180;
    public static final int START_NS = 0x0100, END_NS = 0x0101, START = 0x0102, END = 0x0103, TEXT = 0x0104;
    public static final int UTF8_FLAG = 0x100;
    public static final long NO_ENTRY = 0xffffffffL;
    public static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";

    public static final Map<String, Long> ATTR_ID = new HashMap<>();
    static {
        ATTR_ID.put("label", 0x01010001L);
        ATTR_ID.put("name", 0x01010003L);
        ATTR_ID.put("enabled", 0x0101000EL);
        ATTR_ID.put("debuggable", 0x0101000FL);
        ATTR_ID.put("exported", 0x01010010L);
        ATTR_ID.put("excludeFromRecents", 0x01010017L);
        ATTR_ID.put("authorities", 0x01010018L);
        ATTR_ID.put("initOrder", 0x0101001AL);
        ATTR_ID.put("screenOrientation", 0x0101001EL);
        ATTR_ID.put("value", 0x01010024L);
        ATTR_ID.put("targetSdkVersion", 0x01010270L);
        ATTR_ID.put("allowBackup", 0x01010280L);
        ATTR_ID.put("extractNativeLibs", 0x010104EAL);
    }

    public static final class Attr {
        public String ns, name, raw;
        public int type, data;
        public long resId;
    }

    public static final class Node {
        public int kind, line;
        public String ns, name, prefix, uri, raw;
        public int type, data;
        public final List<Attr> attrs = new ArrayList<>();
    }

    public final List<String> strings = new ArrayList<>();
    public long[] resMap = new long[0];
    public final List<Node> nodes = new ArrayList<>();

    static int u16(byte[] b, int p) { return (b[p] & 0xff) | ((b[p + 1] & 0xff) << 8); }

    static long u32(byte[] b, int p) {
        return (b[p] & 0xffL) | ((b[p + 1] & 0xffL) << 8)
                | ((b[p + 2] & 0xffL) << 16) | ((b[p + 3] & 0xffL) << 24);
    }

    static int i32(byte[] b, int p) { return (int) u32(b, p); }

    static List<String> readPool(byte[] b, int p) {
        long count = u32(b, p + 8);
        long flags = u32(b, p + 16);
        long stringsStart = u32(b, p + 20);
        boolean utf8 = (flags & UTF8_FLAG) != 0;
        List<String> out = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            int off = (int) (p + stringsStart + u32(b, p + 28 + i * 4));
            if (utf8) {
                int q = off;
                int n = b[q++] & 0xff;
                if ((n & 0x80) != 0) q++;
                int len = b[q++] & 0xff;
                if ((len & 0x80) != 0) len = ((len & 0x7f) << 8) | (b[q++] & 0xff);
                out.add(new String(b, q, len, StandardCharsets.UTF_8));
            } else {
                int q = off;
                int n = u16(b, q);
                q += 2;
                if ((n & 0x8000) != 0) {
                    n = ((n & 0x7fff) << 16) | u16(b, q);
                    q += 2;
                }
                out.add(new String(b, q, n * 2, StandardCharsets.UTF_16LE));
            }
        }
        return out;
    }

    String s(long idx) {
        if (idx == NO_ENTRY || idx < 0 || idx >= strings.size()) return null;
        return strings.get((int) idx);
    }

    public static Axml parse(byte[] b) {
        if (b.length < 8 || u16(b, 0) != XML_TYPE) throw new IllegalArgumentException("not binary XML");
        Axml ax = new Axml();
        int p = 8;
        while (p + 8 <= b.length) {
            int type = u16(b, p);
            int headerSize = u16(b, p + 2);
            long size = u32(b, p + 4);
            if (size < 8 || p + size > b.length) break;
            if (type == POOL) {
                ax.strings.clear();
                ax.strings.addAll(readPool(b, p));
            } else if (type == RESMAP) {
                int n = (int) ((size - headerSize) / 4);
                ax.resMap = new long[n];
                for (int i = 0; i < n; i++) ax.resMap[i] = u32(b, p + headerSize + i * 4);
            } else if (type == START_NS || type == END_NS) {
                Node n = new Node();
                n.kind = type;
                n.line = i32(b, p + 8);
                n.prefix = ax.s(u32(b, p + 16));
                n.uri = ax.s(u32(b, p + 20));
                ax.nodes.add(n);
            } else if (type == START) {
                int ext = p + headerSize;
                int attrStart = u16(b, ext + 8);
                int attrSize = u16(b, ext + 10);
                int attrCount = u16(b, ext + 12);
                Node n = new Node();
                n.kind = START;
                n.line = i32(b, p + 8);
                n.ns = ax.s(u32(b, ext));
                n.name = ax.s(u32(b, ext + 4));
                for (int i = 0; i < attrCount; i++) {
                    int a = ext + attrStart + i * attrSize;
                    Attr at = new Attr();
                    at.ns = ax.s(u32(b, a));
                    long nameIdx = u32(b, a + 4);
                    at.name = ax.s(nameIdx);
                    long raw = u32(b, a + 8);
                    at.raw = raw == NO_ENTRY ? null : ax.s(raw);
                    at.type = b[a + 15] & 0xff;
                    at.data = i32(b, a + 16);
                    if (at.raw == null && at.type == 0x03) at.raw = ax.s(at.data & 0xffffffffL);
                    at.resId = (nameIdx >= 0 && nameIdx < ax.resMap.length) ? ax.resMap[(int) nameIdx] : 0L;
                    n.attrs.add(at);
                }
                ax.nodes.add(n);
            } else if (type == END) {
                int ext = p + headerSize;
                Node n = new Node();
                n.kind = END;
                n.line = i32(b, p + 8);
                n.ns = ax.s(u32(b, ext));
                n.name = ax.s(u32(b, ext + 4));
                ax.nodes.add(n);
            } else if (type == TEXT) {
                int ext = p + headerSize;
                Node n = new Node();
                n.kind = TEXT;
                n.line = i32(b, p + 8);
                n.raw = ax.s(u32(b, ext));
                n.type = b[ext + 7] & 0xff;
                n.data = i32(b, ext + 8);
                ax.nodes.add(n);
            }
            p += (int) size;
        }
        return ax;
    }

    static void le16(ByteArrayOutputStream o, int v) {
        o.write(v & 0xff);
        o.write((v >>> 8) & 0xff);
    }

    static void le32(ByteArrayOutputStream o, long v) {
        o.write((int) (v & 0xff));
        o.write((int) ((v >>> 8) & 0xff));
        o.write((int) ((v >>> 16) & 0xff));
        o.write((int) ((v >>> 24) & 0xff));
    }

    static int intern(List<String> pool, Map<String, Integer> idx, String s) {
        if (s == null) return -1;
        Integer i = idx.get(s);
        if (i != null) return i;
        int n = pool.size();
        pool.add(s);
        idx.put(s, n);
        return n;
    }

    static byte[] poolEntry(String str) {
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        int units = str.length();
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        if (units > 0x7f) {
            o.write(0x80 | ((units >> 8) & 0x7f));
            o.write(units & 0xff);
        } else {
            o.write(units);
        }
        if (bytes.length > 0x7f) {
            o.write(0x80 | ((bytes.length >> 8) & 0x7f));
            o.write(bytes.length & 0xff);
        } else {
            o.write(bytes.length);
        }
        o.write(bytes, 0, bytes.length);
        o.write(0);
        return o.toByteArray();
    }

    static byte[] buildPool(List<String> pool) {
        List<byte[]> encoded = new ArrayList<>();
        for (String s : pool) encoded.add(poolEntry(s));
        int cursor = 0;
        int[] offsets = new int[encoded.size()];
        for (int i = 0; i < encoded.size(); i++) {
            offsets[i] = cursor;
            cursor += encoded.get(i).length;
        }
        int headerSize = 28;
        int stringsStart = headerSize + pool.size() * 4;
        int size = (stringsStart + cursor + 3) & ~3;
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        le16(o, POOL);
        le16(o, headerSize);
        le32(o, size);
        le32(o, pool.size());
        le32(o, 0);
        le32(o, UTF8_FLAG);
        le32(o, stringsStart);
        le32(o, 0);
        for (int off : offsets) le32(o, off);
        for (byte[] e : encoded) o.write(e, 0, e.length);
        while (o.size() < size) o.write(0);
        return o.toByteArray();
    }

    static void nodeChunk(ByteArrayOutputStream out, int type, int line, byte[] body) {
        le16(out, type);
        le16(out, 16);
        le32(out, 16L + body.length);
        le32(out, line);
        le32(out, NO_ENTRY);
        out.write(body, 0, body.length);
    }

    public byte[] toBytes() {
        List<String> pool = new ArrayList<>(strings);
        Map<String, Integer> idx = new HashMap<>();
        for (int i = 0; i < pool.size(); i++) idx.putIfAbsent(pool.get(i), i);

        List<Long> mapList = new ArrayList<>();
        for (long id : resMap) mapList.add(id);

        ByteArrayOutputStream parts = new ByteArrayOutputStream();
        for (Node n : nodes) {
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            if (n.kind == START_NS || n.kind == END_NS) {
                le32(body, intern(pool, idx, n.prefix));
                le32(body, intern(pool, idx, n.uri));
                nodeChunk(parts, n.kind, n.line, body.toByteArray());
            } else if (n.kind == START) {
                le32(body, intern(pool, idx, n.ns));
                le32(body, intern(pool, idx, n.name));
                le16(body, 20);
                le16(body, 20);
                le16(body, n.attrs.size());
                le16(body, 0);
                le16(body, 0);
                le16(body, 0);
                for (Attr a : n.attrs) {
                    int strIdx = a.type == 0x03 && a.raw != null ? intern(pool, idx, a.raw) : -1;
                    int raw = strIdx >= 0 ? strIdx : intern(pool, idx, a.raw);
                    int nameIdx = intern(pool, idx, a.name);
                    if (nameIdx >= 0 && a.resId != 0) {
                        while (mapList.size() <= nameIdx) mapList.add(0L);
                        if (mapList.get(nameIdx) == 0L) mapList.set(nameIdx, a.resId);
                    }
                    le32(body, intern(pool, idx, a.ns));
                    le32(body, nameIdx);
                    le32(body, raw < 0 ? NO_ENTRY : raw);
                    le16(body, 8);
                    body.write(0);
                    body.write(a.type);
                    le32(body, strIdx >= 0 ? strIdx : (a.data & 0xffffffffL));
                }
                nodeChunk(parts, START, n.line, body.toByteArray());
            } else if (n.kind == END) {
                le32(body, intern(pool, idx, n.ns));
                le32(body, intern(pool, idx, n.name));
                nodeChunk(parts, END, n.line, body.toByteArray());
            } else if (n.kind == TEXT) {
                le32(body, intern(pool, idx, n.raw));
                le16(body, 8);
                body.write(0);
                body.write(n.type);
                le32(body, n.data & 0xffffffffL);
                nodeChunk(parts, TEXT, n.line, body.toByteArray());
            }
        }

        byte[] poolChunk = buildPool(pool);
        ByteArrayOutputStream mapChunk = new ByteArrayOutputStream();
        if (!mapList.isEmpty()) {
            le16(mapChunk, RESMAP);
            le16(mapChunk, 8);
            le32(mapChunk, 8L + mapList.size() * 4L);
            for (long id : mapList) le32(mapChunk, id);
        }

        byte[] body = parts.toByteArray();
        byte[] map = mapChunk.toByteArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        le16(out, XML_TYPE);
        le16(out, 8);
        le32(out, 8L + poolChunk.length + map.length + body.length);
        out.write(poolChunk, 0, poolChunk.length);
        out.write(map, 0, map.length);
        out.write(body, 0, body.length);
        return out.toByteArray();
    }

    public Node element(String tag) {
        for (Node n : nodes) if (n.kind == START && tag.equals(n.name)) return n;
        return null;
    }

    public static Attr attr(Node n, String name) {
        for (Attr a : n.attrs) if (name.equals(a.name)) return a;
        return null;
    }

    public static Attr setAttr(Node n, String name, String value) {
        Attr a = attr(n, name);
        if (a == null) {
            a = new Attr();
            a.name = name;
            a.ns = ANDROID_NS;
            Long rid = ATTR_ID.get(name);
            if (rid != null) a.resId = rid;
            n.attrs.add(a);
        }
        a.raw = value;
        a.type = 0x03;
        a.data = 0;
        if (a.resId == 0) {
            Long rid = ATTR_ID.get(name);
            if (rid != null) a.resId = rid;
        }
        return a;
    }

    public static Attr setBool(Node n, String name, boolean value) {
        Attr a = attr(n, name);
        if (a == null) {
            a = new Attr();
            a.name = name;
            a.ns = ANDROID_NS;
            Long rid = ATTR_ID.get(name);
            if (rid != null) a.resId = rid;
            n.attrs.add(a);
        }
        a.raw = value ? "true" : "false";
        a.type = 0x12;
        a.data = value ? -1 : 0;
        if (a.resId == 0) {
            Long rid = ATTR_ID.get(name);
            if (rid != null) a.resId = rid;
        }
        return a;
    }

    public static Attr setInt(Node n, String name, int value) {
        Attr a = attr(n, name);
        if (a == null) {
            a = new Attr();
            a.name = name;
            a.ns = ANDROID_NS;
            Long rid = ATTR_ID.get(name);
            if (rid != null) a.resId = rid;
            n.attrs.add(a);
        }
        a.raw = null;
        a.type = 0x10;
        a.data = value;
        if (a.resId == 0) {
            Long rid = ATTR_ID.get(name);
            if (rid != null) a.resId = rid;
        }
        return a;
    }

    public List<Node> subtree(Node startNode) {
        int idx = nodes.indexOf(startNode);
        List<Node> out = new ArrayList<>();
        if (idx < 0) return out;
        int depth = 0;
        for (int i = idx; i < nodes.size(); i++) {
            Node cur = nodes.get(i);
            out.add(cur);
            if (cur.kind == START) depth++;
            else if (cur.kind == END) {
                depth--;
                if (depth <= 0) break;
            }
        }
        return out;
    }

    public boolean removeElement(Node startNode) {
        int idx = nodes.indexOf(startNode);
        if (idx < 0) return false;
        List<Node> sub = subtree(startNode);
        if (sub.isEmpty()) return false;
        nodes.subList(idx, idx + sub.size()).clear();
        return true;
    }
}
