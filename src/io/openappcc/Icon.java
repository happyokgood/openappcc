package io.openappcc;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Typeface;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;

import java.io.ByteArrayOutputStream;
import java.util.Locale;

/**
 * Per-clone icon palette tinting, circular index badge, and live preview helper.
 */
public final class Icon {
    public static final int[] PALETTE = {
            0xFF2E7D32, // 1 green
            0xFFC62828, // 2 red
            0xFF1565C0, // 3 blue
            0xFFEF6C00, // 4 orange
            0xFF6A1B9A, // 5 purple
            0xFF00838F, // 6 teal
            0xFFAD1457, // 7 pink
            0xFF4E342E, // 8 brown
            0xFF283593, // 9 indigo
            0xFF9E9D24, // 10 lime
            0xFF00897B, // 11 green-teal
            0xFFD84315, // 12 deep orange
    };

    private Icon() {
    }

    public static int color(int number) {
        if (number <= 0) number = 1;
        if (number <= PALETTE.length) return PALETTE[number - 1];
        int base = PALETTE[(number - 1) % PALETTE.length];
        float[] hsv = new float[3];
        Color.colorToHSV(base, hsv);
        hsv[0] = (hsv[0] + (number * 47)) % 360f;
        hsv[1] = Math.min(1f, hsv[1] + 0.05f);
        return Color.HSVToColor(hsv);
    }

    public static boolean isRaster(String name) {
        String n = name.toLowerCase(Locale.US);
        if (n.endsWith(".9.png")) return false;
        return n.endsWith(".png") || n.endsWith(".webp");
    }

    public static Bitmap render(Bitmap src, int number, int strength, boolean badge, boolean safe) {
        return render(src, number, strength, badge, safe, true, false, 0, null);
    }

    public static Bitmap render(Bitmap src, int number, int strength, boolean badge, boolean safe,
                                boolean tint, boolean flipX, int rotateDeg, String badgeText) {
        return render(src, number, strength, badge, safe, tint, flipX, rotateDeg, badgeText, true);
    }

    public static Bitmap render(Bitmap src, int number, int strength, boolean badge, boolean safe,
                                boolean tint, boolean flipX, int rotateDeg, String badgeText, boolean multiColor) {
        if (src == null) return null;
        int w = Math.max(1, src.getWidth());
        int h = Math.max(1, src.getHeight());
        int color = color(multiColor ? number : 1);
        Bitmap out = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(out);
        Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG | Paint.FILTER_BITMAP_FLAG);

        Matrix m = new Matrix();
        int rot = ((rotateDeg % 360) + 360) % 360;
        if (rot != 0) m.postRotate(rot, w / 2f, h / 2f);
        if (flipX) m.postScale(-1f, 1f, w / 2f, h / 2f);

        canvas.drawBitmap(src, m, paint);

        if (tint && strength > 0) {
            paint.setColorFilter(new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY));
            paint.setAlpha(Math.max(0, Math.min(255, strength)));
            canvas.drawBitmap(src, m, paint);
            paint.setColorFilter(null);
            paint.setAlpha(255);
        }

        if (badge) {
            float min = Math.min(w, h);
            float radius = safe ? min * 0.10f : min * 0.30f;
            float cx = safe ? w / 2f + min * 0.1556f : w - radius * 0.92f;
            float cy = safe ? h / 2f + min * 0.1556f : h - radius * 0.92f;
            paint.setStyle(Paint.Style.FILL);
            paint.setColor(color);
            canvas.drawCircle(cx, cy, radius, paint);
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(Math.max(2f, radius * 0.12f));
            paint.setColor(Color.WHITE);
            canvas.drawCircle(cx, cy, radius, paint);
            paint.setStyle(Paint.Style.FILL);

            String raw = badgeText != null ? badgeText.trim() : "";
            String text = raw.isEmpty() ? String.valueOf(number)
                    : (raw.length() > 4 ? raw.substring(0, 4) : raw);
            paint.setColor(Color.WHITE);
            paint.setTextAlign(Paint.Align.CENTER);
            paint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
            float scale = text.length() <= 1 ? 1.30f : (text.length() == 2 ? 1.02f : (text.length() == 3 ? 0.78f : 0.62f));
            paint.setTextSize(radius * scale);
            Paint.FontMetrics fm = paint.getFontMetrics();
            canvas.drawText(text, cx, cy - (fm.ascent + fm.descent) / 2f, paint);
        }
        return out;
    }

    public static Bitmap paintBitmap(Drawable drawable, int number, int strength, boolean badge) {
        return paintBitmap(drawable, number, strength, badge, true, false, 0, null);
    }

    public static Bitmap paintBitmap(Drawable drawable, int number, int strength, boolean badge,
                                     boolean tint, boolean flipX, int rotateDeg, String badgeText) {
        return paintBitmap(drawable, number, strength, badge, tint, flipX, rotateDeg, badgeText, true);
    }

    public static Bitmap paintBitmap(Drawable drawable, int number, int strength, boolean badge,
                                     boolean tint, boolean flipX, int rotateDeg, String badgeText, boolean multiColor) {
        if (drawable == null) return null;
        Bitmap src;
        if (drawable instanceof BitmapDrawable && ((BitmapDrawable) drawable).getBitmap() != null) {
            src = ((BitmapDrawable) drawable).getBitmap();
        } else {
            int w = drawable.getIntrinsicWidth() > 0 ? drawable.getIntrinsicWidth() : 128;
            int h = drawable.getIntrinsicHeight() > 0 ? drawable.getIntrinsicHeight() : 128;
            src = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888);
            Canvas c = new Canvas(src);
            drawable.setBounds(0, 0, w, h);
            drawable.draw(c);
        }
        return render(src, number, strength, badge, false, tint, flipX, rotateDeg, badgeText, multiColor);
    }

    public static byte[] paint(byte[] image, int number, int strength, boolean badge, boolean safe) {
        return paint(image, number, strength, badge, safe, true, false, 0, null, true);
    }

    public static byte[] paint(byte[] image, int number, int strength, boolean badge, boolean safe,
                               boolean tint, boolean flipX, int rotateDeg, String badgeText) {
        return paint(image, number, strength, badge, safe, tint, flipX, rotateDeg, badgeText, true);
    }

    public static byte[] paint(byte[] image, int number, int strength, boolean badge, boolean safe,
                               boolean tint, boolean flipX, int rotateDeg, String badgeText, boolean multiColor) {
        Bitmap src;
        try {
            src = BitmapFactory.decodeByteArray(image, 0, image.length);
        } catch (Throwable t) {
            return image;
        }
        if (src == null) return image;
        Bitmap out;
        try {
            out = render(src, number, strength, badge, safe, tint, flipX, rotateDeg, badgeText, multiColor);
        } catch (Throwable t) {
            return image;
        }
        if (out == null) return image;
        ByteArrayOutputStream encoded = new ByteArrayOutputStream(image.length);
        try {
            if (!out.compress(Bitmap.CompressFormat.PNG, 100, encoded)) return image;
            return encoded.toByteArray();
        } catch (Throwable t) {
            return image;
        } finally {
            out.recycle();
            src.recycle();
        }
    }
}
