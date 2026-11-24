package io.openappcc.hook;

import android.app.Activity;
import android.app.Application;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Base64;
import android.view.Window;
import android.view.WindowManager;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Locale;
import java.util.Map;

/**
 * Early-init ContentProvider (initOrder=Integer.MAX_VALUE) providing optional pure-Java hooks:
 * original signature spoof, Android ID override, Build.MODEL override, locale override, and FLAG_SECURE control.
 */
public final class BootstrapProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
        Context ctx = getContext();
        if (ctx == null) return true;
        try {
            String clonedPkg = ctx.getPackageName();
            ApplicationInfo ai = ctx.getPackageManager()
                    .getApplicationInfo(clonedPkg, PackageManager.GET_META_DATA);
            Bundle meta = ai != null ? ai.metaData : null;
            if (meta == null) return true;

            String sigB64 = meta.getString("io.openappcc.ORIGINAL_SIG");
            String origPkg = meta.getString("io.openappcc.ORIGINAL");
            if (sigB64 != null && !sigB64.isEmpty()) {
                byte[] sigBytes = Base64.decode(sigB64, Base64.DEFAULT);
                installPmHook(ctx, clonedPkg, origPkg, new Signature[]{new Signature(sigBytes)});
            }

            String fakeAndroidId = meta.getString("io.openappcc.ANDROID_ID");
            if (fakeAndroidId != null && !fakeAndroidId.isEmpty()) {
                installAndroidIdHook(fakeAndroidId);
            }

            String customModel = meta.getString("io.openappcc.BUILD_MODEL");
            if (customModel != null && !customModel.isEmpty()) {
                applyBuildModel(customModel);
            }

            String localeTag = meta.getString("io.openappcc.LOCALE");
            Locale customLocale = (localeTag != null && !localeTag.isEmpty())
                    ? Locale.forLanguageTag(localeTag.replace('_', '-')) : null;
            if (customLocale != null) {
                applyLocale(ctx, customLocale);
            }

            String shotMode = meta.getString("io.openappcc.SCREENSHOTS");
            if (customLocale != null || (shotMode != null && !shotMode.isEmpty())) {
                Context appCtx = ctx.getApplicationContext();
                if (appCtx instanceof Application) {
                    registerLifecycle((Application) appCtx, customLocale, shotMode);
                }
            }
        } catch (Throwable ignored) {
        }
        return true;
    }

    private static void unsealHiddenApis() {
        if (Build.VERSION.SDK_INT < 28) return;
        try {
            Method forName = Class.class.getDeclaredMethod("forName", String.class);
            Method getDeclaredMethod = Class.class.getDeclaredMethod("getDeclaredMethod", String.class, Class[].class);
            Class<?> vmRuntimeClass = (Class<?>) forName.invoke(null, "dalvik.system.VMRuntime");
            Method getRuntime = (Method) getDeclaredMethod.invoke(vmRuntimeClass, "getRuntime", new Class[0]);
            Method setExemptions = (Method) getDeclaredMethod.invoke(vmRuntimeClass, "setHiddenApiExemptions", new Class[]{String[].class});
            Object runtime = getRuntime.invoke(null);
            setExemptions.invoke(runtime, new Object[]{new String[]{"L"}});
        } catch (Throwable ignored) {
        }
    }

    private static void installPmHook(Context ctx, String clonedPkg, String origPkg, Signature[] fakeSigs)
            throws Exception {
        unsealHiddenApis();
        Class<?> atClass = Class.forName("android.app.ActivityThread");
        Method currentAt = atClass.getDeclaredMethod("currentActivityThread");
        currentAt.setAccessible(true);
        Object at = currentAt.invoke(null);

        Field sPmField = atClass.getDeclaredField("sPackageManager");
        sPmField.setAccessible(true);
        Object realPm = sPmField.get(at);
        if (realPm == null) return;

        Class<?> iPmClass = Class.forName("android.content.pm.IPackageManager");
        Object proxy = Proxy.newProxyInstance(
                iPmClass.getClassLoader(),
                new Class<?>[]{iPmClass},
                new PmHandler(realPm, clonedPkg, origPkg, fakeSigs));
        sPmField.set(at, proxy);

        PackageManager pm = ctx.getPackageManager();
        if (pm != null) {
            Field mPmField = pm.getClass().getDeclaredField("mPM");
            mPmField.setAccessible(true);
            mPmField.set(pm, proxy);
        }
    }

    private static final class PmHandler implements InvocationHandler {
        private final Object real;
        private final String clonedPkg;
        private final String origPkg;
        private final Signature[] fakeSigs;

        PmHandler(Object real, String clonedPkg, String origPkg, Signature[] fakeSigs) {
            this.real = real;
            this.clonedPkg = clonedPkg;
            this.origPkg = origPkg;
            this.fakeSigs = fakeSigs;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            String name = method.getName();
            boolean isPkgInfo = "getPackageInfo".equals(name) || "getPackageInfoVersioned".equals(name);
            boolean isAppInfo = "getApplicationInfo".equals(name);
            boolean isInstaller = "getInstallerPackageName".equals(name) || "getInstallSourceInfo".equals(name);
            if ((isPkgInfo || isAppInfo || isInstaller) && args != null && args.length > 0 && args[0] instanceof String) {
                String req = (String) args[0];
                if (origPkg != null && origPkg.equals(req)) {
                    args[0] = clonedPkg;
                }
            }
            Object res;
            try {
                res = method.invoke(real, args);
            } catch (java.lang.reflect.InvocationTargetException ite) {
                Throwable cause = ite.getTargetException();
                throw cause != null ? cause : ite;
            }
            if (isPkgInfo && res instanceof PackageInfo) {
                PackageInfo pi = (PackageInfo) res;
                if (clonedPkg.equals(pi.packageName) || (origPkg != null && origPkg.equals(pi.packageName))) {
                    patchSignatures(pi, fakeSigs);
                }
            } else if ("checkSignatures".equals(name) && args != null && args.length >= 2) {
                Object a0 = args[0], a1 = args[1];
                if (clonedPkg.equals(a0) || clonedPkg.equals(a1)
                        || (origPkg != null && (origPkg.equals(a0) || origPkg.equals(a1)))) {
                    return PackageManager.SIGNATURE_MATCH;
                }
            } else if ("hasSigningCertificate".equals(name) && args != null && args.length >= 2
                    && args[0] instanceof String && args[1] instanceof byte[]) {
                String p0 = (String) args[0];
                if (clonedPkg.equals(p0) || (origPkg != null && origPkg.equals(p0))) {
                    byte[] target = (byte[]) args[1];
                    for (Signature s : fakeSigs) {
                        if (java.util.Arrays.equals(s.toByteArray(), target)) return true;
                        try {
                            byte[] sha = java.security.MessageDigest.getInstance("SHA-256").digest(s.toByteArray());
                            if (java.util.Arrays.equals(sha, target)) return true;
                        } catch (Throwable ignored) {
                        }
                    }
                }
            }
            return res;
        }
    }

    @SuppressWarnings("deprecation")
    private static void patchSignatures(PackageInfo pi, Signature[] fakeSigs) {
        if (pi.signatures != null) {
            pi.signatures = fakeSigs;
        }
        if (Build.VERSION.SDK_INT >= 28 && pi.signingInfo != null) {
            try {
                Field detailsField = pi.signingInfo.getClass().getDeclaredField("mSigningDetails");
                detailsField.setAccessible(true);
                Object details = detailsField.get(pi.signingInfo);
                if (details != null) {
                    for (String fn : new String[]{"signatures", "mSignatures"}) {
                        try {
                            Field f = details.getClass().getDeclaredField(fn);
                            f.setAccessible(true);
                            f.set(details, fakeSigs);
                        } catch (Throwable ignored) {
                        }
                    }
                    for (String fn : new String[]{"pastSigningCertificates", "mPastSigningCertificates"}) {
                        try {
                            Field f = details.getClass().getDeclaredField(fn);
                            f.setAccessible(true);
                            f.set(details, null);
                        } catch (Throwable ignored) {
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void installAndroidIdHook(String fakeId) {
        try {
            Field cacheField = Settings.Secure.class.getDeclaredField("sNameValueCache");
            cacheField.setAccessible(true);
            Object cache = cacheField.get(null);
            if (cache == null) return;

            try {
                Field valuesField = cache.getClass().getDeclaredField("mValues");
                valuesField.setAccessible(true);
                Object map = valuesField.get(cache);
                if (map instanceof Map) {
                    ((Map<String, String>) map).put(Settings.Secure.ANDROID_ID, fakeId);
                }
            } catch (Throwable ignored) {
            }

            try {
                Field holderField = cache.getClass().getDeclaredField("mProviderHolder");
                holderField.setAccessible(true);
                Object holder = holderField.get(cache);
                if (holder == null) return;
                Field cpField = holder.getClass().getDeclaredField("mContentProvider");
                cpField.setAccessible(true);
                Object realCp = cpField.get(holder);
                if (realCp == null) return;
                Class<?> iCpClass = Class.forName("android.content.IContentProvider");
                Object proxy = Proxy.newProxyInstance(
                        iCpClass.getClassLoader(),
                        new Class<?>[]{iCpClass},
                        (p, m, args) -> {
                            Object res;
                            try {
                                res = m.invoke(realCp, args);
                            } catch (java.lang.reflect.InvocationTargetException ite) {
                                Throwable cause = ite.getTargetException();
                                throw cause != null ? cause : ite;
                            }
                            if ("call".equals(m.getName()) && res instanceof Bundle && args != null) {
                                for (Object a : args) {
                                    if (Settings.Secure.ANDROID_ID.equals(a)) {
                                        Bundle b = new Bundle((Bundle) res);
                                        b.putString("value", fakeId);
                                        return b;
                                    }
                                }
                            }
                            return res;
                        });
                cpField.set(holder, proxy);
            } catch (Throwable ignored) {
            }
        } catch (Throwable ignored) {
        }
    }

    private static void applyBuildModel(String spec) {
        try {
            String manufacturer = null;
            String model = spec;
            int colon = spec.indexOf(':');
            if (colon > 0 && colon < spec.length() - 1) {
                manufacturer = spec.substring(0, colon).trim();
                model = spec.substring(colon + 1).trim();
            }
            Field mf = Build.class.getDeclaredField("MODEL");
            mf.setAccessible(true);
            mf.set(null, model);
            if (manufacturer != null && !manufacturer.isEmpty()) {
                Field br = Build.class.getDeclaredField("MANUFACTURER");
                br.setAccessible(true);
                br.set(null, manufacturer);
            }
        } catch (Throwable ignored) {
        }
    }

    @SuppressWarnings("deprecation")
    private static void applyLocale(Context ctx, Locale loc) {
        Locale.setDefault(loc);
        Resources res = ctx.getResources();
        if (res != null) {
            Configuration cfg = new Configuration(res.getConfiguration());
            cfg.setLocale(loc);
            res.updateConfiguration(cfg, res.getDisplayMetrics());
        }
    }

    private static void registerLifecycle(Application app, Locale loc, String shotMode) {
        app.registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks() {
            private void applyWindow(Activity act) {
                if (loc != null) applyLocale(act, loc);
                Window w = act.getWindow();
                if (w == null || shotMode == null) return;
                if ("allow".equals(shotMode)) {
                    w.clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
                } else if ("block".equals(shotMode)) {
                    w.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
                }
            }
            @Override public void onActivityCreated(Activity a, Bundle b) { applyWindow(a); }
            @Override public void onActivityResumed(Activity a) { applyWindow(a); }
            @Override public void onActivityStarted(Activity a) {}
            @Override public void onActivityPaused(Activity a) {}
            @Override public void onActivityStopped(Activity a) {}
            @Override public void onActivitySaveInstanceState(Activity a, Bundle b) {}
            @Override public void onActivityDestroyed(Activity a) {}
        });
    }

    @Override public Cursor query(Uri u, String[] p, String s, String[] a, String o) { return null; }
    @Override public String getType(Uri u) { return null; }
    @Override public Uri insert(Uri u, ContentValues v) { return null; }
    @Override public int delete(Uri u, String s, String[] a) { return 0; }
    @Override public int update(Uri u, ContentValues v, String s, String[] a) { return 0; }
}
