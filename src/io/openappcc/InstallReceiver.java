package io.openappcc;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.util.Log;
import android.widget.Toast;

/**
 * Handles PackageInstaller session completion and forwards confirmation dialogs to the user.
 */
public class InstallReceiver extends BroadcastReceiver {
    public static final String ACTION = "io.openappcc.INSTALL_RESULT";
    static final String TAG = "openappcc";

    @Override
    public void onReceive(Context ctx, Intent intent) {
        int status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
        String message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);
        String pkg = intent.getStringExtra(PackageInstaller.EXTRA_PACKAGE_NAME);
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            Intent confirm = intent.getParcelableExtra(Intent.EXTRA_INTENT);
            if (confirm != null) {
                confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                try {
                    ctx.startActivity(confirm);
                } catch (Throwable t) {
                    Log.w(TAG, "cannot open installer", t);
                }
            }
            return;
        }
        boolean ok = status == PackageInstaller.STATUS_SUCCESS;
        Log.i(TAG, "install " + (ok ? "ok" : "failed") + ": " + pkg + " status=" + status + " " + message);
        Toast.makeText(ctx, (ok ? "Installed " : "Install failed: ") + (pkg != null ? pkg : "")
                + (ok ? "" : "\n" + status + " " + message), Toast.LENGTH_LONG).show();
    }
}
