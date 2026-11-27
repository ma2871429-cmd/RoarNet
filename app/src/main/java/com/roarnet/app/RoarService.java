package com.roarnet.app;
import android.app.Service;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.os.IBinder;
import androidx.core.app.NotificationCompat;

public class RoarService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel("roar_channel", "RoarNet", NotificationManager.IMPORTANCE_LOW);
            nm.createNotificationChannel(ch);
        }
        Notification n = new NotificationCompat.Builder(this, "roar_channel")
            .setContentTitle("RoarNet شغال")
            .setContentText("خدمة RoarNet تعمل في الخلفية.")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .build();
        startForeground(1, n);
        return START_STICKY;
    }
    @Override public IBinder onBind(Intent intent) { return null; }
}
