package com.roarnet.app;

public final class RelayAgentService extends android.app.Service {
    private static final String CHANNEL = "roarnet_relay_agent";
    private static final int NOTIFICATION_ID = 7318;
    private volatile String accessToken;
    private volatile String deviceId;
    private volatile Thread checker;

    @Override
    public void onCreate() {
        super.onCreate();
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            android.app.NotificationChannel channel =
                new android.app.NotificationChannel(
                    CHANNEL,
                    "RoarNet Relay Agent",
                    android.app.NotificationManager.IMPORTANCE_LOW
                );
            channel.setDescription("حالة خدمة RoarNet المحلية");
            android.app.NotificationManager manager =
                getSystemService(android.app.NotificationManager.class);
            if (manager != null) manager.createNotificationChannel(channel);
        }
    }

    private android.app.Notification buildNotification() {
        android.app.Notification.Builder builder;
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            builder = new android.app.Notification.Builder(this, CHANNEL);
        } else {
            builder = new android.app.Notification.Builder(this);
        }
        return builder
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("RoarNet Relay Agent")
            .setContentText("وضع التجهيز — لا يتم تمرير الترافيك حالياً")
            .setOngoing(true)
            .build();
    }

    @Override
    public int onStartCommand(android.content.Intent intent, int flags, int startId) {
        if (intent == null) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }

        String token = intent.getStringExtra("access_token");
        String device = intent.getStringExtra("device_id");

        if (token == null || token.length() < 20 ||
            device == null ||
            !device.matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }

        accessToken = token;
        deviceId = device;

        startForeground(NOTIFICATION_ID, buildNotification());

        Thread old = checker;
        if (old != null) old.interrupt();

        checker = new Thread(() -> monitorConsent(startId), "RoarNet-Consent-Monitor");
        checker.start();

        return START_NOT_STICKY;
    }

    private Boolean consentStatus() {
        java.net.HttpURLConnection connection = null;
        try {
            String token = accessToken;
            String device = deviceId;

            if (token == null || device == null) return null;

            String encoded = java.net.URLEncoder.encode(device, "UTF-8");
            java.net.URL url = new java.net.URL(
                "http://127.0.0.1:3180/api/participant/device/consent?deviceId=" + encoded
            );

            connection = (java.net.HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.setRequestProperty("Authorization", "Bearer " + token);
            connection.setRequestProperty("Cache-Control", "no-store");

            int status = connection.getResponseCode();

            if (status == 401 || status == 403) return false;
            if (status != 200) return null;

            try (java.io.InputStream in = connection.getInputStream();
                 java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream()) {

                byte[] buffer = new byte[2048];
                int count;

                while ((count = in.read(buffer)) != -1) {
                    if (out.size() + count > 8192) return null;
                    out.write(buffer, 0, count);
                }

                org.json.JSONObject data =
                    new org.json.JSONObject(out.toString("UTF-8"));

                if (!data.has("accepted") || !data.has("deviceId")) {
                    return null;
                }

                boolean accepted = data.getBoolean("accepted");
                boolean matchingDevice = device.equals(
                    data.getString("deviceId")
                );

                return accepted && matchingDevice;
            }

        } catch (Exception ignored) {
            return null;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private boolean sendGatewayHeartbeat() {
        java.net.HttpURLConnection connection = null;

        String token = accessToken;
        String device = deviceId;

        if (token == null || device == null) return false;

        try {
            java.net.URL url = new java.net.URL(
                "http://127.0.0.1:3182/agent/heartbeat"
            );

            connection = (java.net.HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.setDoOutput(true);
            connection.setRequestProperty(
                "Authorization", "Bearer " + token
            );
            connection.setRequestProperty(
                "Content-Type", "application/json; charset=utf-8"
            );
            connection.setRequestProperty("Cache-Control", "no-store");

            byte[] payload = new org.json.JSONObject()
                .put("deviceId", device)
                .toString()
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);

            connection.setFixedLengthStreamingMode(payload.length);

            try (java.io.OutputStream out = connection.getOutputStream()) {
                out.write(payload);
                out.flush();
            }

            int status = connection.getResponseCode();

            if (status == 200) {
                try (java.io.InputStream in = connection.getInputStream()) {
                    byte[] buffer = new byte[1024];
                    int total = 0;
                    int count;

                    while ((count = in.read(buffer)) != -1) {
                        total += count;
                        if (total > 4096) return false;
                    }
                }
                return true;
            }

            return false;

        } catch (Exception ignored) {
            return false;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private void monitorConsent(int startId) {
        while (!Thread.currentThread().isInterrupted()) {

            Boolean consent = consentStatus();

            if (Boolean.FALSE.equals(consent)) {
                // Gateway authentication will revoke this device's sessions.
                sendGatewayHeartbeat();
                stopSelf(startId);
                return;
            }

            if (consent == null) {
                // Temporary server/network failure: retry without treating
                // it as an explicit consent revocation.
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                continue;
            }

            sendGatewayHeartbeat();

            try {
                Thread.sleep(30000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    @Override
    public void onDestroy() {
        Thread current = checker;
        if (current != null) current.interrupt();
        accessToken = null;
        deviceId = null;
        stopForeground(true);
        super.onDestroy();
    }

    @Override
    public android.os.IBinder onBind(android.content.Intent intent) {
        return null;
    }
}
