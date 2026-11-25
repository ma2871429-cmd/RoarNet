package com.roarnet.app;

public final class RelayAgentService extends android.app.Service {
    public static volatile boolean serviceRunning = false;
    public static volatile boolean sharingReady = false;


    private static final String CHANNEL = "roarnet_relay_agent";
    private static final int NOTIFICATION_ID = 7318;
    private volatile String accessToken;
    private volatile String deviceId;
    private volatile Thread checker;

    private volatile Thread relayWorker;
    private volatile boolean relayEnabled = false;

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
        ParticipantTcpTunnel.initializeTrafficStorage(getApplicationContext());
        if (intent == null) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }

        // Fail closed: never start Relay without local sharing consent.
        if (!hasLocalSharingConsent()) {
            relayEnabled = false;
            sharingReady = false;
            ParticipantTcpTunnel.closeAll();
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

        serviceRunning = true;
        startForeground(NOTIFICATION_ID, buildNotification());

        Thread old = checker;
        if (old != null) old.interrupt();

        checker = new Thread(() -> monitorConsent(startId), "RoarNet-Consent-Monitor");
        checker.start();

        Thread oldRelay = relayWorker;
        if (oldRelay != null) oldRelay.interrupt();

        relayWorker = new Thread(
            this::runRelayAgent,
            "RoarNet-Device-TCP-Agent"
        );
        relayWorker.start();


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


    // ROARNET_DEVICE_TCP_AGENT_V1

    private org.json.JSONObject gatewayPost(
        String route,
        org.json.JSONObject payload
    ) throws Exception {
        java.net.HttpURLConnection connection = null;
        try {
            connection = (java.net.HttpURLConnection)
                new java.net.URL("http://127.0.0.1:3182" + route)
                    .openConnection();

            connection.setRequestMethod("POST");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(10000);
            connection.setDoOutput(true);
            connection.setRequestProperty(
                "Authorization", "Bearer " + accessToken
            );
            connection.setRequestProperty(
                "Content-Type", "application/json; charset=utf-8"
            );
            connection.setRequestProperty("Cache-Control", "no-store");

            byte[] body = payload.toString().getBytes(
                java.nio.charset.StandardCharsets.UTF_8
            );
            connection.setFixedLengthStreamingMode(body.length);

            try (java.io.OutputStream out = connection.getOutputStream()) {
                out.write(body);
                out.flush();
            }

            int status = connection.getResponseCode();
            java.io.InputStream stream = status >= 200 && status < 300
                ? connection.getInputStream()
                : connection.getErrorStream();

            if (stream == null) {
                throw new java.io.IOException("GATEWAY_HTTP_" + status);
            }

            byte[] response;
            try (java.io.InputStream in = stream;
                 java.io.ByteArrayOutputStream out =
                     new java.io.ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = in.read(buffer)) != -1) {
                    if (out.size() + count > 128 * 1024) {
                        throw new java.io.IOException(
                            "GATEWAY_RESPONSE_TOO_LARGE"
                        );
                    }
                    out.write(buffer, 0, count);
                }
                response = out.toByteArray();
            }

            if (status < 200 || status >= 300) {
                throw new java.io.IOException("GATEWAY_HTTP_" + status);
            }

            org.json.JSONObject result = new org.json.JSONObject(
                new String(response, java.nio.charset.StandardCharsets.UTF_8)
            );

            if (!result.optBoolean("success", false)) {
                throw new java.io.IOException(
                    result.optString("error", "GATEWAY_OPERATION_FAILED")
                );
            }

            return result;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private org.json.JSONObject agentPayload(String sessionId)
        throws Exception {
        return new org.json.JSONObject()
            .put("deviceId", deviceId)
            .put("sessionId", sessionId);
    }

    private void runRelayAgent() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                if (!hasLocalSharingConsent()) {
                    relayEnabled = false;
                    sharingReady = false;
                    ParticipantTcpTunnel.closeAll();
                    return;
                }

                if (!relayEnabled) {
                    Thread.sleep(1000);
                    continue;
                }

                org.json.JSONObject next = gatewayPost(
                    "/agent/next",
                    new org.json.JSONObject().put("deviceId", deviceId)
                );

                org.json.JSONObject assignment =
                    next.optJSONObject("assignment");

                if (assignment == null) {
                    Thread.sleep(3000);
                    continue;
                }

                runDeviceSession(assignment);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception ignored) {
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    private void runDeviceSession(
        org.json.JSONObject assignment
    ) throws Exception {
        String sessionId = assignment.optString("sessionId", "");
        String providerId = assignment.optString("providerId", "unknown");
        String host = assignment.optString("destinationHost", "");
        int port = assignment.optInt("destinationPort", -1);

        if (!sessionId.matches("[A-Za-z0-9_-]{8,100}") ||
            host.isEmpty() || (port != 80 && port != 443)) {
            throw new java.io.IOException("DEVICE_ASSIGNMENT_REJECTED");
        }

        boolean gatewayOpened = false;

        try {
            org.json.JSONObject opened = gatewayPost(
                "/agent/session/open",
                agentPayload(sessionId)
            );
            gatewayOpened = true;

            if (!opened.optBoolean("requiresDeviceTcp", false)) {
                throw new java.io.IOException("DEVICE_TCP_REQUIRED");
            }

            if (!ParticipantTcpTunnel.open(sessionId, providerId, host, port)) {
                throw new java.io.IOException("DEVICE_TCP_OPEN_FAILED");
            }

            gatewayPost(
                "/agent/session/activate",
                agentPayload(sessionId).put("connected", true)
            );

            while (relayEnabled &&
                   !Thread.currentThread().isInterrupted() &&
                   ParticipantTcpTunnel.isActive(sessionId)) {

                // Buyer -> participant TCP socket
                org.json.JSONObject incoming = gatewayPost(
                    "/agent/session/receive",
                    agentPayload(sessionId)
                );

                org.json.JSONArray items = incoming.optJSONArray("items");
                if (items != null) {
                    for (int i = 0; i < items.length(); i++) {
                        org.json.JSONObject item = items.optJSONObject(i);
                        if (item == null) continue;

                        String encoded = item.optString("data", "");
                        if (encoded.isEmpty()) continue;

                        byte[] bytes = android.util.Base64.decode(
                            encoded, android.util.Base64.DEFAULT
                        );
                        ParticipantTcpTunnel.write(sessionId, bytes);
                    }
                }

                // Participant TCP socket -> buyer
                java.util.List<String> outgoing =
                    ParticipantTcpTunnel.receive(sessionId, 16);

                for (String chunk : outgoing) {
                    gatewayPost(
                        "/agent/session/send",
                        agentPayload(sessionId).put("payload", chunk)
                    );
                }

                Thread.sleep(120);
            }

        } finally {
            ParticipantTcpTunnel.close(sessionId);

            long[] finalTraffic =
                ParticipantTcpTunnel.takeFinalTrafficBytes(sessionId);

            if (gatewayOpened) {
                try {
                    org.json.JSONObject closePayload =
                        agentPayload(sessionId);

                    if (finalTraffic != null && finalTraffic.length >= 3) {
                        org.json.JSONObject report =
                            new org.json.JSONObject();

                        report.put("reportVersion", 1);
                        report.put("sessionId", sessionId);
                        report.put(
                            "deviceId",
                            closePayload.optString("deviceId", "")
                        );
                        report.put("bytesSent", finalTraffic[0]);
                        report.put("bytesReceived", finalTraffic[1]);
                        report.put("totalBytes", finalTraffic[2]);

                        byte[] reportBytes = report.toString().getBytes(
                            java.nio.charset.StandardCharsets.UTF_8
                        );

                        byte[] digest = java.security.MessageDigest
                            .getInstance("SHA-256")
                            .digest(reportBytes);

                        char[] hex = "0123456789abcdef".toCharArray();
                        StringBuilder reportHash = new StringBuilder(64);

                        for (byte value : digest) {
                            int v = value & 0xff;
                            reportHash.append(hex[v >>> 4]);
                            reportHash.append(hex[v & 0x0f]);
                        }

                        closePayload.put("agentReport", report);
                        closePayload.put(
                            "agentReportHash",
                            reportHash.toString()
                        );
                    }

                    gatewayPost(
                        "/agent/session/close",
                        closePayload
                    );
                } catch (Exception ignored) {}
            }
        }
    }

    private boolean hasLocalSharingConsent() {
        return getSharedPreferences("roarnet_consent", MODE_PRIVATE)
            .getBoolean("accepted", false);
    }

    private void monitorConsent(int startId) {
        while (!Thread.currentThread().isInterrupted()) {

            if (!hasLocalSharingConsent()) {
                relayEnabled = false;
                sharingReady = false;
                ParticipantTcpTunnel.closeAll();
                stopSelf(startId);
                return;
            }

            Boolean consent = consentStatus();

            if (Boolean.FALSE.equals(consent)) {
                relayEnabled = false;
                sharingReady = false;
                ParticipantTcpTunnel.closeAll();
                sendGatewayHeartbeat();
                stopSelf(startId);
                return;
            }

            if (consent == null) {
                relayEnabled = false;
                sharingReady = false;
                ParticipantTcpTunnel.closeAll();
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

            relayEnabled = true;

            sharingReady = true;
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
        serviceRunning = false;
        Thread current = checker;
        if (current != null) current.interrupt();
        relayEnabled = false;
        sharingReady = false;
        Thread relay = relayWorker;
        if (relay != null) relay.interrupt();
        ParticipantTcpTunnel.closeAll();
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
