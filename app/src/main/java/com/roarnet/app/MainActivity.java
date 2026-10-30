package com.roarnet.app;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.JavascriptInterface;
import android.app.AlertDialog;
import java.net.HttpURLConnection;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import android.webkit.WebSettings;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.graphics.Color;
import android.view.Gravity;
import android.content.SharedPreferences;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.net.URL;
import java.security.SecureRandom;
import org.json.JSONObject;

public class MainActivity extends Activity {
    private static final String LOCAL_URL = "http://127.0.0.1:3180/";
    private WebView web;

    private native int startNode(
        String scriptPath,
        String databasePath,
        String adminToken
    );

    static {
        System.loadLibrary("node");
        System.loadLibrary("native-lib");
    }

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        showMessage("🦁 RoarNet", "جاري تشغيل خادم RoarNet المحلي...");

        new Thread(() -> {
            try {
                File root = new File(getFilesDir(), "roarnet-server");
                if (!root.exists() && !root.mkdirs()) {
                    throw new IOException("تعذر إنشاء مجلد الخادم");
                }

                File script = new File(root, "server.mjs");
                copyAsset("roarnet-server/server.mjs", script);
                copyAssetDirectory(
                    "roarnet-server/public",
                    new File(root, "public")
                );

                File database = new File(root, "roarnet.sqlite");
                SharedPreferences prefs =
                    getSharedPreferences("roarnet_local", MODE_PRIVATE);

                String token = prefs.getString("admin_token", null);
                if (token == null || token.length() < 32) {
                    byte[] bytes = new byte[32];
                    new SecureRandom().nextBytes(bytes);
                    StringBuilder hex = new StringBuilder();
                    for (byte b : bytes) {
                        hex.append(String.format("%02x", b & 0xff));
                    }
                    token = hex.toString();
                    prefs.edit().putString("admin_token", token).apply();
                }

                final String adminToken = token;
                new Thread(() ->
                    startNode(script.getAbsolutePath(),
                              database.getAbsolutePath(),
                              adminToken)
                , "RoarNet-Node").start();

                boolean ready = false;
                for (int i = 0; i < 60; i++) {
                    try {
                        HttpURLConnection c = (HttpURLConnection)
                            new URL(LOCAL_URL).openConnection();
                        c.setConnectTimeout(1000);
                        c.setReadTimeout(1000);
                        c.setRequestMethod("GET");
                        int code = c.getResponseCode();
                        c.disconnect();
                        if (code > 0) {
                            ready = true;
                            break;
                        }
                    } catch (Exception ignored) {
                        Thread.sleep(500);
                    }
                }

                if (!ready) {
                    runOnUiThread(() -> showMessage(
                        "RoarNet",
                        "لم يبدأ الخادم المحلي. راجع سجل تشغيل التطبيق."
                    ));
                    return;
                }

                runOnUiThread(this::openLocalWebView);
            } catch (Exception e) {
                runOnUiThread(() -> showMessage(
                    "RoarNet",
                    "تعذر تجهيز الخادم: " + e.getMessage()
                ));
            }
        }, "RoarNet-Setup").start();
    }

    private void copyAsset(String assetName, File destination)
            throws IOException {
        try (InputStream in = getAssets().open(assetName);
             FileOutputStream out = new FileOutputStream(destination)) {
            byte[] buffer = new byte[16384];
            int count;
            while ((count = in.read(buffer)) != -1) {
                out.write(buffer, 0, count);
            }
        }
    }


    private void copyAssetDirectory(String assetDir, File destination)
            throws IOException {
        String[] entries = getAssets().list(assetDir);
        if (entries == null || entries.length == 0) {
            copyAsset(assetDir, destination);
            return;
        }

        if (!destination.exists() && !destination.mkdirs()) {
            throw new IOException("تعذر إنشاء المجلد: " + destination);
        }

        for (String entry : entries) {
            copyAssetDirectory(
                assetDir + "/" + entry,
                new File(destination, entry)
            );
        }
    }


    // ROARNET_ANDROID_ADMIN_BRIDGE_V1
    private final class RoarNetAdminBridge {
        @JavascriptInterface
        public String generateParticipantLinkCode(String nodeId) {
            if (nodeId == null ||
                !nodeId.matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
                return "{\"error\":\"معرّف العقدة غير صالح.\"}";
            }

            CountDownLatch latch = new CountDownLatch(1);
            AtomicBoolean approved = new AtomicBoolean(false);

            runOnUiThread(() -> {
                new AlertDialog.Builder(MainActivity.this)
                    .setTitle("تأكيد إصدار رمز ربط")
                    .setMessage("هل توافق على إصدار رمز ربط مؤقت لهذه العقدة؟")
                    .setNegativeButton("إلغاء", (dialog, which) -> {
                        approved.set(false);
                        latch.countDown();
                    })
                    .setPositiveButton("إصدار الرمز", (dialog, which) -> {
                        approved.set(true);
                        latch.countDown();
                    })
                    .setOnCancelListener(dialog -> latch.countDown())
                    .show();
            });

            try {
                if (!latch.await(60, TimeUnit.SECONDS) || !approved.get()) {
                    return "{\"error\":\"ألغيت العملية أو انتهت مهلة التأكيد.\"}";
                }

                SharedPreferences prefs =
                    getSharedPreferences("roarnet_local", MODE_PRIVATE);
                String adminToken = prefs.getString("admin_token", null);

                if (adminToken == null || adminToken.length() < 32) {
                    return "{\"error\":\"رمز المدير المحلي غير متاح.\"}";
                }

                URL endpoint = new URL(
                    LOCAL_URL + "api/admin/nodes/" + nodeId + "/link-code"
                );
                HttpURLConnection connection =
                    (HttpURLConnection) endpoint.openConnection();

                connection.setRequestMethod("POST");
                connection.setConnectTimeout(8000);
                connection.setReadTimeout(12000);
                connection.setDoOutput(true);
                connection.setRequestProperty(
                    "Authorization", "Bearer " + adminToken
                );
                connection.setRequestProperty(
                    "Content-Type", "application/json"
                );

                try (OutputStream out = connection.getOutputStream()) {
                    out.write("{}".getBytes("UTF-8"));
                }

                int status = connection.getResponseCode();
                InputStream input = status >= 400
                    ? connection.getErrorStream()
                    : connection.getInputStream();

                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                if (input != null) {
                    try (InputStream in = input) {
                        byte[] chunk = new byte[4096];
                        int count;
                        while ((count = in.read(chunk)) != -1) {
                            buffer.write(chunk, 0, count);
                        }
                    }
                }

                connection.disconnect();
                return new String(buffer.toByteArray(), "UTF-8");

            } catch (Exception e) {
                return "{\"error\":\"تعذر الاتصال بخادم RoarNet المحلي.\"}";
            }
        }

        // ROARNET_ADMIN_FINANCE_BRIDGE_V1
        private String adminRequest(String path, String method, String payload) {
            HttpURLConnection connection = null;
            try {
                SharedPreferences prefs =
                    getSharedPreferences("roarnet_local", MODE_PRIVATE);
                String token = prefs.getString("admin_token", null);
                if (token == null || token.length() < 32) {
                    return "{\"error\":\"رمز المدير المحلي غير متاح.\"}";
                }

                if (!path.equals("api/admin/summary") &&
                    !path.equals("api/admin/provider-revenue-batches")) {
                    return "{\"error\":\"مسار إداري غير مسموح.\"}";
                }

                URL endpoint = new URL(LOCAL_URL + path);
                connection = (HttpURLConnection) endpoint.openConnection();
                connection.setRequestMethod(method);
                connection.setConnectTimeout(8000);
                connection.setReadTimeout(12000);
                connection.setRequestProperty("Authorization", "Bearer " + token);
                connection.setRequestProperty("Accept", "application/json");

                if ("POST".equals(method)) {
                    connection.setDoOutput(true);
                    connection.setRequestProperty("Content-Type", "application/json");
                    try (OutputStream out = connection.getOutputStream()) {
                        out.write(payload.getBytes("UTF-8"));
                    }
                }

                int status = connection.getResponseCode();
                InputStream input = status >= 400
                    ? connection.getErrorStream()
                    : connection.getInputStream();

                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                if (input != null) {
                    try (InputStream in = input) {
                        byte[] chunk = new byte[4096];
                        int count;
                        while ((count = in.read(chunk)) != -1) buffer.write(chunk, 0, count);
                    }
                }
                return new String(buffer.toByteArray(), "UTF-8");
            } catch (Exception e) {
                return "{\"error\":\"تعذر الاتصال بخادم RoarNet المحلي.\"}";
            } finally {
                if (connection != null) connection.disconnect();
            }
        }

        @JavascriptInterface
        public String getAdminSummary() {
            return adminRequest("api/admin/summary", "GET", "");
        }

        @JavascriptInterface
        public String getProviderRevenueBatches() {
            return adminRequest("api/admin/provider-revenue-batches", "GET", "");
        }

        @JavascriptInterface
        public String createProviderRevenueBatch(String json) {
            if (json == null || json.length() > 4096) {
                return "{\"error\":\"بيانات التقرير غير صالحة.\"}";
            }

            final JSONObject data;
            try {
                data = new JSONObject(json);
                String reference = data.optString("reference", "");
                String month = data.optString("month", "");
                long bytes = data.getLong("providerBytes");
                double netUsd = data.getDouble("netUsd");

                if (!reference.matches("[A-Za-z0-9_.:-]{8,120}") ||
                    !month.matches("\\d{4}-(0[1-9]|1[0-2])") ||
                    bytes <= 0 || !Double.isFinite(netUsd) ||
                    netUsd <= 0 || netUsd > 1000000) {
                    return "{\"error\":\"تحقق من مرجع التقرير والشهر والترافيك والإيراد.\"}";
                }
            } catch (Exception e) {
                return "{\"error\":\"صيغة التقرير غير صحيحة.\"}";
            }

            CountDownLatch latch = new CountDownLatch(1);
            AtomicBoolean approved = new AtomicBoolean(false);

            runOnUiThread(() -> new AlertDialog.Builder(MainActivity.this)
                .setTitle("تأكيد تسجيل إيراد المزود")
                .setMessage("سيُسجّل التقرير ويُوزّع صافي الإيراد وفق 80% للمالك و15% للمشاركين و5% للاحتياطي. هل تؤكد؟")
                .setNegativeButton("إلغاء", (dialog, which) -> latch.countDown())
                .setPositiveButton("تأكيد التسجيل", (dialog, which) -> {
                    approved.set(true);
                    latch.countDown();
                })
                .setOnCancelListener(dialog -> latch.countDown())
                .show());

            try {
                if (!latch.await(60, TimeUnit.SECONDS) || !approved.get()) {
                    return "{\"error\":\"ألغيت العملية أو انتهت مهلة التأكيد.\"}";
                }
                return adminRequest(
                    "api/admin/provider-revenue-batches",
                    "POST",
                    data.toString()
                );
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return "{\"error\":\"تم إيقاف العملية.\"}";
            }
        }
        // /ROARNET_ADMIN_FINANCE_BRIDGE_V1
    }
    // /ROARNET_ANDROID_ADMIN_BRIDGE_V1

    private void openLocalWebView() {
        web = new WebView(this);
        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        // ROARNET_WEBVIEW_LOCAL_ONLY_V1
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setJavaScriptCanOpenWindowsAutomatically(false);
        settings.setSupportMultipleWindows(false);

        web.setWebViewClient(new WebViewClient() {
            private boolean isTrustedLocalUrl(String value) {
                if (value == null) return false;
                try {
                    URL parsed = new URL(value);
                    return "http".equalsIgnoreCase(parsed.getProtocol())
                        && "127.0.0.1".equals(parsed.getHost())
                        && parsed.getPort() == 3180;
                } catch (Exception e) {
                    return false;
                }
            }

            @Override
            public boolean shouldOverrideUrlLoading(
                    WebView view, String url) {
                return !isTrustedLocalUrl(url);
            }

            @Override
            public boolean shouldOverrideUrlLoading(
                    WebView view,
                    android.webkit.WebResourceRequest request) {
                return !isTrustedLocalUrl(
                    request.getUrl().toString()
                );
            }
        });

        web.addJavascriptInterface(new RoarNetAdminBridge(), "RoarNetAdmin");
        web.setBackgroundColor(Color.rgb(16, 24, 39));
        // /ROARNET_WEBVIEW_LOCAL_ONLY_V1
        setContentView(web);
        web.loadUrl(LOCAL_URL);
    }

    private void showMessage(String title, String message) {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setGravity(Gravity.CENTER);
        layout.setPadding(32, 32, 32, 32);
        layout.setBackgroundColor(Color.rgb(16, 24, 39));

        TextView heading = new TextView(this);
        heading.setText(title);
        heading.setTextSize(28);
        heading.setTextColor(Color.rgb(117, 224, 193));
        heading.setGravity(Gravity.CENTER);

        TextView body = new TextView(this);
        body.setText(message);
        body.setTextSize(16);
        body.setTextColor(Color.WHITE);
        body.setGravity(Gravity.CENTER);
        body.setPadding(0, 24, 0, 0);

        layout.addView(heading);
        layout.addView(body);
        setContentView(layout);
    }

    @Override
    public void onBackPressed() {
        if (web != null && web.canGoBack()) {
            web.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
