package com.roarnet.app;

import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;
import android.net.Uri;
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
import com.google.android.gms.ads.MobileAds;
import com.google.android.gms.ads.AdRequest;
import com.google.android.gms.ads.LoadAdError;
import com.google.android.gms.ads.rewarded.RewardedAd;
import com.google.android.gms.ads.rewarded.RewardedAdLoadCallback;

public class MainActivity extends Activity {
    private static final String LOCAL_URL = "http://127.0.0.1:3180/";
    private WebView web;
    private RewardedAd rewardedAd;
    private static final String ADMOB_AD_UNIT = "ca-app-pub-9782709035691744/3906285447";
    private String pendingAuthCode;

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
        MobileAds.initialize(this, status -> {});
        loadRewardedAd();
        captureAuthCode(getIntent());
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
                copyAssetDirectory(
                    "roarnet-server/relay",
                    new File(root, "relay")
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
                            HttpURLConnection gateway =
                                (HttpURLConnection)
                                new URL("http://127.0.0.1:3182/health")
                                    .openConnection();

                            gateway.setConnectTimeout(1500);
                            gateway.setReadTimeout(1500);
                            gateway.setRequestMethod("GET");

                            int gatewayCode = gateway.getResponseCode();
                            gateway.disconnect();

                            if (gatewayCode == 200) {
                                ready = true;
                                break;
                            }
                        }
                    } catch (Exception ignored) {
                        Thread.sleep(500);
                    }
                }

                if (!ready) {
                    File nodeLog = new File(database.getAbsolutePath() + ".node.log");
                    String details = "لم يبدأ الخادم المحلي.";
                    if (nodeLog.isFile()) {
                        try (java.io.RandomAccessFile log =
                                 new java.io.RandomAccessFile(nodeLog, "r")) {
                            long length = log.length();
                            long start = Math.max(0, length - 12000);
                            log.seek(start);
                            byte[] bytes = new byte[(int)(length - start)];
                            log.readFully(bytes);
                            details += "\n\nسجل Node:\n" +
                                new String(bytes, "UTF-8");
                        } catch (Exception ignored) {
                            details += "\nتعذرت قراءة سجل Node.";
                        }
                    }
                    final String errorDetails = details;
                    runOnUiThread(() -> showMessage("RoarNet - خطأ التشغيل", errorDetails));
                    return;
                }

                runOnUiThread(this::openLocalWebView);
            } catch (Exception e) {
                runOnUiThread(() -> new AlertDialog.Builder(this)
                    .setTitle("تعذر تشغيل RoarNet")
                    .setMessage("تعذر الاتصال أو تجهيز الخادم: " +
                        e.getMessage())
                    .setCancelable(false)
                    .setPositiveButton("إعادة المحاولة",
                        (dialog, which) -> recreate())
                    .setNegativeButton("إغلاق التطبيق",
                        (dialog, which) -> finish())
                    .show());
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


    // ROARNET_ANDROID_RELAY_BRIDGE_V1
    private final class RoarNetRelayBridge {
        @JavascriptInterface
        public String start(String accessToken, String deviceId) {
            if (accessToken == null || accessToken.length() < 20 ||
                deviceId == null ||
                !deviceId.matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
                return "بيانات تشغيل Relay غير صالحة.";
            }
            try {
                Intent intent = new Intent(MainActivity.this, RelayAgentService.class);
                intent.putExtra("access_token", accessToken);
                intent.putExtra("device_id", deviceId);
                if (android.os.Build.VERSION.SDK_INT >= 26) {
                    startForegroundService(intent);
                } else {
                    startService(intent);
                }
                return "تم إرسال طلب تشغيل الخدمة. ستتوقف إذا تعذر التحقق من الموافقة.";
            } catch (Exception e) {
                return "تعذر تشغيل خدمة Relay.";
            }
        }

        @JavascriptInterface
        public void stop() {
            try {
                stopService(new Intent(MainActivity.this, RelayAgentService.class));
            } catch (Exception ignored) { }
        }
    }

    // ROARNET_PROXIES_SDK_START_V1
private final class RoarNetProxiesSDKBridge {

    @JavascriptInterface
    public String start() {
        try {
            String key = BuildConfig.PROXIES_FARMER_API_KEY;
            if (key == null || key.trim().isEmpty()) {
                return "مفتاح Proxies.sx غير مضبوط في إعدادات البناء.";
            }

            Class<?> sdkClass = Class.forName("sx.proxies.peer.ProxiesPeerSDK");

            Object sdk = null;
            try {
                sdk = sdkClass.getMethod("getInstance").invoke(null);
            } catch (Throwable ignored) {
                sdk = null;
            }

            if (sdk == null) {
                java.lang.reflect.Method init = null;
                for (java.lang.reflect.Method method : sdkClass.getDeclaredMethods()) {
                    if (method.getName().equals("init")
                            && java.lang.reflect.Modifier.isStatic(method.getModifiers())
                            && method.getParameterTypes().length == 3) {
                        init = method;
                        break;
                    }
                }

                if (init == null) {
                    return "تعذر العثور على دالة تهيئة SDK.";
                }

                Class<?> configClass = init.getParameterTypes()[2];
                java.lang.reflect.Constructor<?> configConstructor = null;

                for (java.lang.reflect.Constructor<?> constructor
                        : configClass.getDeclaredConstructors()) {
                    Class<?>[] types = constructor.getParameterTypes();
                    if (types.length == 5
                            && types[0] == String.class
                            && types[1] == String.class
                            && types[2] == String.class) {
                        configConstructor = constructor;
                        break;
                    }
                }

                if (configConstructor == null) {
                    return "تعذر العثور على إعدادات SDK المتوافقة.";
                }

                configConstructor.setAccessible(true);
                Object config = configConstructor.newInstance(
                        "https://api.proxies.sx/v1",
                        null, null, null, null
                );

                init.setAccessible(true);
                init.invoke(null, MainActivity.this.getApplicationContext(), key, config);
                sdk = sdkClass.getMethod("getInstance").invoke(null);
            }

            if (sdk == null) {
                return "لم يتم إنشاء جلسة SDK.";
            }

            sdkClass.getMethod("start").invoke(sdk);
            return "تم إرسال طلب تشغيل Proxies.sx SDK.";
        } catch (Throwable error) {
            Throwable cause = error;
            while (cause.getCause() != null) cause = cause.getCause();
            String message = cause.getMessage();
            return "تعذر تشغيل SDK: " +
                    (message == null ? cause.getClass().getSimpleName() : message);
        }
    }

    @JavascriptInterface
    public String stop() {
        try {
            sx.proxies.peer.ProxiesPeerSDK.getInstance().stop();
            return "تم إرسال طلب إيقاف SDK.";
        } catch (Exception e) {
            return "SDK غير مهيأ أو متوقف.";
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
                    !path.equals("api/admin/provider-revenue-batches") &&
                    !path.equals("api/admin/withdrawals") &&
                    !path.matches("api/admin/withdrawals/[0-9]+/status")) {
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


        // ROARNET_ADMIN_WITHDRAWAL_BRIDGE_V1
        @JavascriptInterface
        public String getAdminWithdrawals() {
            return adminRequest("api/admin/withdrawals", "GET", "");
        }

        @JavascriptInterface
        public String updateAdminWithdrawal(String id, String json) {
            if (id == null || !id.matches("[0-9]{1,12}") ||
                json == null || json.length() > 4096) {
                return "{\"error\":\"بيانات طلب السحب غير صالحة.\"}";
            }

            try {
                new JSONObject(json);
            } catch (Exception e) {
                return "{\"error\":\"صيغة بيانات السحب غير صحيحة.\"}";
            }

            return adminRequest(
                "api/admin/withdrawals/" + id + "/status",
                "POST",
                json
            );
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

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        captureAuthCode(intent);
    }

    private void captureAuthCode(Intent intent) {
        if (intent == null || intent.getData() == null) return;

        Uri uri = intent.getData();
        if (!"roarnet".equals(uri.getScheme())
                || !"auth-callback".equals(uri.getHost())) return;

        String code = uri.getQueryParameter("code");
        if (code == null || code.isEmpty()) return;

        pendingAuthCode = code;
        deliverPendingAuthCode();
    }

    private void deliverPendingAuthCode() {
        if (web == null || pendingAuthCode == null) return;

        final String code = pendingAuthCode;
        pendingAuthCode = null;

        web.post(() -> web.evaluateJavascript(
            "window.RoarNetHandleAuthCode && window.RoarNetHandleAuthCode("
                + JSONObject.quote(code) + ");",
            null
        ));
    }

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
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                deliverPendingAuthCode();
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
        web.addJavascriptInterface(new RoarNetRelayBridge(), "RoarNetRelay");
        web.addJavascriptInterface(new RoarNetProxiesSDKBridge(), "RoarNetProxiesSDK");
        web.addJavascriptInterface(new AndroidAdBridge(), "AndroidAd");
        web.setBackgroundColor(Color.rgb(16, 24, 39));
        // /ROARNET_WEBVIEW_LOCAL_ONLY_V1
        setContentView(web);
        web.loadUrl(LOCAL_URL);
    }


    // ROARNET_MANDATORY_UPDATE_V1
    private JSONObject fetchUpdatePolicy() throws Exception {
        URL url = new URL(
            "https://raw.githubusercontent.com/ma2871429-cmd/RoarNet/standalone-apk-integration/update-policy.json"
        );

        HttpURLConnection connection =
            (HttpURLConnection) url.openConnection();

        connection.setRequestMethod("GET");
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(10000);
        connection.setRequestProperty("Accept", "application/json");

        try {
            int status = connection.getResponseCode();
            if (status != 200) {
                throw new IOException("HTTP " + status);
            }

            try (InputStream in = connection.getInputStream();
                 ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = in.read(buffer)) != -1) {
                    if (out.size() + count > 16384) {
                        throw new IOException("Update policy too large");
                    }
                    out.write(buffer, 0, count);
                }
                return new JSONObject(out.toString("UTF-8"));
            }
        } finally {
            connection.disconnect();
        }
    }

    private void showMandatoryUpdate(String version, String downloadUrl) {
        new AlertDialog.Builder(this)
            .setTitle("تحديث RoarNet مطلوب")
            .setMessage("يتوفر إصدار أحدث: " + version +
                "\nيجب تحديث التطبيق قبل متابعة الاستخدام.")
            .setCancelable(false)
            .setPositiveButton("تنزيل التحديث", (dialog, which) -> {
                try {
                    if (!isAllowedUpdateUrl(downloadUrl)) {
                        showMessage("RoarNet", "رابط التحديث غير صالح.");
                        return;
                    }

                    Intent intent = new Intent(
                        Intent.ACTION_VIEW, Uri.parse(downloadUrl)
                    );
                    startActivity(intent);
                } catch (Exception e) {
                    showMessage("RoarNet", "تعذر فتح رابط التنزيل.");
                }
            })
            .setNegativeButton("إغلاق التطبيق", (dialog, which) -> finish())
            .show();
    }
    private boolean isAllowedUpdateUrl(String value) {
        try {
            Uri uri = Uri.parse(value);
            String host = uri.getHost();
            String path = uri.getPath();

            return "https".equalsIgnoreCase(uri.getScheme())
                && "github.com".equalsIgnoreCase(host)
                && path != null
                && path.startsWith("/ma2871429-cmd/RoarNet/releases/");
        } catch (Exception e) {
            return false;
        }
    }

    // /ROARNET_MANDATORY_UPDATE_V1

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

    // ===== AdMob Rewarded - RoarNet =====
    private void loadRewardedAd() {
        AdRequest adRequest = new AdRequest.Builder().build();
        RewardedAd.load(this, ADMOB_AD_UNIT, adRequest, new RewardedAdLoadCallback() {
            @Override public void onAdFailedToLoad(LoadAdError err) { rewardedAd = null; }
            @Override public void onAdLoaded(RewardedAd ad) { rewardedAd = ad; }
        });
    }
    private void showRewardedAd() {
        runOnUiThread(() -> {
            if (rewardedAd != null) {
                rewardedAd.show(MainActivity.this, reward -> {
                    rewardedAd = null;
                    loadRewardedAd();
                    if (web != null) web.evaluateJavascript("javascript:onAdRewarded()", null);
                });
            } else {
                loadRewardedAd();
                if (web != null) web.evaluateJavascript("javascript:onAdRewarded()", null);
            }
        });
    }
    public class AndroidAdBridge {
        @JavascriptInterface public void showRewarded() { showRewardedAd(); }
    }
}
