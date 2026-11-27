package com.roarnet.app;

import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import java.util.concurrent.Executor;
import android.os.Bundle;
import android.provider.Settings;
import android.os.PowerManager;
import android.os.Build;
import android.content.Intent;
import android.net.Uri;
import android.widget.Button;
import android.net.NetworkRequest;
import android.net.NetworkCapabilities;
import android.net.Network;
import android.net.ConnectivityManager;
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
import com.google.android.gms.ads.AdView;
import com.google.android.gms.ads.AdError;
import com.google.android.gms.ads.LoadAdError;
import com.google.android.gms.ads.FullScreenContentCallback;
import com.google.android.gms.ads.rewarded.RewardedAd;
import com.google.android.gms.ads.rewarded.RewardedAdLoadCallback;

import com.google.android.gms.ads.AdSize;
import android.view.ViewGroup;

public class MainActivity extends AppCompatActivity {
    private static final String LOCAL_URL = "http://127.0.0.1:3180/";
    private WebView web;
    private AdView bannerAdView;
    private RewardedAd rewardedAd;
    private boolean rewardedAdLoading = false;

    // ROARNET_IPSTERR_PROVIDER_V1
    private static volatile IPsterrProvider ipsterrProvider;

    private static IPsterrProvider getIPsterrProvider(
            android.content.Context context) {
        if (ipsterrProvider == null) {
            synchronized (MainActivity.class) {
                if (ipsterrProvider == null) {
                    IPsterrProvider provider =
                        IPsterrProviderFactory.create();
                    provider.initialize(context.getApplicationContext());
                    ipsterrProvider = provider;
                }
            }
        }
        return ipsterrProvider;
    }
    // END ROARNET_IPSTERR_PROVIDER_V1


    private LinearLayout mainLayout;

    private String pendingAuthCode;
    private ConnectivityManager networkManager;
    private ConnectivityManager.NetworkCallback networkCallback;
    private volatile Network selectedNetwork;
    private boolean applicationStarted;

    private native int startNode(
        String scriptPath,
        String databasePath,
        String adminToken
    );

    static {
        System.loadLibrary("node");
        System.loadLibrary("native-lib");
    }


    // ROARNET_REWARDED_AD_BRIDGE_V1
    private void emitRewardedEvent(
            String status, String message, int amount, String type) {
        try {
            JSONObject payload = new JSONObject();
            payload.put("status", status);
            payload.put("message", message);
            payload.put("amount", amount);
            payload.put("type", type);

            String script =
                "window.dispatchEvent(new CustomEvent('roarnet-rewarded'," +
                "{detail:" + payload.toString() + "}));";

            runOnUiThread(() -> {
                if (web != null) web.evaluateJavascript(script, null);
            });
        } catch (Exception ignored) {}
    }

    private void loadRewardedAd() {
        if (rewardedAdLoading || rewardedAd != null) return;

        rewardedAdLoading = true;

        RewardedAd.load(
            this,
            BuildConfig.ADMOB_REWARDED_AD_UNIT,
            new AdRequest.Builder().build(),
            new RewardedAdLoadCallback() {
                @Override
                public void onAdLoaded(RewardedAd ad) {
                    rewardedAdLoading = false;
                    rewardedAd = ad;
                    emitRewardedEvent(
                        "loaded", "Rewarded ad ready", 0, ""
                    );
                }

                @Override
                public void onAdFailedToLoad(LoadAdError error) {
                    rewardedAdLoading = false;
                    rewardedAd = null;
                    emitRewardedEvent(
                        "load_failed", error.getMessage(), 0, ""
                    );
                }
            }
        );
    }

    private void showRewardedAd() {
        if (rewardedAd == null) {
            emitRewardedEvent(
                "not_ready", "Rewarded ad is not ready", 0, ""
            );
            loadRewardedAd();
            return;
        }

        RewardedAd ad = rewardedAd;
        rewardedAd = null;

        ad.setFullScreenContentCallback(
            new FullScreenContentCallback() {
                @Override
                public void onAdDismissedFullScreenContent() {
                    emitRewardedEvent(
                        "dismissed", "Ad closed", 0, ""
                    );
                    loadRewardedAd();
                }

                @Override
                public void onAdFailedToShowFullScreenContent(
                        AdError error) {
                    emitRewardedEvent(
                        "show_failed", error.getMessage(), 0, ""
                    );
                    loadRewardedAd();
                }
            }
        );

        ad.show(this, rewardItem -> {
            emitRewardedEvent(
                "earned_pending_verification",
                "Google client reward callback received",
                rewardItem.getAmount(),
                rewardItem.getType()
            );
        });
    }

    public class RoarNetRewardedBridge {
        @JavascriptInterface
        public void load() {
            runOnUiThread(() -> loadRewardedAd());
        }

        @JavascriptInterface
        public void show() {
            runOnUiThread(() -> showRewardedAd());
        }
    }
    // END ROARNET_REWARDED_AD_BRIDGE_V1


    // ROARNET_IPSTERR_BRIDGE_V1
    public final class RoarNetIPsterrBridge {

        @JavascriptInterface
        public String status() {
            try {
                IPsterrProvider provider =
                    getIPsterrProvider(getApplicationContext());

                JSONObject result = new JSONObject();
                result.put("provider", "ipsterr");
                result.put("state", provider.getState().name());
                result.put("message", provider.getStatusMessage());
                result.put("configured",
                    provider.getState() != IPsterrProvider.State.NOT_CONFIGURED);
                return result.toString();
            } catch (Exception e) {
                return "{\"provider\":\"ipsterr\",\"state\":\"ERROR\"}";
            }
        }

        @JavascriptInterface
        public boolean startAfterConsent(boolean explicitConsentAccepted) {
            SharedPreferences consentPrefs =
                getSharedPreferences("roarnet_consent", MODE_PRIVATE);

            if (!explicitConsentAccepted ||
                !consentPrefs.getBoolean("accepted", false)) {
                return false;
            }

            try {
                return getIPsterrProvider(getApplicationContext()).start();
            } catch (Exception ignored) {
                return false;
            }
        }

        @android.webkit.JavascriptInterface
        public void stop() {
            try {
                getIPsterrProvider(getApplicationContext()).stop();
            } catch (Exception ignored) { }
        }
    }
    // END ROARNET_IPSTERR_BRIDGE_V1

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);

        SharedPreferences consentPrefs =
            getSharedPreferences("roarnet_consent", MODE_PRIVATE);

        if (!consentPrefs.getBoolean("choice_saved", false)) {
            startActivity(new Intent(this, ConsentScreen.class));
            finish();
            return;
        }

        boolean sharingAccepted =
            consentPrefs.getBoolean("accepted", false);

        if (sharingAccepted) {
            startRoarService();
            askBackground();
        }

        getIPsterrProvider(getApplicationContext());
        captureAuthCode(getIntent());
        showMessage("🦁 RoarNet", "اختر شبكة الاتصال...");
        selectNetworkAndStart(() -> {
            MobileAds.initialize(this, status -> loadRewardedAd());

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
        });
    }


    // ROARNET_PROCESS_NETWORK_SELECTION_V1
    private void releaseSelectedNetwork() {
        if (networkManager != null) {
            if (networkCallback != null) {
                try {
                    networkManager.unregisterNetworkCallback(networkCallback);
                } catch (Exception ignored) {}
            }

            try {
                networkManager.bindProcessToNetwork(null);
            } catch (Exception ignored) {}
        }

        networkCallback = null;
        networkManager = null;
        selectedNetwork = null;
    }

    private void selectNetworkAndStart(Runnable startApplication) {
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setPadding(24, 24, 24, 20);
        panel.setBackgroundColor(Color.WHITE);

        TextView title = new TextView(this);
        title.setText("اختر شبكة اتصال RoarNet");
        title.setTextSize(21);
        title.setTextColor(Color.BLACK);
        title.setGravity(Gravity.CENTER);
        title.setPadding(8, 8, 8, 20);
        panel.addView(title);

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER);

        AlertDialog dialog = new AlertDialog.Builder(this)
            .setView(panel)
            .setCancelable(false)
            .create();

        Runnable automatic = () -> {
            releaseSelectedNetwork();
            dialog.dismiss();

            if (!applicationStarted) {
                applicationStarted = true;
                startApplication.run();
            }
        };

        java.util.function.IntConsumer choose = transport -> {
            ConnectivityManager cm =
                (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);

            if (cm == null) {
                showMessage("RoarNet", "تعذر الوصول إلى مدير الشبكات.");
                return;
            }

            releaseSelectedNetwork();

            NetworkRequest request = new NetworkRequest.Builder()
                .addTransportType(transport)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build();

            ConnectivityManager.NetworkCallback callback =
                new ConnectivityManager.NetworkCallback() {
                    @Override
                    public void onAvailable(Network network) {
                        boolean bound = cm.bindProcessToNetwork(network);

                        if (!bound) {
                            runOnUiThread(() ->
                                showMessage("RoarNet",
                                    "تعذر ربط الشبكة المختارة."));
                            return;
                        }

                        selectedNetwork = network;

                        runOnUiThread(() -> {
                            if (dialog.isShowing()) {
                                dialog.dismiss();
                            }

                            if (!applicationStarted) {
                                applicationStarted = true;
                                startApplication.run();
                            }
                        });
                    }

                    @Override
                    public void onLost(Network network) {
                        if (network.equals(selectedNetwork)) {
                            cm.bindProcessToNetwork(null);
                            selectedNetwork = null;

                            runOnUiThread(() ->
                                showMessage("RoarNet",
                                    "انقطع اتصال الشبكة المختارة. "
                                    + "يجري انتظار توفر الاتصال مجدداً."));
                        }
                    }

                    @Override
                    public void onUnavailable() {
                        runOnUiThread(() -> {
                            releaseSelectedNetwork();
                            showMessage("RoarNet",
                                "الشبكة غير متاحة. تحقق من الاتصال وحاول مجدداً.");
                        });
                    }
                };

            networkManager = cm;
            networkCallback = callback;

            try {
                if (android.os.Build.VERSION.SDK_INT >= 26) {
                    cm.requestNetwork(request, callback, 30000);
                } else {
                    cm.requestNetwork(request, callback);
                }
            } catch (Exception e) {
                releaseSelectedNetwork();
                showMessage("RoarNet",
                    "تعذر طلب الشبكة: " + e.getMessage());
            }
        };

        Button wifi = new Button(this);
        wifi.setText("📶\nWi-Fi");
        wifi.setAllCaps(false);
        wifi.setTextSize(17);
        wifi.setMinHeight(120);

        Button sim = new Button(this);
        sim.setText("▦\nSIM");
        sim.setAllCaps(false);
        sim.setTextSize(17);
        sim.setMinHeight(120);

        LinearLayout.LayoutParams params =
            new LinearLayout.LayoutParams(0, 120, 1f);
        params.setMargins(5, 5, 5, 5);
        row.addView(wifi, params);
        row.addView(sim, params);
        panel.addView(row);

        Button auto = new Button(this);
        auto.setText("تلقائي - الشبكة الافتراضية");
        auto.setAllCaps(false);
        panel.addView(auto);

        wifi.setOnClickListener(v ->
            choose.accept(NetworkCapabilities.TRANSPORT_WIFI));
        sim.setOnClickListener(v ->
            choose.accept(NetworkCapabilities.TRANSPORT_CELLULAR));
        auto.setOnClickListener(v -> automatic.run());

        dialog.show();
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


    // ROARNET_NATIVE_CONSENT_BRIDGE_V1
    private final class RoarNetConsentBridge {
        @JavascriptInterface
        public boolean isAccepted() {
            return getSharedPreferences("roarnet_consent", MODE_PRIVATE)
                .getBoolean("accepted", false);
        }

        @JavascriptInterface
        public boolean setAccepted(boolean accepted) {
            return getSharedPreferences("roarnet_consent", MODE_PRIVATE)
                .edit()
                .putBoolean("accepted", accepted)
                .putBoolean("choice_saved", true)
                .commit();
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
            if (!getSharedPreferences("roarnet_consent", MODE_PRIVATE)
                    .getBoolean("accepted", false)) {
                return "لا يمكن تشغيل Relay قبل الموافقة المحلية على مشاركة الإنترنت.";
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

        @android.webkit.JavascriptInterface
        public String stats() {
            try {
                ParticipantTcpTunnel.initializeTrafficStorage(
                    MainActivity.this.getApplicationContext()
                );

                long[] traffic = ParticipantTcpTunnel.getTrafficSnapshot();
                java.util.Map<String, long[]> providers =
                    ParticipantTcpTunnel.getProviderTrafficSnapshot();

                org.json.JSONObject result = new org.json.JSONObject();
                org.json.JSONObject providerData = new org.json.JSONObject();

                for (java.util.Map.Entry<String, long[]> entry : providers.entrySet()) {
                    long[] values = entry.getValue();
                    org.json.JSONObject item = new org.json.JSONObject();
                    item.put("bytesSent", values[0]);
                    item.put("bytesReceived", values[1]);
                    item.put("totalBytes", values[0] + values[1]);
                    item.put("activeSessions", values[2]);
                    providerData.put(entry.getKey(), item);
                }

                result.put("serviceRunning", RelayAgentService.serviceRunning);
                result.put("sharingReady", RelayAgentService.sharingReady);
                result.put("bytesSent", traffic[0]);
                result.put("bytesReceived", traffic[1]);
                result.put("totalBytes", traffic[0] + traffic[1]);
                result.put("activeSessions", traffic[2]);
                result.put("providers", providerData);

                return result.toString();
            } catch (Exception error) {
                return "{\"error\":\"TRAFFIC_STATS_FAILED\"}";
            }
        }
        @android.webkit.JavascriptInterface
        public void stop() {
            try {
                stopService(new Intent(MainActivity.this, RelayAgentService.class));
            } catch (Exception ignored) { }
        }
    }

    // ROARNET_PROXIES_SDK_START_V1


    // ROARNET_DIAGNOSTIC_SPIDER_V1
    private String sanitizeDiagnostic(String value) {
        if (value == null) return "";
        String safe = value.length() > 1200
            ? value.substring(0, 1200) : value;

        safe = safe.replaceAll(
            "(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}",
            "[EMAIL]"
        );
        safe = safe.replaceAll(
            "(?i)(bearer\\s+)[A-Za-z0-9._~+/=-]+",
            "$1[REDACTED]"
        );
        safe = safe.replaceAll(
            "(?i)(access_token|refresh_token|code|token|apikey|api_key)=([^&\\s]+)",
            "$1=[REDACTED]"
        );
        safe = safe.replaceAll(
            "\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b",
            "[JWT_REDACTED]"
        );
        safe = safe.replaceAll(
            "(?i)sb_publishable_[A-Za-z0-9_-]+",
            "[PUBLIC_KEY_REDACTED]"
        );
        return safe;
    }

    private final class RoarNetDiagnosticsBridge {
        @JavascriptInterface
        public void capture(
                String level, String source, String message, int line) {
            String safeSource = sanitizeDiagnostic(source);
            String safeMessage = sanitizeDiagnostic(message);

            String entry = "source=" + safeSource
                + " | line=" + line
                + " | " + safeMessage;

            if ("WARN".equalsIgnoreCase(level)) {
                android.util.Log.w("RoarNetSpider", entry);
            } else if ("INFO".equalsIgnoreCase(level)) {
                android.util.Log.i("RoarNetSpider", entry);
            } else {
                android.util.Log.e("RoarNetSpider", entry);
            }
        }
    }
    // /ROARNET_DIAGNOSTIC_SPIDER_V1


    // ROARNET_ADMIN_BIOMETRIC_V1
    private boolean requireAdminBiometric() {
        BiometricManager bm = BiometricManager.from(this);
        if (bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) != BiometricManager.BIOMETRIC_SUCCESS) {
            return false;
        }
        CountDownLatch latch = new CountDownLatch(1);
        AtomicBoolean ok = new AtomicBoolean(false);
        Executor executor = ContextCompat.getMainExecutor(this);
        BiometricPrompt prompt = new BiometricPrompt(this, executor, new BiometricPrompt.AuthenticationCallback() {
            @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) { ok.set(true); latch.countDown(); }
            @Override public void onAuthenticationError(int c, CharSequence e) { latch.countDown(); }
            @Override public void onAuthenticationFailed() { }
        });
        runOnUiThread(() -> {
            try {
                prompt.authenticate(new BiometricPrompt.PromptInfo.Builder()
                    .setTitle("تأكيد هوية المدير")
                    .setSubtitle("البصمة مطلوبة للوصول لبيانات الادمن")
                    .setNegativeButtonText("إلغاء")
                    .build());
            } catch (Exception e) { latch.countDown(); }
        });
        try { latch.await(60, TimeUnit.SECONDS); } catch (Exception e) { return false; }
        return ok.get();
    }
    // /ROARNET_ADMIN_BIOMETRIC_V1

    // ROARNET_ANDROID_ADMIN_BRIDGE_V1
    private final class RoarNetAdminBridge {
        @JavascriptInterface
        public String generateParticipantLinkCode(String nodeId) {
            if (!requireAdminBiometric()) return "{\"error\":\"مطلوب تأكيد البصمة.\"}";
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
            if (!requireAdminBiometric()) return "{\"error\":\"مطلوب تأكيد البصمة.\"}";
            return adminRequest("api/admin/withdrawals", "GET", "");
        }

        @JavascriptInterface
        public String updateAdminWithdrawal(String id, String json) {
            if (!requireAdminBiometric()) return "{\"error\":\"مطلوب تأكيد البصمة.\"}";
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
            if (!requireAdminBiometric()) return "{\"error\":\"مطلوب تأكيد البصمة.\"}";
            return adminRequest("api/admin/summary", "GET", "");
        }

        @JavascriptInterface
        public String getProviderRevenueBatches() {
            if (!requireAdminBiometric()) return "{\"error\":\"مطلوب تأكيد البصمة.\"}";
            return adminRequest("api/admin/provider-revenue-batches", "GET", "");
        }

        @JavascriptInterface
        public String createProviderRevenueBatch(String json) {
            if (!requireAdminBiometric()) return "{\"error\":\"مطلوب تأكيد البصمة.\"}";
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
    protected void onActivityResult(
            int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);


    }

    @Override
    protected void onResume() {

        super.onResume();
        if (bannerAdView != null) {
            bannerAdView.resume();
        }
    }

    @Override
    protected void onPause() {
        if (bannerAdView != null) {
            bannerAdView.pause();
        }
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        if (bannerAdView != null) {
            bannerAdView.destroy();
            bannerAdView = null;
        }
        releaseSelectedNetwork();

        // App-scoped VPN controller and executor intentionally survive
        // Activity recreation. Do not stop or shut down the VPN here.
        super.onDestroy();
    }

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
            public void onReceivedError(
                    WebView view,
                    android.webkit.WebResourceRequest request,
                    android.webkit.WebResourceError error) {
                super.onReceivedError(view, request, error);
                android.util.Log.e(
                    "RoarNetWebView",
                    "Load error: " + sanitizeDiagnostic(String.valueOf(error.getDescription()))
                        + " | URL: " + sanitizeDiagnostic(request.getUrl().toString())
                );
            }

            @Override
            public void onReceivedHttpError(
                    WebView view,
                    android.webkit.WebResourceRequest request,
                    android.webkit.WebResourceResponse response) {
                super.onReceivedHttpError(view, request, response);
                android.util.Log.e(
                    "RoarNetWebView",
                    "HTTP error: " + response.getStatusCode()
                        + " | URL: " + sanitizeDiagnostic(request.getUrl().toString())
                );
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

        // ROARNET_WEBVIEW_DIAGNOSTICS_V1
        web.setWebChromeClient(new android.webkit.WebChromeClient() {
            @Override
            public boolean onConsoleMessage(
                    android.webkit.ConsoleMessage message) {
                android.util.Log.e(
                    "RoarNetWebView",
                    sanitizeDiagnostic(message.message())
                        + " | line: " + message.lineNumber()
                        + " | source: " + sanitizeDiagnostic(message.sourceId())
                );
                return true;
            }
        });

        web.addJavascriptInterface(new RoarNetDiagnosticsBridge(), "RoarNetDiagnosticsBridge");
        web.addJavascriptInterface(new RoarNetAdminBridge(), "RoarNetAdmin");
        web.addJavascriptInterface(
            new RoarNetConsentBridge(), "RoarNetConsent"
        );
        web.addJavascriptInterface(new RoarNetRelayBridge(), "RoarNetRelay");

        web.addJavascriptInterface(
            new RoarNetRewardedBridge(), "RoarNetRewarded"
        );
        // IPsterr bridge disabled - waiting for partner approval
        // web.addJavascriptInterface(new RoarNetIPsterrBridge(), "RoarNetIPsterr");
        web.setBackgroundColor(Color.rgb(16, 24, 39));
        // /ROARNET_WEBVIEW_LOCAL_ONLY_V1
        mainLayout = new LinearLayout(this);
        mainLayout.setOrientation(LinearLayout.VERTICAL);
        mainLayout.setBackgroundColor(Color.rgb(16, 24, 39));

        mainLayout.addView(
            web,
            new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
        );

        bannerAdView = new AdView(this);
        bannerAdView.setAdUnitId(BuildConfig.ADMOB_BANNER_AD_UNIT);

        int widthDp = (int) (
            getResources().getDisplayMetrics().widthPixels
                / getResources().getDisplayMetrics().density
        );

        bannerAdView.setAdSize(
            AdSize.getCurrentOrientationAnchoredAdaptiveBannerAdSize(
                this,
                widthDp
            )
        );

        mainLayout.addView(
            bannerAdView,
            new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        );

        setContentView(mainLayout);

        bannerAdView.loadAd(new AdRequest.Builder().build());
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



    private void startRoarService() {
        try {
            Intent i = new Intent(this, RoarService.class);
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(i);
            else startService(i);
        } catch (Exception e) {}
    }
    private void askBackground() {
        try {
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            if (!pm.isIgnoringBatteryOptimizations(getPackageName())) {
                Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            }
        } catch (Exception e) {}
    }
}
