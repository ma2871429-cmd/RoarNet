package com.roarnet.app;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;
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
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.SecureRandom;

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
                if (!script.exists()) {
                    copyAsset("roarnet-server/server.mjs", script);
                }

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

    private void openLocalWebView() {
        web = new WebView(this);
        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        web.setWebViewClient(new WebViewClient());
        web.setBackgroundColor(Color.rgb(16, 24, 39));
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
