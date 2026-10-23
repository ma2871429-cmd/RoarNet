package com.roarnet.app;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebSettings;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;

public class MainActivity extends Activity {
    // After deploying backend/server, replace this with its HTTPS address, e.g. https://roarnet.example.com
    private static final String SERVER_URL = "";
    private WebView web;

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (SERVER_URL.startsWith("https://")) {
            web = new WebView(this);
            WebSettings settings = web.getSettings();
            settings.setJavaScriptEnabled(true);
            settings.setDomStorageEnabled(true);
            web.setWebViewClient(new WebViewClient());
            web.setBackgroundColor(Color.rgb(16,24,39));
            setContentView(web);
            web.loadUrl(SERVER_URL);
        } else {
            LinearLayout layout = new LinearLayout(this);
            layout.setOrientation(LinearLayout.VERTICAL);
            layout.setGravity(Gravity.CENTER);
            layout.setPadding(32,32,32,32);
            layout.setBackgroundColor(Color.rgb(16,24,39));
            TextView title = new TextView(this);
            title.setText("🦁 RoarNet"); title.setTextSize(30); title.setTypeface(null, Typeface.BOLD); title.setTextColor(Color.rgb(117,224,193)); title.setGravity(Gravity.CENTER);
            TextView body = new TextView(this);
            body.setText("تم تثبيت غلاف التطبيق بنجاح.\n\nحتى تعمل لوحة الإدارة وتسجيل الدخول، يجب نشر خادم RoarNet ثم وضع رابط HTTPS الخاص به في SERVER_URL داخل MainActivity.java وإعادة بناء APK.\n\nهذه النسخة لا تشارك الإنترنت ولا تولّد أرباحاً حقيقية.");
            body.setTextSize(17); body.setTextColor(Color.WHITE); body.setGravity(Gravity.CENTER); body.setPadding(0,24,0,0);
            layout.addView(title); layout.addView(body); setContentView(layout);
        }
    }
    @Override public void onBackPressed() {
        if (web != null && web.canGoBack()) web.goBack(); else super.onBackPressed();
    }
}
