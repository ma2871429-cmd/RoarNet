package com.roarnet.app;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class ConsentScreen extends Activity {

    private static final String PREFS = "roarnet_consent";
    private static final String KEY_SAVED = "choice_saved";
    private static final String KEY_ACCEPTED = "accepted";

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);

        getWindow().setStatusBarColor(Color.rgb(9, 16, 29));
        getWindow().setNavigationBarColor(Color.rgb(9, 16, 29));
        getWindow().setFlags(
            WindowManager.LayoutParams.FLAG_FULLSCREEN,
            WindowManager.LayoutParams.FLAG_FULLSCREEN
        );

        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        if (prefs.getBoolean(KEY_SAVED, false)) {
            openApplication();
            return;
        }

        buildScreen();
    }

    private void buildScreen() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(Color.rgb(9, 16, 29));

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setPadding(dp(26), dp(35), dp(26), dp(28));

        TextView logo = new TextView(this);
        logo.setText("RoarNet");
        logo.setTextColor(Color.rgb(76, 211, 176));
        logo.setTextSize(32);
        logo.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        logo.setGravity(Gravity.CENTER);
        root.addView(logo, matchWrap());

        TextView heading = new TextView(this);
        heading.setText("موافقة استخدام التطبيق ومشاركة الاتصال");
        heading.setTextColor(Color.WHITE);
        heading.setTextSize(22);
        heading.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        heading.setGravity(Gravity.CENTER);
        heading.setPadding(0, dp(32), 0, dp(18));
        root.addView(heading, matchWrap());

        TextView description = new TextView(this);
        description.setText(
            "قبل استخدام RoarNet، يرجى قراءة ما يلي:\\n\\n" +
            "• عند تفعيل مشاركة الإنترنت، قد يُستخدم جزء من اتصال جهازك " +
            "من خلال مزودي خدمات معتمدين، ومنهم حالياً: Earn.fm.\\n\\n" +
            "• قد تتم معالجة عنوان IP وحركة البيانات المرتبطة بالمشاركة " +
            "وفق شروط كل مزود وسياسة خصوصية RoarNet.\\n\\n" +
            "• قد يؤدي تشغيل المشاركة إلى استهلاك بيانات الإنترنت " +
            "واستخدام موارد اتصال جهازك.\\n\\n" +
            "• القبول هنا يسمح بمتابعة إعداد المشاركة، لكنه لا يمنح " +
            "أي مزود موافقة تلقائية؛ ستبقى موافقات المزودين المنفصلة مطلوبة.\\n\\n" +
            "• تحصل على مكافآت مالية مقابل حجم الترافيك المؤهل الذي يمر عبر جهازك، ويتم احتسابها وفق شروط كل مزود.\\n\\n" +
            "• يمكنك إيقاف مشاركة الإنترنت في أي وقت من داخل التطبيق، وسيتوقف استخدام اتصالك فوراً.\\n\\n" +
            "• يمكنك رفض المشاركة. سيظل بإمكانك فتح التطبيق، لكن لن " +
            "تُفعّل مشاركة الإنترنت من خلال هذا الاختيار."
        );
        description.setTextColor(Color.rgb(213, 222, 235));
        description.setTextSize(16);
        description.setLineSpacing(dp(4), 1.0f);
        root.addView(description, matchWrap());

        TextView note = new TextView(this);
        note.setText("سيُحفظ اختيارك على هذا الجهاز. يمكنك تغييره أو إيقاف المشاركة في أي وقت من إعدادات التطبيق.");
        note.setTextColor(Color.rgb(145, 164, 187));
        note.setTextSize(13);
        note.setPadding(0, dp(24), 0, dp(20));
        root.addView(note, matchWrap());

        Button accept = new Button(this);
        accept.setText("أوافق وأتابع");
        accept.setTextSize(16);
        accept.setAllCaps(false);
        accept.setTextColor(Color.WHITE);
        accept.setBackgroundTintList(
            android.content.res.ColorStateList.valueOf(Color.rgb(22, 124, 104))
        );
        root.addView(accept, buttonParams());

        Button reject = new Button(this);
        reject.setText("أرفض");
        reject.setTextSize(16);
        reject.setAllCaps(false);
        reject.setTextColor(Color.WHITE);
        reject.setBackgroundTintList(
            android.content.res.ColorStateList.valueOf(Color.rgb(75, 85, 101))
        );
        LinearLayout.LayoutParams rejectParams = buttonParams();
        rejectParams.topMargin = dp(12);
        root.addView(reject, rejectParams);

        accept.setOnClickListener(v -> saveChoice(true));
        reject.setOnClickListener(v -> saveChoice(false));

        scroll.addView(root);
        setContentView(scroll);
    }

    private void saveChoice(boolean accepted) {
        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        boolean saved = prefs.edit()
            .putBoolean(KEY_ACCEPTED, accepted)
            .putBoolean(KEY_SAVED, true)
            .commit();

        if (!saved) return;
        openApplication();
    }

    private void openApplication() {
        Intent intent = new Intent(this, MainActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK |
                        Intent.FLAG_ACTIVITY_CLEAR_TOP);
        startActivity(intent);
        finish();
    }

    private int dp(int value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        );
    }

    private LinearLayout.LayoutParams buttonParams() {
        LinearLayout.LayoutParams params = matchWrap();
        params.height = dp(54);
        return params;
    }
}
