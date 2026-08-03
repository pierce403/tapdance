package tech.titor.tapdance;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.NfcA;
import android.os.Build;
import android.os.Bundle;
import android.os.PersistableBundle;
import android.view.Gravity;
import android.view.HapticFeedbackConstants;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Space;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import tech.titor.tapdance.nfc.AuthenticationResult;
import tech.titor.tapdance.nfc.DiagnosticReport;
import tech.titor.tapdance.nfc.Hex;
import tech.titor.tapdance.nfc.RecordingByteTransceiver;
import tech.titor.tapdance.nfc.UltralightAesAuthenticator;

public final class MainActivity extends Activity implements NfcAdapter.ReaderCallback {
    private static final int NFC_TIMEOUT_MILLIS = 1000;
    private static final int PRESENCE_CHECK_DELAY_MILLIS = 250;
    private static final int BG = Color.rgb(9, 9, 11);
    private static final int PANEL = Color.rgb(23, 23, 28);
    private static final int PANEL_ALT = Color.rgb(31, 29, 39);
    private static final int TEXT = Color.rgb(247, 245, 239);
    private static final int MUTED = Color.rgb(185, 182, 176);
    private static final int PURPLE = Color.rgb(155, 135, 245);
    private static final int CYAN = Color.rgb(103, 232, 249);
    private static final int GREEN = Color.rgb(110, 231, 168);
    private static final int ORANGE = Color.rgb(255, 122, 26);
    private static final int RED = Color.rgb(255, 123, 114);

    private final AtomicBoolean armed = new AtomicBoolean(false);
    private final AtomicBoolean busy = new AtomicBoolean(false);
    private final AtomicLong attemptGeneration = new AtomicLong();
    private final AtomicLong closeRequestedAttempt = new AtomicLong(Long.MIN_VALUE);
    private final ExecutorService nfcWorker = Executors.newSingleThreadExecutor();
    private final SecureRandom random = new SecureRandom();

    private NfcAdapter adapter;
    private volatile NfcA activeNfcA;
    private volatile long armedAttempt;
    private TextView stateBadge;
    private TextView stateTitle;
    private TextView stateDetail;
    private TextView technicalDetail;
    private Button armButton;
    private Button diagnosticButton;
    private String latestDiagnosticReport = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        View content = buildInterface();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            getWindow().setDecorFitsSystemWindows(false);
            content.setOnApplyWindowInsetsListener((view, windowInsets) -> {
                android.graphics.Insets bars = windowInsets.getInsets(
                        WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
                return windowInsets;
            });
        }
        setContentView(content);

        adapter = NfcAdapter.getDefaultAdapter(this);
        if (adapter == null) {
            armButton.setEnabled(false);
            renderState("NO NFC", "This phone cannot run TapDance",
                    "TapDance requires an Android device with NFC-A reader support.", RED, "");
        } else if (!adapter.isEnabled()) {
            armButton.setEnabled(false);
            renderState("NFC OFF", "Turn on NFC to begin",
                    "Enable NFC in Android settings, then return to TapDance.", ORANGE, "");
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (adapter != null && adapter.isEnabled()) {
            armButton.setEnabled(true);
        }
    }

    @Override
    protected void onPause() {
        disarm(false);
        NfcA session = activeNfcA;
        if (session != null) {
            closeRequestedAttempt.set(armedAttempt);
            try {
                session.close();
            } catch (IOException | SecurityException ignored) {
                // Closing is the documented way to cancel a blocked transceive.
            }
        }
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        nfcWorker.shutdownNow();
        super.onDestroy();
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        if (!armed.compareAndSet(true, false) || !busy.compareAndSet(false, true)) {
            return;
        }
        long attempt = armedAttempt;

        runOnUiThread(() -> {
            armButton.setEnabled(false);
            renderState("TESTING", "Keep the tag in place",
                    "Identifying the chip and making one authentication attempt…",
                    PURPLE, "UID  " + Hex.encodeSpaced(tag.getId()));
        });

        nfcWorker.execute(() -> runAuthentication(tag, attempt));
    }

    private void runAuthentication(Tag tag, long attempt) {
        long startedNanos = System.nanoTime();
        AuthenticationResult result;
        RecordingByteTransceiver trace = new RecordingByteTransceiver(
                command -> { throw new IOException("NFC-A session unavailable"); });
        DiagnosticReport.Metadata metadata = diagnosticMetadata(tag);
        NfcA nfcA = NfcA.get(tag);
        if (nfcA == null) {
            result = AuthenticationResult.of(
                    AuthenticationResult.Outcome.UNSUPPORTED,
                    "The detected tag does not expose Android's NFC-A interface.",
                    tag.getId(), null);
        } else {
            metadata.atqa = nfcA.getAtqa();
            metadata.sak = nfcA.getSak();
            metadata.maxTransceiveLength = nfcA.getMaxTransceiveLength();
            try {
                activeNfcA = nfcA;
                if (!isAttemptActive(attempt)) {
                    result = cancelledBeforeSubmission(tag);
                } else if (metadata.maxTransceiveLength < 33) {
                    result = AuthenticationResult.of(
                            AuthenticationResult.Outcome.UNSUPPORTED,
                            "This phone's NFC controller cannot send the 33-byte authentication "
                                    + "frame required by MIFARE Ultralight AES.",
                            tag.getId(), null);
                } else {
                    nfcA.connect();
                    nfcA.setTimeout(NFC_TIMEOUT_MILLIS);
                    metadata.timeoutMillis = nfcA.getTimeout();
                    if (!isAttemptActive(attempt)) {
                        result = cancelledBeforeSubmission(tag);
                    } else {
                        RecordingByteTransceiver activeTrace =
                                new RecordingByteTransceiver(nfcA::transceive);
                        trace = activeTrace;
                        result = UltralightAesAuthenticator.testFactoryDataKey(
                                command -> {
                                    if (!isAttemptActive(attempt)) {
                                        throw new IOException("Test cancelled");
                                    }
                                    return activeTrace.transceive(command);
                                },
                                tag.getId(),
                                random::nextBytes,
                                () -> !isAttemptActive(attempt));
                    }
                }
            } catch (IOException | SecurityException error) {
                metadata.sessionErrorType = error.getClass().getName();
                metadata.sessionErrorMessage = error.getMessage();
                result = AuthenticationResult.of(
                        AuthenticationResult.Outcome.INCONCLUSIVE,
                        "Communication ended before the authentication exchange completed. "
                                + "Keep the tag still and try one more deliberate scan.",
                        tag.getId(), null);
            } finally {
                metadata.cancelledDuringExchange = closeRequestedAttempt.get() == attempt;
                try {
                    metadata.connectedAfterExchange = nfcA.isConnected();
                } catch (SecurityException error) {
                    metadata.connectedAfterExchange = false;
                    if (metadata.sessionErrorType.isEmpty()) {
                        metadata.sessionErrorType = error.getClass().getName();
                        metadata.sessionErrorMessage = error.getMessage();
                    }
                }
                activeNfcA = null;
                try {
                    nfcA.close();
                } catch (IOException | SecurityException ignored) {
                    // The RF session is already over.
                }
            }
        }

        metadata.totalDurationNanos = System.nanoTime() - startedNanos;
        returnResult(result, DiagnosticReport.create(result, trace, metadata));
    }

    private DiagnosticReport.Metadata diagnosticMetadata(Tag tag) {
        DiagnosticReport.Metadata metadata = new DiagnosticReport.Metadata();
        metadata.appVersion = BuildConfig.VERSION_NAME + " (" + BuildConfig.VERSION_CODE + ")";
        metadata.device = Build.MANUFACTURER + " " + Build.MODEL;
        metadata.androidVersion = Build.VERSION.RELEASE + " / API " + Build.VERSION.SDK_INT;
        metadata.buildFingerprint = Build.FINGERPRINT;
        metadata.technologies = tag.getTechList();
        metadata.presenceCheckDelayMillis = PRESENCE_CHECK_DELAY_MILLIS;
        metadata.timeoutMillis = NFC_TIMEOUT_MILLIS;
        return metadata;
    }

    private boolean isAttemptActive(long attempt) {
        return busy.get() && attemptGeneration.get() == attempt;
    }

    private AuthenticationResult cancelledBeforeSubmission(Tag tag) {
        return AuthenticationResult.of(
                AuthenticationResult.Outcome.INCONCLUSIVE,
                "The test was cancelled before the candidate-key proof was submitted. No key "
                        + "guess was sent.",
                tag.getId(), null);
    }

    private void returnResult(AuthenticationResult result, DiagnosticReport report) {
        AuthenticationResult finalResult = result;
        runOnUiThread(() -> {
            stopReaderMode();
            busy.set(false);
            armButton.setEnabled(adapter != null && adapter.isEnabled());
            armButton.setText("Run another one-shot test");
            armButton.setOnClickListener(view -> requestArm());
            setDiagnosticReport(report.full());
            showResult(finalResult, report);
            armButton.performHapticFeedback(HapticFeedbackConstants.CONFIRM);
        });
    }

    private void showResult(AuthenticationResult result, DiagnosticReport report) {
        String tech = "UID  " + Hex.encodeSpaced(result.uid());
        if (result.version().length > 0) {
            tech += "\nVER  " + Hex.encodeSpaced(result.version());
        }
        tech += "\n\n" + report.summary();

        switch (result.outcome()) {
            case ACCEPTED:
                renderState("ACCEPTED", "Factory key accepted",
                        "This tag authenticated with the all-zero factory DataProtKey. "
                                + "TapDance made no writes.", GREEN, tech);
                break;
            case REJECTED:
                renderState("REJECTED", "Factory key rejected",
                        "The all-zero factory DataProtKey did not authenticate. This result "
                                + "does not prove that the credential or access system is secure.",
                        RED, tech);
                break;
            case UNSUPPORTED:
                renderState("NOT A MATCH", "Different or unsupported tag",
                        result.detail(), ORANGE, tech);
                break;
            case INCONCLUSIVE:
            default:
                renderState("INCONCLUSIVE", "No reliable answer",
                        result.detail(), ORANGE, tech);
                break;
        }
    }

    private View buildInterface() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BG);

        LinearLayout page = column();
        page.setPadding(dp(22), dp(30), dp(22), dp(32));
        scroll.addView(page, matchWrap());

        TextView wordmark = text("TAPDANCE", 13, PURPLE, Typeface.BOLD);
        wordmark.setLetterSpacing(0.22f);
        page.addView(wordmark);

        TextView headline = text("One tap. One key.\nOne clear answer.", 38, TEXT, Typeface.BOLD);
        headline.setLineSpacing(0, 0.96f);
        page.addView(headline, margins(matchWrap(), 0, 14, 0, 0));

        TextView intro = text(
                "A read-only diagnostic for NXP MIFARE Ultralight AES tags. "
                        + "TapDance tests only the factory DataProtKey—and only when you arm it.",
                17, MUTED, Typeface.NORMAL);
        intro.setLineSpacing(dp(3), 1f);
        page.addView(intro, margins(matchWrap(), 0, 14, 0, 0));

        LinearLayout stateCard = column();
        stateCard.setPadding(dp(20), dp(20), dp(20), dp(20));
        stateCard.setBackground(roundRect(PANEL_ALT, 22, Color.rgb(61, 56, 78)));
        page.addView(stateCard, margins(matchWrap(), 0, 25, 0, 0));

        stateBadge = text("READY", 12, PURPLE, Typeface.BOLD);
        stateBadge.setLetterSpacing(0.14f);
        stateCard.addView(stateBadge);

        stateTitle = text("Ready when you are", 25, TEXT, Typeface.BOLD);
        stateTitle.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_ASSERTIVE);
        stateCard.addView(stateTitle, margins(matchWrap(), 0, 9, 0, 0));

        stateDetail = text(
                "Arm the one-shot test, then hold an authorized tag against the back of your phone.",
                16, MUTED, Typeface.NORMAL);
        stateDetail.setLineSpacing(dp(2), 1f);
        stateCard.addView(stateDetail, margins(matchWrap(), 0, 9, 0, 0));

        technicalDetail = text("", 13, CYAN, Typeface.MONOSPACE.getStyle());
        technicalDetail.setTypeface(Typeface.MONOSPACE);
        technicalDetail.setVisibility(View.GONE);
        stateCard.addView(technicalDetail, margins(matchWrap(), 0, 15, 0, 0));

        diagnosticButton = new Button(this);
        diagnosticButton.setAllCaps(false);
        diagnosticButton.setText("View diagnostic report");
        diagnosticButton.setTextSize(14);
        diagnosticButton.setTextColor(TEXT);
        diagnosticButton.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        diagnosticButton.setMinHeight(dp(48));
        diagnosticButton.setBackground(roundRect(PANEL, 14, Color.rgb(76, 72, 91)));
        diagnosticButton.setOnClickListener(view -> showDiagnosticReport());
        diagnosticButton.setVisibility(View.GONE);
        stateCard.addView(diagnosticButton, margins(matchWrap(), 0, 15, 0, 0));

        armButton = new Button(this);
        armButton.setAllCaps(false);
        armButton.setText("Arm one-shot test");
        armButton.setTextSize(17);
        armButton.setTextColor(BG);
        armButton.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        armButton.setMinHeight(dp(56));
        armButton.setBackground(roundRect(PURPLE, 16, PURPLE));
        armButton.setOnClickListener(view -> requestArm());
        page.addView(armButton, margins(matchWrap(), 0, 20, 0, 0));

        LinearLayout keyCard = column();
        keyCard.setPadding(dp(18), dp(17), dp(18), dp(17));
        keyCard.setBackground(roundRect(PANEL, 18, Color.rgb(48, 48, 57)));
        page.addView(keyCard, margins(matchWrap(), 0, 14, 0, 0));
        keyCard.addView(text("KEY UNDER TEST", 11, MUTED, Typeface.BOLD));
        TextView key = text("0000000000000000\n0000000000000000", 17, CYAN, Typeface.NORMAL);
        key.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        key.setLetterSpacing(0.08f);
        keyCard.addView(key, margins(matchWrap(), 0, 8, 0, 0));
        keyCard.addView(text("DataProtKey · AES-128 · exactly one attempt", 13, MUTED,
                Typeface.NORMAL), margins(matchWrap(), 0, 8, 0, 0));

        LinearLayout warning = column();
        warning.setPadding(dp(18), dp(17), dp(18), dp(17));
        warning.setBackground(roundRect(Color.rgb(38, 27, 20), 18, Color.rgb(100, 60, 29)));
        page.addView(warning, margins(matchWrap(), 0, 14, 0, 0));
        warning.addView(text("⚠  BEFORE YOU TAP", 12, ORANGE, Typeface.BOLD));
        TextView warningCopy = text(
                "Use only tags you own or are explicitly authorized to test. TapDance never "
                        + "writes tag memory, but a rejected authentication may advance a tag's "
                        + "configured attempt counter.", 15, TEXT, Typeface.NORMAL);
        warningCopy.setLineSpacing(dp(2), 1f);
        warning.addView(warningCopy, margins(matchWrap(), 0, 9, 0, 0));

        LinearLayout privacy = column();
        privacy.setPadding(dp(18), dp(17), dp(18), dp(17));
        privacy.setBackground(roundRect(PANEL, 18, Color.rgb(48, 48, 57)));
        page.addView(privacy, margins(matchWrap(), 0, 14, 0, 0));
        privacy.addView(text("LOCAL BY DESIGN", 12, GREEN, Typeface.BOLD));
        privacy.addView(text(
                "No Internet permission. No analytics. No automatic retries. No write commands. "
                        + "Diagnostic reports stay in memory unless you explicitly copy or share "
                        + "them.", 15, TEXT, Typeface.NORMAL),
                margins(matchWrap(), 0, 9, 0, 0));

        TextView footer = text("Open source · Independent · Not affiliated with NXP", 12, MUTED,
                Typeface.NORMAL);
        footer.setGravity(Gravity.CENTER);
        page.addView(footer, margins(matchWrap(), 0, 18, 0, 0));
        page.addView(new Space(this), new LinearLayout.LayoutParams(1, dp(8)));

        return scroll;
    }

    private void requestArm() {
        if (busy.get()) return;
        if (adapter == null || !adapter.isEnabled()) {
            renderState("NFC OFF", "Turn on NFC to begin",
                    "Enable NFC in Android settings, then return to TapDance.", ORANGE, "");
            return;
        }

        new AlertDialog.Builder(this)
                .setTitle("Submit exactly one key guess?")
                .setMessage(
                        "TapDance will test only the all-zero factory DataProtKey. It sends no "
                                + "memory-write command, but a failed authentication may consume "
                                + "one AUTH_LIM attempt. If the tag has one attempt remaining, "
                                + "protected data could become permanently locked.\n\nContinue only "
                                + "with a tag you own or are authorized to test.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("I understand — arm", (dialog, which) -> armConfirmed())
                .show();
    }

    private void armConfirmed() {
        if (busy.get() || adapter == null || !adapter.isEnabled()) return;
        setDiagnosticReport("");
        armedAttempt = attemptGeneration.incrementAndGet();
        armed.set(true);
        startReaderMode();
        armButton.setText("Cancel test");
        armButton.setOnClickListener(view -> disarm(true));
        renderState("ARMED", "Now tap the card",
                "Hold it against the back of your phone until TapDance reports a result. "
                        + "The test automatically disarms after one tag.", PURPLE, "");
        armButton.performHapticFeedback(HapticFeedbackConstants.CONTEXT_CLICK);
    }

    private void disarm(boolean render) {
        armed.set(false);
        attemptGeneration.incrementAndGet();
        stopReaderMode();
        if (armButton == null) return;
        runOnUiThread(() -> {
            armButton.setText("Arm one-shot test");
            armButton.setOnClickListener(view -> requestArm());
            if (render && !busy.get()) {
                renderState("READY", "Test cancelled",
                        "No memory-write command was sent. Arm the test whenever you're ready.",
                        PURPLE, "");
            }
        });
    }

    private void startReaderMode() {
        if (adapter == null) return;
        Bundle options = new Bundle();
        options.putInt(
                NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY,
                PRESENCE_CHECK_DELAY_MILLIS);
        adapter.enableReaderMode(
                this,
                this,
                NfcAdapter.FLAG_READER_NFC_A
                        | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
                        | NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                options);
    }

    private void stopReaderMode() {
        if (adapter != null) adapter.disableReaderMode(this);
    }

    private void renderState(
            String badge, String title, String detail, int accent, String technical) {
        stateBadge.setText(badge);
        stateBadge.setTextColor(accent);
        stateTitle.setText(title);
        stateDetail.setText(detail);
        technicalDetail.setText(technical);
        technicalDetail.setVisibility(technical.isEmpty() ? View.GONE : View.VISIBLE);
    }

    private void setDiagnosticReport(String report) {
        latestDiagnosticReport = report == null ? "" : report;
        if (diagnosticButton != null) {
            diagnosticButton.setVisibility(
                    latestDiagnosticReport.isEmpty() ? View.GONE : View.VISIBLE);
        }
    }

    private void showDiagnosticReport() {
        if (latestDiagnosticReport.isEmpty()) return;
        TextView reportView = text(latestDiagnosticReport, 12, TEXT, Typeface.NORMAL);
        reportView.setTypeface(Typeface.MONOSPACE);
        reportView.setTextIsSelectable(true);
        reportView.setPadding(dp(18), dp(12), dp(18), dp(12));

        ScrollView reportScroll = new ScrollView(this);
        reportScroll.addView(reportView, matchWrap());

        new AlertDialog.Builder(this)
                .setTitle("One-shot diagnostic report")
                .setMessage(
                        "Contains the tag UID, raw authentication frames, and device build "
                                + "details. Review it before copying or sharing.")
                .setView(reportScroll)
                .setNegativeButton("Close", null)
                .setNeutralButton("Copy", (dialog, which) -> confirmCopyDiagnosticReport())
                .setPositiveButton("Share…", (dialog, which) -> confirmShareDiagnosticReport())
                .show();
    }

    private void confirmCopyDiagnosticReport() {
        if (latestDiagnosticReport.isEmpty()) return;
        new AlertDialog.Builder(this)
                .setTitle("Copy NFC diagnostics?")
                .setMessage(
                        "This report contains the tag UID, raw authentication frames, and device "
                                + "build details. Your keyboard, clipboard history, or synced "
                                + "devices may retain it.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Copy report", (dialog, which) -> copyDiagnosticReport())
                .show();
    }

    private void copyDiagnosticReport() {
        ClipboardManager clipboard =
                (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
        if (clipboard == null || latestDiagnosticReport.isEmpty()) return;
        ClipData reportClip = ClipData.newPlainText(
                "TapDance diagnostic report", latestDiagnosticReport);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            PersistableBundle extras = new PersistableBundle();
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
            reportClip.getDescription().setExtras(extras);
        }
        clipboard.setPrimaryClip(reportClip);
        Toast.makeText(this, "Diagnostic report copied", Toast.LENGTH_SHORT).show();
    }

    private void confirmShareDiagnosticReport() {
        if (latestDiagnosticReport.isEmpty()) return;
        new AlertDialog.Builder(this)
                .setTitle("Share NFC diagnostics?")
                .setMessage(
                        "This report contains the tag UID, raw authentication frames, and device "
                                + "build details. The receiving app may transmit or retain it.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Choose app", (dialog, which) -> shareDiagnosticReport())
                .show();
    }

    private void shareDiagnosticReport() {
        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType("text/plain");
        send.putExtra(Intent.EXTRA_SUBJECT, "TapDance NFC diagnostic report");
        send.putExtra(Intent.EXTRA_TEXT, latestDiagnosticReport);
        startActivity(Intent.createChooser(send, "Share TapDance diagnostics"));
    }

    private LinearLayout column() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        return layout;
    }

    private TextView text(String value, int sp, int color, int style) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(sp);
        view.setTextColor(color);
        view.setTypeface(Typeface.DEFAULT, style);
        return view;
    }

    private GradientDrawable roundRect(int fill, int radiusDp, int stroke) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(radiusDp));
        drawable.setStroke(dp(1), stroke);
        return drawable;
    }

    private LinearLayout.LayoutParams matchWrap() {
        return new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private LinearLayout.LayoutParams margins(
            LinearLayout.LayoutParams params, int left, int top, int right, int bottom) {
        params.setMargins(dp(left), dp(top), dp(right), dp(bottom));
        return params;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
