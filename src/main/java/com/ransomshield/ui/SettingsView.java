package com.ransomshield.ui;

import com.ransomshield.RansomShieldEngine;
import com.ransomshield.model.MonitoringConfig;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.DirectoryChooser;

import java.io.File;

/**
 * Settings and threshold configuration screen for RansomShield.
 */
public class SettingsView extends BorderPane {

    private final MonitoringConfig config;

    private final TextField txtMonitoredDir = new TextField();
    private final TextField txtTestDir = new TextField();
    private final Spinner<Double> spinWindowSeconds = new Spinner<>(1.0, 30.0, 5.0, 0.5);

    private final Spinner<Double> spinEntropyLow = new Spinner<>(1.0, 8.0, 6.0, 0.1);
    private final Spinner<Double> spinEntropyMed = new Spinner<>(1.0, 8.0, 7.0, 0.1);
    private final Spinner<Double> spinEntropyHigh = new Spinner<>(1.0, 8.0, 7.5, 0.1);

    private final Spinner<Double> spinRateLow = new Spinner<>(0.5, 50.0, 2.0, 0.5);
    private final Spinner<Double> spinRateMed = new Spinner<>(1.0, 50.0, 5.0, 0.5);
    private final Spinner<Double> spinRateHigh = new Spinner<>(1.0, 100.0, 15.0, 1.0);

    private final Spinner<Integer> spinScoreSuspicious = new Spinner<>(10, 50, 30, 5);
    private final Spinner<Integer> spinScoreHigh = new Spinner<>(40, 80, 60, 5);
    private final Spinner<Integer> spinScoreCritical = new Spinner<>(60, 95, 80, 5);

    private final Label lblStatusFeedback = new Label();

    public SettingsView(RansomShieldEngine engine) {
        this(engine.getConfig());
    }

    public SettingsView(MonitoringConfig config) {
        this.config = config;
        setPadding(new Insets(16));
        setCenter(buildForm());
        loadValues();
    }

    private ScrollPane buildForm() {
        VBox container = new VBox(16);
        container.setPadding(new Insets(10));

        // Group 1: Directories
        VBox grpDirs = createGroup("MONITORING & SANDBOX DIRECTORIES");
        GridPane gridDirs = new GridPane();
        gridDirs.setHgap(10);
        gridDirs.setVgap(8);

        gridDirs.add(new Label("Default Monitored Directory:"), 0, 0);
        txtMonitoredDir.setPrefWidth(350);
        Button btnBrowseMon = new Button("Browse...");
        btnBrowseMon.setOnAction(e -> browseDirectory(txtMonitoredDir));
        HBox boxMon = new HBox(6, txtMonitoredDir, btnBrowseMon);
        gridDirs.add(boxMon, 1, 0);

        gridDirs.add(new Label("Safe Test Simulator Directory:"), 0, 1);
        txtTestDir.setPrefWidth(350);
        Button btnBrowseTest = new Button("Browse...");
        btnBrowseTest.setOnAction(e -> browseDirectory(txtTestDir));
        HBox boxTest = new HBox(6, txtTestDir, btnBrowseTest);
        gridDirs.add(boxTest, 1, 1);

        gridDirs.add(new Label("Sliding Window Duration (seconds):"), 0, 2);
        gridDirs.add(spinWindowSeconds, 1, 2);

        grpDirs.getChildren().add(gridDirs);

        // Group 2: Entropy Thresholds
        VBox grpEntropy = createGroup("SHANNON ENTROPY THRESHOLDS (BITS / BYTE, 0-8)");
        GridPane gridEntropy = new GridPane();
        gridEntropy.setHgap(10);
        gridEntropy.setVgap(8);
        gridEntropy.add(new Label("Low Elevation (5 pts):"), 0, 0);
        gridEntropy.add(spinEntropyLow, 1, 0);
        gridEntropy.add(new Label("High Elevation (10 pts):"), 0, 1);
        gridEntropy.add(spinEntropyMed, 1, 1);
        gridEntropy.add(new Label("Critical Spike (20 pts):"), 0, 2);
        gridEntropy.add(spinEntropyHigh, 1, 2);
        grpEntropy.getChildren().add(gridEntropy);

        // Group 3: Modification Rate Thresholds
        VBox grpRate = createGroup("BURST MODIFICATION RATE THRESHOLDS (FILES / SEC)");
        GridPane gridRate = new GridPane();
        gridRate.setHgap(10);
        gridRate.setVgap(8);
        gridRate.add(new Label("Noticeable Activity (5 pts):"), 0, 0);
        gridRate.add(spinRateLow, 1, 0);
        gridRate.add(new Label("Elevated Burst (10 pts):"), 0, 1);
        gridRate.add(spinRateMed, 1, 1);
        gridRate.add(new Label("Rapid Attack Speed (20 pts):"), 0, 2);
        gridRate.add(spinRateHigh, 1, 2);
        grpRate.getChildren().add(gridRate);

        // Group 4: Score Classification
        VBox grpScore = createGroup("THREAT SCORE CLASSIFICATION BOUNDARIES (0-100)");
        GridPane gridScore = new GridPane();
        gridScore.setHgap(10);
        gridScore.setVgap(8);
        gridScore.add(new Label("SUSPICIOUS Score Cutoff:"), 0, 0);
        gridScore.add(spinScoreSuspicious, 1, 0);
        gridScore.add(new Label("HIGH Score Cutoff:"), 0, 1);
        gridScore.add(spinScoreHigh, 1, 1);
        gridScore.add(new Label("CRITICAL Score Cutoff:"), 0, 2);
        gridScore.add(spinScoreCritical, 1, 2);
        grpScore.getChildren().add(gridScore);

        // Save Button & Feedback
        HBox actionBox = new HBox(12);
        actionBox.setAlignment(Pos.CENTER_LEFT);

        Button btnSave = new Button("Apply & Save Settings");
        btnSave.getStyleClass().add("btn-primary");
        btnSave.setOnAction(e -> saveSettings());

        lblStatusFeedback.setStyle("-fx-text-fill: #10b981; -fx-font-weight: bold;");

        actionBox.getChildren().addAll(btnSave, lblStatusFeedback);

        container.getChildren().addAll(grpDirs, grpEntropy, grpRate, grpScore, actionBox);

        ScrollPane scroll = new ScrollPane(container);
        scroll.setFitToWidth(true);
        scroll.setStyle("-fx-background: transparent; -fx-background-color: transparent;");
        return scroll;
    }

    private VBox createGroup(String title) {
        VBox group = new VBox(10);
        group.getStyleClass().add("kpi-card");
        Label lbl = new Label(title);
        lbl.getStyleClass().add("kpi-title");
        group.getChildren().add(lbl);
        return group;
    }

    private void browseDirectory(TextField targetField) {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Select Directory");
        File dir = chooser.showDialog(getScene().getWindow());
        if (dir != null) {
            targetField.setText(dir.getAbsolutePath());
        }
    }

    private void loadValues() {
        txtMonitoredDir.setText(config.getMonitoredDirectory());
        txtTestDir.setText(config.getTestDirectory());
        spinWindowSeconds.getValueFactory().setValue(config.getAnalysisWindowSeconds());

        spinEntropyLow.getValueFactory().setValue(config.getEntropyLow());
        spinEntropyMed.getValueFactory().setValue(config.getEntropyMedium());
        spinEntropyHigh.getValueFactory().setValue(config.getEntropyHigh());

        spinRateLow.getValueFactory().setValue(config.getRateLow());
        spinRateMed.getValueFactory().setValue(config.getRateMedium());
        spinRateHigh.getValueFactory().setValue(config.getRateHigh());

        spinScoreSuspicious.getValueFactory().setValue(config.getScoreSuspicious());
        spinScoreHigh.getValueFactory().setValue(config.getScoreHigh());
        spinScoreCritical.getValueFactory().setValue(config.getScoreCritical());
    }

    private void saveSettings() {
        config.setMonitoredDirectory(txtMonitoredDir.getText().trim());
        config.setTestDirectory(txtTestDir.getText().trim());
        config.setAnalysisWindowSeconds(spinWindowSeconds.getValue());

        config.setEntropyLow(spinEntropyLow.getValue());
        config.setEntropyMedium(spinEntropyMed.getValue());
        config.setEntropyHigh(spinEntropyHigh.getValue());

        config.setRateLow(spinRateLow.getValue());
        config.setRateMedium(spinRateMed.getValue());
        config.setRateHigh(spinRateHigh.getValue());

        config.setScoreSuspicious(spinScoreSuspicious.getValue());
        config.setScoreHigh(spinScoreHigh.getValue());
        config.setScoreCritical(spinScoreCritical.getValue());

        lblStatusFeedback.setText("Settings applied successfully.");
    }
}
