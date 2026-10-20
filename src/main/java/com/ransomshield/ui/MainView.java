package com.ransomshield.ui;

import com.ransomshield.RansomShieldEngine;
import com.ransomshield.alert.AlertListener;
import com.ransomshield.model.FileEvent;
import com.ransomshield.model.Incident;
import com.ransomshield.model.ThreatAssessment;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Main application window for RansomShield assembling the header status bar,
 * live control buttons, and multi-tabbed security workbench.
 */
public class MainView extends BorderPane implements AlertListener {

    private final RansomShieldEngine engine;
    private final Stage stage;

    private final Label lblStatus = new Label("MONITORING: STOPPED");
    private final Label lblMonitoredPath = new Label();
    private final Button btnStart = new Button("Start Monitoring");
    private final Button btnStop = new Button("Stop Monitoring");
    private final Button btnSelectDir = new Button("Select Directory");

    private DashboardView dashboardView;
    private IncidentHistoryView incidentHistoryView;
    private SimulatorControlView simulatorView;
    private SettingsView settingsView;

    public MainView(RansomShieldEngine engine, Stage stage) {
        this.engine = engine;
        this.stage = stage;

        this.dashboardView = new DashboardView(engine);
        this.incidentHistoryView = new IncidentHistoryView(engine);
        this.simulatorView = new SimulatorControlView(engine);
        this.settingsView = new SettingsView(engine);

        engine.getAlertManager().addListener(this);

        setTop(buildHeader());
        setCenter(buildTabs());
    }

    private VBox buildHeader() {
        VBox headerContainer = new VBox();
        headerContainer.getStyleClass().add("app-header");

        HBox topRow = new HBox(16);
        topRow.setAlignment(Pos.CENTER_LEFT);

        // Title and Subtitle
        VBox titleBox = new VBox(2);
        Label title = new Label("RANSOMSHIELD");
        title.getStyleClass().add("header-title");

        Label subtitle = new Label("Real-Time Behavioral Ransomware Detection using Shannon Entropy & Anomaly Scoring");
        subtitle.getStyleClass().add("header-subtitle");
        titleBox.getChildren().addAll(title, subtitle);

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        // Status pill
        lblStatus.getStyleClass().addAll("status-pill", "status-stopped");

        // Action Buttons
        btnSelectDir.getStyleClass().add("btn-secondary");
        btnSelectDir.setOnAction(e -> handleSelectDirectory());

        btnStart.getStyleClass().add("btn-success");
        btnStart.setOnAction(e -> handleStartMonitoring());

        btnStop.getStyleClass().add("btn-danger");
        btnStop.setDisable(true);
        btnStop.setOnAction(e -> handleStopMonitoring());

        topRow.getChildren().addAll(titleBox, spacer, lblStatus, btnSelectDir, btnStart, btnStop);

        // Bottom sub-row: Path display
        HBox pathRow = new HBox(8);
        pathRow.setAlignment(Pos.CENTER_LEFT);
        pathRow.setPadding(new Insets(8, 0, 0, 0));

        Label lblPathPrefix = new Label("Monitored Path:");
        lblPathPrefix.setStyle("-fx-text-fill: #94a3b8; -fx-font-weight: bold; -fx-font-size: 11px;");

        lblMonitoredPath.setText(engine.getConfig().getMonitoredDirectoryPath().toString());
        lblMonitoredPath.setStyle("-fx-text-fill: #38bdf8; -fx-font-size: 11px;");

        pathRow.getChildren().addAll(lblPathPrefix, lblMonitoredPath);

        headerContainer.getChildren().addAll(topRow, pathRow);
        return headerContainer;
    }

    private TabPane buildTabs() {
        TabPane tabPane = new TabPane();
        tabPane.getStyleClass().add("tab-pane");

        Tab tabDashboard = new Tab("Live Threat Monitor", dashboardView);
        tabDashboard.setClosable(false);

        Tab tabIncidents = new Tab("Incident History", incidentHistoryView);
        tabIncidents.setClosable(false);

        Tab tabSimulator = new Tab("Safe Test Simulator", simulatorView);
        tabSimulator.setClosable(false);

        Tab tabSettings = new Tab("Settings & Thresholds", settingsView);
        tabSettings.setClosable(false);

        tabPane.getTabs().addAll(tabDashboard, tabIncidents, tabSimulator, tabSettings);
        return tabPane;
    }

    private void handleSelectDirectory() {
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Select Root Directory to Monitor");
        File current = engine.getConfig().getMonitoredDirectoryPath().toFile();
        if (current.exists()) {
            chooser.setInitialDirectory(current);
        }
        File selected = chooser.showDialog(stage);
        if (selected != null) {
            engine.getConfig().setMonitoredDirectory(selected.getAbsolutePath());
            lblMonitoredPath.setText(selected.getAbsolutePath());
        }
    }

    private void handleStartMonitoring() {
        try {
            Path path = engine.getConfig().getMonitoredDirectoryPath();
            if (!Files.exists(path)) {
                Files.createDirectories(path);
            }

            engine.startMonitoring(path);

            lblStatus.setText("MONITORING: RUNNING");
            lblStatus.getStyleClass().removeAll("status-stopped");
            lblStatus.getStyleClass().add("status-running");

            btnStart.setDisable(true);
            btnStop.setDisable(false);
            btnSelectDir.setDisable(true);

        } catch (Exception e) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Monitoring Error");
            alert.setHeaderText("Failed to Start Monitoring");
            alert.setContentText(e.getMessage());
            alert.showAndWait();
        }
    }

    private void handleStopMonitoring() {
        engine.stopMonitoring();

        lblStatus.setText("MONITORING: STOPPED");
        lblStatus.getStyleClass().removeAll("status-running");
        lblStatus.getStyleClass().add("status-stopped");

        btnStart.setDisable(false);
        btnStop.setDisable(true);
        btnSelectDir.setDisable(false);
    }

    @Override
    public void onThreatAssessed(ThreatAssessment assessment) {
        dashboardView.updateAssessment(assessment);
    }

    @Override
    public void onIncidentRaised(Incident incident) {
        Platform.runLater(() -> incidentHistoryView.refreshIncidents());
    }

    @Override
    public void onEventProcessed(FileEvent event) {
        dashboardView.addEvent(event);
    }

    public DashboardView getDashboardView() {
        return dashboardView;
    }

    public IncidentHistoryView getIncidentHistoryView() {
        return incidentHistoryView;
    }

    public SimulatorControlView getSimulatorView() {
        return simulatorView;
    }
}
