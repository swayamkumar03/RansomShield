package com.ransomshield.ui;

import com.ransomshield.RansomShieldEngine;
import com.ransomshield.simulator.RansomwareSimulator;
import com.ransomshield.simulator.SimulationMode;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;

import java.nio.file.Path;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.CompletableFuture;

/**
 * Control panel for safe, sandboxed simulation testing.
 * Strictly operates only within the designated RansomShield test directory.
 */
public class SimulatorControlView extends BorderPane {

    private final RansomShieldEngine engine;
    private final ComboBox<SimulationMode> comboMode = new ComboBox<>();
    private final Label lblModeDescription = new Label();
    private final Label lblTestPath = new Label();
    private final TextArea logConsole = new TextArea();
    private final ProgressIndicator progressIndicator = new ProgressIndicator();
    private final Button btnRun = new Button("Run Selected Simulation");
    private final Button btnReset = new Button("Clear & Reset Test Data");

    private RansomwareSimulator simulator;

    public SimulatorControlView(RansomShieldEngine engine) {
        this.engine = engine;
        initializeSimulator();
        setPadding(new Insets(16));
        setTop(buildHeaderAndSafetyBanner());
        setCenter(buildControlBody());
    }

    private void initializeSimulator() {
        try {
            Path testDir = engine.getConfig().getTestDirectoryPath();
            this.simulator = new RansomwareSimulator(testDir);
            this.simulator.ensureTestDataset();
        } catch (Exception e) {
            log("Error initializing test simulator: " + e.getMessage());
        }
    }

    private VBox buildHeaderAndSafetyBanner() {
        VBox topBox = new VBox(10);
        topBox.setPadding(new Insets(0, 0, 16, 0));

        // Safety Notice Banner
        VBox safetyBanner = new VBox(4);
        safetyBanner.setStyle("-fx-background-color: rgba(6, 182, 212, 0.15); -fx-border-color: #0891b2; " +
                "-fx-border-radius: 8px; -fx-background-radius: 8px; -fx-padding: 12px 16px;");

        Label lblSafeTitle = new Label("CONTROLLED DEFENSIVE TEST HARNESS (SAFE SANDBOX)");
        lblSafeTitle.setStyle("-fx-font-weight: bold; -fx-font-size: 13px; -fx-text-fill: #38bdf8;");

        Label lblSafeSub = new Label("Strictly operates ONLY inside the designated RansomShield test directory. " +
                "Never executes external shell commands, never contacts the network, and never modifies files outside the test boundary.");
        lblSafeSub.setStyle("-fx-font-size: 11px; -fx-text-fill: #cbd5e1;");

        safetyBanner.getChildren().addAll(lblSafeTitle, lblSafeSub);

        // Path indicator card
        HBox pathCard = new HBox(12);
        pathCard.setAlignment(Pos.CENTER_LEFT);
        pathCard.getStyleClass().add("kpi-card");
        pathCard.setStyle("-fx-padding: 10px 14px;");

        Label lblPathTitle = new Label("TARGET TEST DIRECTORY:");
        lblPathTitle.setStyle("-fx-font-weight: bold; -fx-text-fill: #94a3b8; -fx-font-size: 11px;");

        lblTestPath.setText(engine.getConfig().getTestDirectoryPath().toString());
        lblTestPath.setStyle("-fx-font-weight: bold; -fx-text-fill: #10b981; -fx-font-size: 12px;");

        pathCard.getChildren().addAll(lblPathTitle, lblTestPath);

        topBox.getChildren().addAll(safetyBanner, pathCard);
        return topBox;
    }

    private VBox buildControlBody() {
        VBox body = new VBox(14);

        // Simulation Mode Selection Card
        VBox selectionCard = new VBox(10);
        selectionCard.getStyleClass().add("kpi-card");

        Label lblSelectTitle = new Label("SELECT SIMULATION SCENARIO");
        lblSelectTitle.getStyleClass().add("kpi-title");

        comboMode.getItems().addAll(SimulationMode.values());
        comboMode.setValue(SimulationMode.COMBINED_RANSOMWARE_SIMULATION);
        comboMode.setPrefWidth(420);
        comboMode.setOnAction(e -> updateModeDescription());

        lblModeDescription.setStyle("-fx-font-size: 12px; -fx-text-fill: #94a3b8;");
        lblModeDescription.setWrapText(true);
        updateModeDescription();

        // Buttons
        HBox buttonBox = new HBox(12);
        buttonBox.setAlignment(Pos.CENTER_LEFT);

        btnRun.getStyleClass().add("btn-danger");
        btnRun.setOnAction(e -> confirmAndRunSimulation());

        btnReset.getStyleClass().add("btn-secondary");
        btnReset.setOnAction(e -> handleResetTestData());

        progressIndicator.setVisible(false);
        progressIndicator.setPrefSize(24, 24);

        buttonBox.getChildren().addAll(btnRun, btnReset, progressIndicator);
        selectionCard.getChildren().addAll(lblSelectTitle, comboMode, lblModeDescription, buttonBox);

        // Live Log Output
        VBox logBox = new VBox(8);
        Label lblLogTitle = new Label("SIMULATOR ACTIVITY AUDIT LOG");
        lblLogTitle.setStyle("-fx-font-weight: bold; -fx-font-size: 11px; -fx-text-fill: #94a3b8;");

        logConsole.setEditable(false);
        logConsole.getStyleClass().add("log-console");
        logConsole.setPrefHeight(220);
        VBox.setVgrow(logConsole, Priority.ALWAYS);

        logBox.getChildren().addAll(lblLogTitle, logConsole);
        VBox.setVgrow(logBox, Priority.ALWAYS);

        body.getChildren().addAll(selectionCard, logBox);
        return body;
    }

    private void updateModeDescription() {
        SimulationMode mode = comboMode.getValue();
        if (mode != null) {
            lblModeDescription.setText(mode.getDescription());
        }
    }

    private void confirmAndRunSimulation() {
        SimulationMode mode = comboMode.getValue();
        if (mode == null) return;

        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
        confirm.setTitle("Confirm Safe Simulation Execution");
        confirm.setHeaderText("Execute " + mode.getTitle() + "?");
        confirm.setContentText("The simulation will run strictly inside:\n" +
                engine.getConfig().getTestDirectoryPath() + "\n\nProceed with simulation?");

        confirm.showAndWait().ifPresent(res -> {
            if (res == ButtonType.OK) {
                executeSimulation(mode);
            }
        });
    }

    private void executeSimulation(SimulationMode mode) {
        setBusy(true);
        log("Executing " + mode.getTitle() + "...");

        CompletableFuture.runAsync(() -> {
            try {
                if (simulator == null) {
                    initializeSimulator();
                }
                simulator.runSimulation(mode);
                Platform.runLater(() -> log("Completed " + mode.getTitle() + " successfully."));
            } catch (Exception ex) {
                Platform.runLater(() -> log("Simulation error: " + ex.getMessage()));
            } finally {
                Platform.runLater(() -> setBusy(false));
            }
        });
    }

    private void handleResetTestData() {
        setBusy(true);
        log("Resetting test data directory...");

        CompletableFuture.runAsync(() -> {
            try {
                if (simulator == null) {
                    initializeSimulator();
                }
                simulator.resetTestData();
                Platform.runLater(() -> log("Reset complete: 100 fresh test files populated across 4 directories."));
            } catch (Exception ex) {
                Platform.runLater(() -> log("Reset error: " + ex.getMessage()));
            } finally {
                Platform.runLater(() -> setBusy(false));
            }
        });
    }

    private void setBusy(boolean busy) {
        btnRun.setDisable(busy);
        btnReset.setDisable(busy);
        comboMode.setDisable(busy);
        progressIndicator.setVisible(busy);
    }

    private void log(String message) {
        String time = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        logConsole.appendText(String.format("[%s] %s\n", time, message));
    }
}
