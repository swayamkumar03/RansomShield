package com.ransomshield.ui;

import com.ransomshield.RansomShieldEngine;
import com.ransomshield.database.IncidentRepository;
import com.ransomshield.defense.ResponseResult;
import com.ransomshield.model.Incident;
import com.ransomshield.model.IncidentStatus;
import com.ransomshield.model.ThreatLevel;
import com.ransomshield.util.TimeUtils;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * Incident history management screen providing querying, severity filtering,
 * lifecycle status management (Acknowledge/Resolve/Contain), and detailed incident auditing.
 */
public class IncidentHistoryView extends BorderPane {

    private final RansomShieldEngine engine;
    private final IncidentRepository repository;
    private final ObservableList<Incident> incidentList = FXCollections.observableArrayList();
    private final TableView<Incident> incidentTable = new TableView<>();
    private final ComboBox<String> filterSeverity = new ComboBox<>();

    public IncidentHistoryView(RansomShieldEngine engine) {
        this.engine = engine;
        this.repository = engine != null ? engine.getIncidentRepository() : null;
        setPadding(new Insets(16));
        setTop(buildToolbar());
        setCenter(buildTable());
        refreshIncidents();
    }

    public IncidentHistoryView(IncidentRepository repository) {
        this.engine = null;
        this.repository = repository;
        setPadding(new Insets(16));
        setTop(buildToolbar());
        setCenter(buildTable());
        refreshIncidents();
    }

    private HBox buildToolbar() {
        HBox toolbar = new HBox(12);
        toolbar.setAlignment(Pos.CENTER_LEFT);
        toolbar.setPadding(new Insets(0, 0, 14, 0));

        Label lblFilter = new Label("Filter by Severity:");
        lblFilter.setStyle("-fx-text-fill: #94a3b8; -fx-font-weight: bold;");

        filterSeverity.getItems().addAll("ALL", "CRITICAL", "HIGH", "SUSPICIOUS", "NORMAL");
        filterSeverity.setValue("ALL");
        filterSeverity.setOnAction(e -> applyFilter());

        Button btnRefresh = new Button("Refresh");
        btnRefresh.getStyleClass().add("btn-secondary");
        btnRefresh.setOnAction(e -> refreshIncidents());

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Button btnSimulate = new Button("Simulate Containment");
        btnSimulate.getStyleClass().add("btn-primary");
        btnSimulate.setOnAction(e -> handleSimulateContainment());

        Button btnAcknowledge = new Button("Acknowledge");
        btnAcknowledge.getStyleClass().add("btn-secondary");
        btnAcknowledge.setOnAction(e -> updateSelectedStatus(IncidentStatus.ACKNOWLEDGED));

        Button btnResolve = new Button("Mark Resolved");
        btnResolve.getStyleClass().add("btn-success");
        btnResolve.setOnAction(e -> updateSelectedStatus(IncidentStatus.RESOLVED));

        Button btnDetails = new Button("View Details");
        btnDetails.getStyleClass().add("btn-secondary");
        btnDetails.setOnAction(e -> showDetailsModal());

        toolbar.getChildren().addAll(lblFilter, filterSeverity, btnRefresh, spacer, btnSimulate, btnAcknowledge, btnResolve, btnDetails);
        return toolbar;
    }

    private VBox buildTable() {
        VBox box = new VBox(10);
        incidentTable.setItems(incidentList);
        incidentTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_ALL_COLUMNS);

        // ID
        TableColumn<Incident, String> colId = new TableColumn<>("INCIDENT ID");
        colId.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getId().substring(0, Math.min(8, d.getValue().getId().length()))));
        colId.setPrefWidth(85);

        // Timestamp
        TableColumn<Incident, String> colTime = new TableColumn<>("DETECTED AT");
        colTime.setCellValueFactory(d -> new SimpleStringProperty(TimeUtils.formatFull(d.getValue().getTimestamp())));
        colTime.setPrefWidth(135);

        // Severity
        TableColumn<Incident, String> colSev = new TableColumn<>("SEVERITY");
        colSev.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getSeverity().name()));
        colSev.setPrefWidth(95);
        colSev.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    setGraphic(null);
                } else {
                    Label badge = new Label(item);
                    badge.getStyleClass().add("badge");
                    try {
                        ThreatLevel tl = ThreatLevel.valueOf(item);
                        badge.getStyleClass().add(tl.getStyleClass());
                    } catch (Exception ignored) {}
                    setGraphic(badge);
                    setAlignment(Pos.CENTER);
                }
            }
        });

        // Score
        TableColumn<Incident, String> colScore = new TableColumn<>("SCORE");
        colScore.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getScore() + "/100"));
        colScore.setPrefWidth(65);

        // Files
        TableColumn<Incident, String> colFiles = new TableColumn<>("FILES");
        colFiles.setCellValueFactory(d -> new SimpleStringProperty(String.valueOf(d.getValue().getFilesAffected())));
        colFiles.setPrefWidth(55);

        // Dirs
        TableColumn<Incident, String> colDirs = new TableColumn<>("DIRS");
        colDirs.setCellValueFactory(d -> new SimpleStringProperty(String.valueOf(d.getValue().getDirectoriesAffected())));
        colDirs.setPrefWidth(50);

        // Rate
        TableColumn<Incident, String> colRate = new TableColumn<>("RATE");
        colRate.setCellValueFactory(d -> new SimpleStringProperty(String.format("%.1f/s", d.getValue().getModificationRate())));
        colRate.setPrefWidth(65);

        // Max Entropy
        TableColumn<Incident, String> colEntropy = new TableColumn<>("MAX ENTROPY");
        colEntropy.setCellValueFactory(d -> new SimpleStringProperty(String.format("%.2f bits", d.getValue().getMaxEntropy())));
        colEntropy.setPrefWidth(90);

        // Status
        TableColumn<Incident, String> colStatus = new TableColumn<>("STATUS");
        colStatus.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getStatus().name()));
        colStatus.setPrefWidth(110);
        colStatus.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setText(null);
                    setGraphic(null);
                } else {
                    Label badge = new Label(item);
                    badge.getStyleClass().add("badge");
                    if ("RESOLVED".equalsIgnoreCase(item)) {
                        badge.setStyle("-fx-background-color: rgba(16, 185, 129, 0.2); -fx-text-fill: #10b981; -fx-border-color: #10b981;");
                    } else if ("CONTAINED".equalsIgnoreCase(item)) {
                        badge.setStyle("-fx-background-color: rgba(139, 92, 246, 0.2); -fx-text-fill: #a78bfa; -fx-border-color: #8b5cf6;");
                    } else if ("ACKNOWLEDGED".equalsIgnoreCase(item)) {
                        badge.setStyle("-fx-background-color: rgba(245, 158, 11, 0.2); -fx-text-fill: #f59e0b; -fx-border-color: #f59e0b;");
                    } else if ("CONTAINMENT_REQUESTED".equalsIgnoreCase(item)) {
                        badge.setStyle("-fx-background-color: rgba(56, 189, 248, 0.2); -fx-text-fill: #38bdf8; -fx-border-color: #0284c7;");
                    } else if ("FAILED".equalsIgnoreCase(item)) {
                        badge.setStyle("-fx-background-color: rgba(220, 38, 38, 0.2); -fx-text-fill: #f87171; -fx-border-color: #dc2626;");
                    } else {
                        badge.setStyle("-fx-background-color: rgba(239, 68, 68, 0.2); -fx-text-fill: #ef4444; -fx-border-color: #ef4444;");
                    }
                    setGraphic(badge);
                    setAlignment(Pos.CENTER);
                }
            }
        });

        // Response Action
        TableColumn<Incident, String> colAction = new TableColumn<>("RESPONSE ACTION");
        colAction.setCellValueFactory(d -> {
            String act = d.getValue().getResponseAction();
            if (d.getValue().isSimulated() && !"NONE".equalsIgnoreCase(act)) {
                act += " [SIM]";
            }
            return new SimpleStringProperty(act);
        });
        colAction.setPrefWidth(125);

        // Summary
        TableColumn<Incident, String> colSummary = new TableColumn<>("SUMMARY / REASONS");
        colSummary.setCellValueFactory(d -> new SimpleStringProperty(d.getValue().getOperationSummary()));
        colSummary.setPrefWidth(200);

        incidentTable.getColumns().addAll(List.of(colId, colTime, colSev, colScore, colFiles, colDirs, colRate, colEntropy, colStatus, colAction, colSummary));

        // Double click row to open details
        incidentTable.setRowFactory(tv -> {
            TableRow<Incident> row = new TableRow<>();
            row.setOnMouseClicked(event -> {
                if (event.getClickCount() == 2 && (!row.isEmpty())) {
                    showDetailsModal();
                }
            });
            return row;
        });

        VBox.setVgrow(incidentTable, Priority.ALWAYS);
        box.getChildren().add(incidentTable);
        return box;
    }

    public void refreshIncidents() {
        if (repository == null) return;
        applyFilter();
    }

    private void applyFilter() {
        if (repository == null) return;
        String val = filterSeverity.getValue();
        List<Incident> results;
        if (val == null || "ALL".equalsIgnoreCase(val)) {
            results = repository.findAll();
        } else {
            try {
                ThreatLevel level = ThreatLevel.valueOf(val);
                results = repository.findBySeverity(level);
            } catch (Exception e) {
                results = repository.findAll();
            }
        }
        incidentList.setAll(results);
    }

    private void updateSelectedStatus(IncidentStatus newStatus) {
        Incident selected = incidentTable.getSelectionModel().getSelectedItem();
        if (selected == null) {
            showAlert("No Selection", "Please select an incident from the table first.");
            return;
        }

        if (repository != null) {
            selected.setStatus(newStatus);
            repository.save(selected);
            refreshIncidents();
        }
    }

    private void handleSimulateContainment() {
        Incident selected = incidentTable.getSelectionModel().getSelectedItem();
        if (selected == null) {
            showAlert("No Selection", "Please select an incident from the table to simulate containment.");
            return;
        }
        if (engine == null || engine.getDefenseManager() == null) {
            showAlert("Defense Unavailable", "DefenseManager is not initialized.");
            return;
        }

        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
        confirm.setTitle("Simulate Containment");
        confirm.setHeaderText("Simulate Containment for Incident " + selected.getId().substring(0, Math.min(8, selected.getId().length())));
        confirm.setContentText("Execute safe simulated containment for this historical incident?\n\nZero files or processes will be modified.");

        Optional<ButtonType> choice = confirm.showAndWait();
        if (choice.isPresent() && choice.get() == ButtonType.OK) {
            ResponseResult res = engine.getDefenseManager().simulateContainment(selected);
            refreshIncidents();
            showAlert("Containment Executed", res.getMessage());
        }
    }

    private void showDetailsModal() {
        Incident selected = incidentTable.getSelectionModel().getSelectedItem();
        if (selected == null) {
            showAlert("No Selection", "Please select an incident from the table first.");
            return;
        }

        Dialog<Void> dialog = new Dialog<>();
        dialog.setTitle("Incident Audit Report – " + selected.getId());
        dialog.setHeaderText("RansomShield Incident Forensic Audit Report");

        VBox content = new VBox(12);
        content.setPadding(new Insets(16));
        content.setPrefWidth(580);

        GridPane grid = new GridPane();
        grid.setHgap(14);
        grid.setVgap(8);

        grid.add(createHeaderLabel("Incident ID:"), 0, 0);
        grid.add(new Label(selected.getId()), 1, 0);

        grid.add(createHeaderLabel("First / Last Seen:"), 0, 1);
        grid.add(new Label(TimeUtils.formatFull(selected.getFirstSeen()) + " — " + TimeUtils.formatFull(selected.getLastSeen())), 1, 1);

        grid.add(createHeaderLabel("Severity & Score:"), 0, 2);
        grid.add(new Label(selected.getSeverity().name() + " (" + selected.getScore() + "/100)"), 1, 2);

        grid.add(createHeaderLabel("Root Directory:"), 0, 3);
        grid.add(new Label(selected.getRootDirectory()), 1, 3);

        grid.add(createHeaderLabel("Scope & Volume:"), 0, 4);
        grid.add(new Label(selected.getFilesAffected() + " files affected across " + selected.getDirectoriesAffected() + " directories"), 1, 4);

        grid.add(createHeaderLabel("Burst Modification Rate:"), 0, 5);
        grid.add(new Label(String.format("%.2f files/sec", selected.getModificationRate())), 1, 5);

        grid.add(createHeaderLabel("Entropy Statistics:"), 0, 6);
        grid.add(new Label(String.format("Avg: %.2f bits  |  Max: %.2f bits",
                selected.getAverageEntropy(), selected.getMaxEntropy())), 1, 6);

        grid.add(createHeaderLabel("Incident Status:"), 0, 7);
        grid.add(new Label(selected.getStatus().name()), 1, 7);

        grid.add(createHeaderLabel("Response Action:"), 0, 8);
        grid.add(new Label(selected.getResponseAction() + (selected.isSimulated() ? " [SIMULATED]" : " [REAL]")), 1, 8);

        if (selected.getResponseResult() != null && !selected.getResponseResult().isBlank()) {
            grid.add(createHeaderLabel("Response Result:"), 0, 9);
            Label lblRes = new Label(selected.getResponseResult());
            lblRes.setWrapText(true);
            grid.add(lblRes, 1, 9);
        }

        Label lblReasons = createHeaderLabel("Behavioral Trigger Reasons:");
        ListView<String> lvReasons = new ListView<>();
        lvReasons.setPrefHeight(80);
        lvReasons.getItems().addAll(selected.getReasons());

        Label lblPaths = createHeaderLabel("Tracked Affected Paths (" + selected.getAffectedPaths().size() + "):");
        ListView<String> lvPaths = new ListView<>();
        lvPaths.setPrefHeight(90);
        lvPaths.getItems().addAll(selected.getAffectedPaths());

        content.getChildren().addAll(grid, new Separator(), lblReasons, lvReasons, lblPaths, lvPaths);
        dialog.getDialogPane().setContent(content);
        dialog.getDialogPane().getButtonTypes().add(ButtonType.CLOSE);
        dialog.showAndWait();
    }

    private Label createHeaderLabel(String text) {
        Label lbl = new Label(text);
        lbl.setStyle("-fx-font-weight: bold; -fx-text-fill: #94a3b8;");
        return lbl;
    }

    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }
}
