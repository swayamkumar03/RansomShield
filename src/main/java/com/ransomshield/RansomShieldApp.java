package com.ransomshield;

import com.ransomshield.model.MonitoringConfig;
import com.ransomshield.ui.MainView;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;

/**
 * JavaFX Application entry point for the RansomShield behavioral cybersecurity platform.
 */
public class RansomShieldApp extends Application {
    private static final Logger logger = LoggerFactory.getLogger(RansomShieldApp.class);

    private RansomShieldEngine engine;

    @Override
    public void start(Stage primaryStage) {
        logger.info("Initializing RansomShield Application UI...");

        MonitoringConfig config = new MonitoringConfig();
        this.engine = new RansomShieldEngine(config);

        MainView mainView = new MainView(engine, primaryStage);
        Scene scene = new Scene(mainView, 1220, 800);

        // Attach modern dark cybersecurity stylesheet
        URL cssResource = getClass().getResource("/styles/application.css");
        if (cssResource != null) {
            scene.getStylesheets().add(cssResource.toExternalForm());
        } else {
            logger.warn("Stylesheet application.css could not be located");
        }

        primaryStage.setTitle("RansomShield – Real-Time Behavioral Ransomware Detection System");
        primaryStage.setMinWidth(1000);
        primaryStage.setMinHeight(700);
        primaryStage.setScene(scene);

        primaryStage.setOnCloseRequest(e -> {
            logger.info("Shutting down RansomShield engine and releasing resources...");
            engine.shutdown();
            Platform.exit();
            System.exit(0);
        });

        primaryStage.show();
        logger.info("RansomShield UI started successfully");
    }

    @Override
    public void stop() {
        if (engine != null) {
            engine.shutdown();
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}
