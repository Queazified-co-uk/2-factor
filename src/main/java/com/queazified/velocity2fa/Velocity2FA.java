package com.queazified.velocity2fa;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.command.CommandManager;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Plugin(
    id = "velocity2fa",
    name = "Velocity2FA",
    version = "1.0.0",
    description = "Two-Factor Authentication for staff members",
    authors = {"YourName"}
)
public class Velocity2FA {

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;
    
    private TwoFactorManager twoFactorManager;
    private ConfigManager configManager;
    private final Set<String> authenticatedPlayers = ConcurrentHashMap.newKeySet();
    private final Set<String> pendingAuthentication = ConcurrentHashMap.newKeySet();

    @Inject
    public Velocity2FA(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onProxyInitialization(ProxyInitializeEvent event) {
        logger.info("Velocity2FA is starting up...");
        
        // Initialize managers
        this.configManager = new ConfigManager(dataDirectory);
        this.twoFactorManager = new TwoFactorManager(dataDirectory, logger);
        
        // Register commands
        CommandManager commandManager = server.getCommandManager();
        commandManager.register("2fa", new TwoFactorCommand(this));
        commandManager.register("2fa-admin", new AdminCommand(this));
        
        logger.info("Velocity2FA has been enabled successfully!");
    }

    @Subscribe
    public void onPostLogin(PostLoginEvent event) {
        Player player = event.getPlayer();
        
        // Check if player has staff permission and 2FA enabled
        if (hasStaffPermission(player) && twoFactorManager.hasSecretKey(player.getUniqueId())) {
            pendingAuthentication.add(player.getUsername());
            
            player.sendMessage(Component.text("=== 2FA AUTHENTICATION REQUIRED ===")
                .color(NamedTextColor.RED));
            player.sendMessage(Component.text("Please enter your 2FA code using: /2fa <code>")
                .color(NamedTextColor.YELLOW));
            player.sendMessage(Component.text("You cannot join servers until authenticated.")
                .color(NamedTextColor.RED));
        }
    }

    @Subscribe
    public void onServerPreConnect(ServerPreConnectEvent event) {
        Player player = event.getPlayer();
        
        // Block server connections if staff member hasn't authenticated with 2FA
        if (hasStaffPermission(player) && 
            twoFactorManager.hasSecretKey(player.getUniqueId()) && 
            !authenticatedPlayers.contains(player.getUsername())) {
            
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
            player.sendMessage(Component.text("You must authenticate with 2FA first! Use /2fa <code>")
                .color(NamedTextColor.RED));
        }
    }

    private boolean hasStaffPermission(Player player) {
        // Check for any staff permission - you can customize this logic
        return player.hasPermission("staff") || 
               player.hasPermission("moderator") || 
               player.hasPermission("admin") ||
               player.hasPermission("helper") ||
               player.hasPermission("velocity2fa.staff");
    }

    // Getters for other classes
    public ProxyServer getServer() { return server; }
    public Logger getLogger() { return logger; }
    public Path getDataDirectory() { return dataDirectory; }
    public TwoFactorManager getTwoFactorManager() { return twoFactorManager; }
    public ConfigManager getConfigManager() { return configManager; }
    public Set<String> getAuthenticatedPlayers() { return authenticatedPlayers; }
    public Set<String> getPendingAuthentication() { return pendingAuthentication; }
}
