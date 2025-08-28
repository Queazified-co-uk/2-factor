package com.queazified.velocity2fa;

import com.google.inject.Inject;
import com.velocitypowered.api.command.RawCommand;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.format.NamedTextColor;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

@Plugin(id = "velocity2fa", name = "Velocity2FA", version = "1.0.0", authors = {"Queazified"})
public class Velocity2FA {

    public static final String PERM_REQUIRE = "staff.2fa";
    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDir;
    private final Store store;
    private final VerifiedSessionCache sessions;

    @Inject
    public Velocity2FA(ProxyServer server, Logger logger, @DataDirectory Path dataDir) throws IOException {
        this.server = server;
        this.logger = logger;
        this.dataDir = dataDir;
        if (!Files.exists(dataDir)) Files.createDirectories(dataDir);
        this.store = new Store(dataDir.resolve("secrets.json"));
        this.sessions = new VerifiedSessionCache(Duration.ofHours(12)); // keep staff verified for 12h
        registerCommands();
        logger.info("Velocity2FA initialized. Data dir: {}", dataDir.toAbsolutePath());
    }

    private void registerCommands() {
        server.getCommandManager().register("verify", new VerifyCommand());
        server.getCommandManager().register("2fa", new VerifyCommand());
        server.getCommandManager().register("2fasetup", new SetupCommand());
    }

    @Subscribe
    public void onPostLogin(PostLoginEvent event) {
        Player player = event.getPlayer();
        if (!player.hasPermission(PERM_REQUIRE)) return;

        UUID uuid = player.getUniqueId();
        if (sessions.isVerified(uuid)) return; // already verified recently

        String secret = store.getOrCreateSecret(uuid, player.getUsername());
        String otpauth = TOTPUtil.buildOtpAuthURL("Queazified", player.getUsername(), secret);
        Component clickable = Component.text("Click to copy your OTP secret").color(NamedTextColor.YELLOW)
                .clickEvent(ClickEvent.copyToClipboard(secret));
        player.sendMessage(Component.text("[2FA] ", NamedTextColor.GOLD)
                .append(Component.text("Scan in Google Authenticator or Authy, then run ", NamedTextColor.WHITE))
                .append(Component.text("/verify <6-digit-code>", NamedTextColor.AQUA)));
        player.sendMessage(Component.text("otpauth URL: ", NamedTextColor.GRAY).append(Component.text(otpauth, NamedTextColor.WHITE)));
        player.sendMessage(clickable);
        player.sendMessage(Component.text("Until verified, you cannot join a backend.").color(NamedTextColor.RED));
    }

    @Subscribe
    public void onServerPreConnect(ServerPreConnectEvent event) {
        Player player = event.getPlayer();
        if (!player.hasPermission(PERM_REQUIRE)) return;
        if (sessions.isVerified(player.getUniqueId())) return;

        event.setResult(ServerPreConnectEvent.ServerResult.denied());
        player.sendMessage(Component.text("[2FA] Verification required. Use /verify <code> from your authenticator app.", NamedTextColor.RED));
    }

    private class VerifyCommand implements RawCommand {
        @Override
        public void execute(Invocation invocation) {
            if (!(invocation.source() instanceof Player player)) {
                invocation.source().sendMessage(Component.text("Players only."));
                return;
            }
            if (!player.hasPermission(PERM_REQUIRE)) {
                player.sendMessage(Component.text("You don't need 2FA.", NamedTextColor.GREEN));
                return;
            }
            String[] args = invocation.arguments().split("\\s+");
            if (args.length != 1 || args[0].isEmpty()) {
                player.sendMessage(Component.text("Usage: /verify <6-digit-code>", NamedTextColor.YELLOW));
                return;
            }
            String code = args[0].trim();
            String secret = store.getSecret(player.getUniqueId()).orElse(null);
            if (secret == null) {
                player.sendMessage(Component.text("No secret found. Run /2fasetup to create one.", NamedTextColor.RED));
                return;
            }
            boolean ok = TOTPUtil.verifyCode(secret, code, 1); // allow +/- 1 time-step drift
            if (ok) {
                sessions.markVerified(player.getUniqueId());
                player.sendMessage(Component.text("[2FA] Verified. You can now join servers.", NamedTextColor.GREEN));
            } else {
                player.sendMessage(Component.text("[2FA] Invalid code.", NamedTextColor.RED));
            }
        }
    }

    private class SetupCommand implements RawCommand {
        @Override
        public void execute(Invocation invocation) {
            if (!(invocation.source() instanceof Player player)) {
                invocation.source().sendMessage(Component.text("Players only."));
                return;
            }
            if (!player.hasPermission(PERM_REQUIRE)) {
                player.sendMessage(Component.text("You are not required to use 2FA.", NamedTextColor.YELLOW));
                return;
            }
            String secret = store.getOrCreateSecret(player.getUniqueId(), player.getUsername());
            String otpauth = TOTPUtil.buildOtpAuthURL("Queazified", player.getUsername(), secret);
            player.sendMessage(Component.text("[2FA] Secret: ", NamedTextColor.GOLD).append(Component.text(secret, NamedTextColor.WHITE))
                    .append(Component.text("  (copied with click above)", NamedTextColor.GRAY)));
            player.sendMessage(Component.text("otpauth URL: ", NamedTextColor.GRAY).append(Component.text(otpauth, NamedTextColor.WHITE)));
        }
    }
}
