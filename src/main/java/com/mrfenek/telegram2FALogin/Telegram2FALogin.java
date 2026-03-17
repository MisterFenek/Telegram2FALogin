package com.mrfenek.telegram2FALogin;

import com.google.gson.*;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.Bukkit;
import org.bukkit.Server;
import org.bukkit.entity.Player;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.permissions.Permission;
import org.bukkit.permissions.PermissionAttachment;
import org.bukkit.permissions.PermissionAttachmentInfo;
import org.bukkit.plugin.java.JavaPlugin;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.*;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;

public final class Telegram2FALogin extends JavaPlugin implements Listener, CommandExecutor, org.bukkit.command.TabCompleter {

    private String botToken;
    private long expiryMs = 12 * 60 * 60 * 1000L;
    private String op2faMode = "session";
    private String nonOp2faMode = "disabled";
    private int sessionExpiryHours = 12;
    private final Path dataFile = Path.of(getDataFolder().getPath(), "tg2fa_data.json");
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private final Map<UUID, Long> linkedChats = new ConcurrentHashMap<>();
    private final Map<UUID, Map<String, Long>> approvedIps = new ConcurrentHashMap<>();
    private final Map<UUID, Set<String>> blacklistedIps = new ConcurrentHashMap<>();
    private final Map<String, PendingLink> pendingLinks = new ConcurrentHashMap<>();
    private final Map<String, PendingApproval> pendingApprovals = new ConcurrentHashMap<>();
    private final Map<Long, String> chatStates = new ConcurrentHashMap<>();
    private final Map<Long, Set<String>> disabledNotifications = new ConcurrentHashMap<>();
    private final Map<String, String> ipManagerShortIds = new ConcurrentHashMap<>();
    private final Map<String, Long> ipManagerShortIdsTimestamp = new ConcurrentHashMap<>();
    private final Map<UUID, String> player2faModes = new ConcurrentHashMap<>();
    private long ownerId;
    private final Set<Long> adminIds = ConcurrentHashMap.newKeySet();
    private boolean rconEnabled = true;
    private boolean privateOnly = true;
    private FileConfiguration messagesConfig;
    private volatile Thread pollingThread;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private volatile boolean isRunning = true;
    private boolean debugEnabled = false;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        reloadPlugin();

        if (debugEnabled) {
            getLogger().info("Debug mode enabled.");
        }

        if (this.botToken == null || this.botToken.isEmpty() || this.botToken.equalsIgnoreCase("YOUR_BOT_TOKEN_HERE")) {
            getLogger().warning("Telegram Bot Token is not set in config.yml! Plugin will not work.");
        }

        if (!getDataFolder().exists()) getDataFolder().mkdirs();
        loadData();

        getServer().getPluginManager().registerEvents(this, this);
        org.bukkit.command.PluginCommand cmd = getCommand("tg2fa");
        if (cmd != null) {
            cmd.setExecutor(this);
            cmd.setTabCompleter(this);
        }

        pollingThread = new Thread(this::pollTelegramUpdates, "TG2FALogin-Polling");
        pollingThread.start();
        scheduler.scheduleAtFixedRate(this::cleanupExpiredIps, 1, 5, TimeUnit.MINUTES);

        if (!Bukkit.getOnlineMode()) {
            getLogger().warning("SERVER IS RUNNING IN OFFLINE MODE! This plugin's first-time linking process is vulnerable to impersonation in offline mode.");
            getLogger().warning("It is strongly recommended to use a secure proxy (like BungeeGuard) or run the server in online-mode.");
        }

        debug("Telegram Bot initialized and polling updates.");
        notifyAdmins("server_status", getMsg("tg-server-start"));
    }

    private void reloadPlugin() {
        reloadConfig();
        this.botToken = getConfig().getString("bot-token", "YOUR_BOT_TOKEN_HERE");
        this.debugEnabled = getConfig().getBoolean("debug", false);
        this.ownerId = getConfig().getLong("owner-id", 0L);
        this.op2faMode = getConfig().getString("op-2fa-mode", "session");
        this.nonOp2faMode = getConfig().getString("non-op-2fa-mode", "disabled");
        this.sessionExpiryHours = getConfig().getInt("session-expiry-hours", 12);
        this.expiryMs = (long) sessionExpiryHours * 60 * 60 * 1000L;
        this.adminIds.clear();
        getConfig().getLongList("admin-ids").forEach(this.adminIds::add);
        this.rconEnabled = getConfig().getBoolean("rcon-enabled", true);
        this.privateOnly = getConfig().getBoolean("private-only", true);

        loadMessages();
        approvedIps.clear();
    }

    private final SecureRandom secureRandom = new SecureRandom();

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;");
    }

    private void loadMessages() {
        String lang = getConfig().getString("language", "en").toLowerCase();
        if (!lang.equals("en") && !lang.equals("ru")) {
            lang = "en";
        }
        File messagesFile = new File(getDataFolder(), "messages.yml");

        if (!messagesFile.exists()) {
            saveResource("messages_" + lang + ".yml", false);
            File langFile = new File(getDataFolder(), "messages_" + lang + ".yml");
            if (langFile.exists()) {
                try {
                    Files.move(langFile.toPath(), messagesFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException e) {
                    getLogger().severe("Could not move messages file: " + e.getMessage());
                }
            }
        }

        messagesConfig = YamlConfiguration.loadConfiguration(messagesFile);
        String currentInternalLang = messagesConfig.getString("language-internal", "en");

        if (!currentInternalLang.equalsIgnoreCase(lang)) {
            // Language switched! Backup old
            File backupFile = new File(getDataFolder(), "messages_" + currentInternalLang + ".bak");
            if (messagesFile.exists()) {
                try {
                    Files.move(messagesFile.toPath(), backupFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException ignored) {}
            }

            // Save new
            saveResource("messages_" + lang + ".yml", true);
            File langFile = new File(getDataFolder(), "messages_" + lang + ".yml");
            if (langFile.exists()) {
                try {
                    Files.move(langFile.toPath(), messagesFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException e) {
                    getLogger().severe("Could not move messages file: " + e.getMessage());
                }
            }

            // Reload
            messagesConfig = YamlConfiguration.loadConfiguration(messagesFile);
            getLogger().info("Language switched to " + lang + ". Old messages backed up to " + backupFile.getName());
        }

        // Fill missing keys from jar resource
        InputStream defConfigStream = getResource("messages_" + lang + ".yml");
        if (defConfigStream != null) {
            YamlConfiguration defConfig = YamlConfiguration.loadConfiguration(new InputStreamReader(defConfigStream, StandardCharsets.UTF_8));
            boolean changed = false;
            for (String key : defConfig.getKeys(true)) {
                if (!messagesConfig.contains(key)) {
                    messagesConfig.set(key, defConfig.get(key));
                    changed = true;
                }
            }
            if (changed) {
                try {
                    messagesConfig.save(messagesFile);
                } catch (IOException ignored) {}
            }
        }
    }

    private String getMsg(String key) {
        return messagesConfig.getString(key, "Message missing: " + key);
    }

    private void debug(String message) {
        if (debugEnabled) {
            getLogger().info("[DEBUG] " + message);
        }
    }

    private void checkTokenError(int statusCode) {
        if (statusCode == 404) {
            getLogger().severe("Telegram API error 404 (Not Found). Please check your bot-token in config.yml! It appears to be invalid.");
        }
    }

    @Override
    public void onDisable() {
        isRunning = false;
        if (pollingThread != null) {
            pollingThread.interrupt();
        }
        notifyAdminsSync("server_status", getMsg("tg-server-stop"));
        saveData();
        scheduler.shutdown();
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();
        String ip = player.getAddress().getAddress().getHostAddress();

        String pMode = player2faModes.get(uuid);
        String effMode = (pMode != null) ? pMode : (player.isOp() ? op2faMode : nonOp2faMode);

        if (effMode.equalsIgnoreCase("always")) {
            Map<String, Long> ips = approvedIps.get(uuid);
            if (ips != null) {
                if (ips.remove(ip) != null) {
                    debug("Removed " + player.getName() + "'s IP from session (mode: always).");
                }
            }
        }

        if (player.isOp()) {
            notifyAdmins("join_leave", getMsg("tg-admin-join").replace("%player%", escapeHtml(player.getName())));
        }
    }

    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        if (event.getPlayer().isOp()) {
            notifyAdmins("join_leave", getMsg("tg-admin-quit").replace("%player%", escapeHtml(event.getPlayer().getName())));
        }
    }

    @EventHandler
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        if (event.getPlayer().isOp()) {
            notifyAdmins("commands", getMsg("tg-admin-cmd").replace("%player%", escapeHtml(event.getPlayer().getName())).replace("%command%", escapeHtml(event.getMessage())));
        }
    }

    private void notifyAdmins(String category, String message) {
        if (ownerId != 0 && !disabledNotifications.getOrDefault(ownerId, Set.of()).contains(category)) {
            sendTelegramMessage(ownerId, message);
        }
        for (long adminId : adminIds) {
            if (adminId != ownerId && !disabledNotifications.getOrDefault(adminId, Set.of()).contains(category)) {
                sendTelegramMessage(adminId, message);
            }
        }
    }

    private void notifyAdminsSync(String category, String message) {
        if (ownerId != 0 && !disabledNotifications.getOrDefault(ownerId, Set.of()).contains(category)) {
            sendTelegramMessageSync(ownerId, message);
        }
        for (long adminId : adminIds) {
            if (adminId != ownerId && !disabledNotifications.getOrDefault(adminId, Set.of()).contains(category)) {
                sendTelegramMessageSync(adminId, message);
            }
        }
    }

    private boolean isChatAdmin(long chatId) {
        if (chatId == 0) return false;
        return chatId == ownerId || adminIds.contains(chatId);
    }

    @EventHandler
    public void onAsyncPreLogin(AsyncPlayerPreLoginEvent event) {
        UUID uuid = event.getUniqueId();
        String ip = event.getAddress().getHostAddress();
        String name = event.getName();

        debug("Player " + name + " (" + ip + ") is attempting to join.");

        OfflinePlayer offlinePlayer = Bukkit.getOfflinePlayer(uuid);
        boolean isOp = offlinePlayer.isOp();

        String playerMode = player2faModes.get(uuid);
        String effectiveMode = (playerMode != null) ? playerMode : (isOp ? op2faMode : nonOp2faMode);

        if (effectiveMode.equalsIgnoreCase("disabled")) {
            debug("2FA disabled for " + name + " (OP: " + isOp + "). Allowing join.");
            return;
        }

        debug("Player " + name + " (OP: " + isOp + ") mode: " + effectiveMode + ". Checking protection...");

        Set<String> blacklist = blacklistedIps.get(uuid);
        if (blacklist != null && blacklist.contains(ip)) {
            debug("Refusing connection for " + name + ": IP " + ip + " is blacklisted.");
            notifyAdmins("security", getMsg("tg-admin-blacklist-attempt").replace("%player%", escapeHtml(name)).replace("%ip%", escapeHtml(ip)));
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED,
                    LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("kick-blacklisted")).colorIfAbsent(NamedTextColor.RED));
            return;
        }

        if (!linkedChats.containsKey(uuid)) {
            debug("Refusing connection for " + name + ": Account not linked to Telegram.");
            notifyAdmins("security", getMsg("tg-admin-unlinked-attempt").replace("%player%", escapeHtml(name)).replace("%ip%", escapeHtml(ip)));
            
            String code = generateCode(uuid);
            pendingLinks.put(code, new PendingLink(uuid));
            
            String kickMsg = getMsg("kick-unlinked").replace("%code%", code);
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    LegacyComponentSerializer.legacyAmpersand().deserialize(kickMsg).colorIfAbsent(NamedTextColor.RED));
            return;
        }

        Map<String, Long> playerApproved = approvedIps.get(uuid);
        if (playerApproved != null) {
            Long expiry = playerApproved.get(ip);
            if (expiry != null) {
                if (effectiveMode.equalsIgnoreCase("whitelist") || System.currentTimeMillis() < expiry) {
                    if (effectiveMode.equalsIgnoreCase("always")) {
                        // For 'always' mode, we allow it once and remove immediately.
                        playerApproved.remove(ip);
                        debug("Allowing one-time 'always' connection for " + name + " and removing approval.");
                    } else {
                        debug("Allowing connection for " + name + ": IP " + ip + " is already approved.");
                    }
                    return;
                } else {
                    debug("IP " + ip + " for player " + name + " has expired approval.");
                    playerApproved.remove(ip);
                }
            }
        }

        debug("Suspending login for " + name + ": 2FA verification required via Telegram.");
        event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("kick-2fa")).colorIfAbsent(NamedTextColor.YELLOW));
        
        String approvalId = generateShortId();
        pendingApprovals.put(approvalId, new PendingApproval(uuid, ip));
        
        String tgMsg = getMsg("tg-2fa-prompt").replace("%ip%", escapeHtml(ip)).replace("%player%", escapeHtml(name));
        sendTelegramMessageWithButtons(linkedChats.get(uuid), tgMsg, approvalId);
    }

    @Override
    public boolean onCommand(@NotNull CommandSender sender, @NotNull Command command, @NotNull String label, @NotNull String[] args) {
        if (!command.getName().equalsIgnoreCase("tg2fa")) return false;

        if (args.length == 0) {
            sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("tg-usage")).colorIfAbsent(NamedTextColor.RED));
            return true;
        }

        String subCommand = args[0].toLowerCase();

        if (subCommand.equals("link")) {
            if (!sender.hasPermission("telegram2falogin.use")) {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("tg-no-permission")).colorIfAbsent(NamedTextColor.RED));
                return true;
            }
            if (!(sender instanceof org.bukkit.entity.Player player)) {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("mc-player-only")).colorIfAbsent(NamedTextColor.RED));
                return true;
            }

            UUID uuid = player.getUniqueId();
            if (linkedChats.containsKey(uuid)) {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("mc-already-linked")).colorIfAbsent(NamedTextColor.RED));
                return true;
            }

            String code = generateCode(uuid);
            pendingLinks.put(code, new PendingLink(uuid));
            sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("mc-link-code").replace("%code%", code)).colorIfAbsent(NamedTextColor.YELLOW));
            return true;
        }

        if (subCommand.equals("reload")) {
            if (!sender.isOp() && !(sender instanceof ConsoleCommandSender)) {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("tg-no-permission")).colorIfAbsent(NamedTextColor.RED));
                return true;
            }
            reloadPlugin();
            sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("tg-reloaded")).colorIfAbsent(NamedTextColor.GREEN));
            return true;
        }

        if (subCommand.equals("settings")) {
            if (!sender.hasPermission("telegram2falogin.use")) {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("tg-no-permission")).colorIfAbsent(NamedTextColor.RED));
                return true;
            }
            if (!(sender instanceof org.bukkit.entity.Player player)) {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("mc-player-only")).colorIfAbsent(NamedTextColor.RED));
                return true;
            }

            if (args.length < 2) {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("mc-settings-usage")).colorIfAbsent(NamedTextColor.RED));
                return true;
            }

            String mode = args[1].toLowerCase();
            if (mode.equals("always") || mode.equals("session") || mode.equals("whitelist") || mode.equals("disabled")) {
                player2faModes.put(player.getUniqueId(), mode);
                saveData();
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("mc-settings-updated").replace("%mode%", mode)).colorIfAbsent(NamedTextColor.GREEN));
            } else {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("mc-settings-invalid-mode")).colorIfAbsent(NamedTextColor.RED));
            }
            return true;
        }

        if (subCommand.equals("config")) {
            if (!sender.isOp() && !(sender instanceof ConsoleCommandSender)) {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("tg-no-permission")).colorIfAbsent(NamedTextColor.RED));
                return true;
            }

            if (sender instanceof org.bukkit.entity.Player player) {
                Long chatId = linkedChats.get(player.getUniqueId());
                if (chatId == null || !isChatAdmin(chatId)) {
                    sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("tg-unauthorized-config")).colorIfAbsent(NamedTextColor.RED));
                    return true;
                }
            }

            if (args.length < 3) {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("tg-config-usage")).colorIfAbsent(NamedTextColor.RED));
                return true;
            }

            String path = args[1];
            String value = String.join(" ", Arrays.copyOfRange(args, 2, args.length));

            try {
                if (path.equalsIgnoreCase("debug")) {
                    boolean val = Boolean.parseBoolean(value);
                    getConfig().set(path, val);
                    this.debugEnabled = val;
                } else if (path.equalsIgnoreCase("owner-id")) {
                    long val = Long.parseLong(value);
                    getConfig().set(path, val);
                    this.ownerId = val;
                } else if (path.equalsIgnoreCase("bot-token")) {
                    getConfig().set(path, value);
                    this.botToken = value;
                } else if (path.equalsIgnoreCase("admin-ids")) {
                    String[] ids = value.split(",");
                    List<Long> longList = new ArrayList<>();
                    for (String s : ids) {
                        try { longList.add(Long.parseLong(s.trim())); } catch (NumberFormatException ignored) {}
                    }
                    getConfig().set(path, longList);
                    this.adminIds.clear();
                    this.adminIds.addAll(longList);
                } else if (path.equalsIgnoreCase("op-2fa-mode")) {
                    getConfig().set(path, value);
                    this.op2faMode = value;
                } else if (path.equalsIgnoreCase("session-expiry-hours")) {
                    int val = Integer.parseInt(value);
                    getConfig().set(path, val);
                    this.sessionExpiryHours = val;
                    this.expiryMs = (long) val * 60 * 60 * 1000L;
                } else if (path.equalsIgnoreCase("rcon-enabled")) {
                    boolean val = Boolean.parseBoolean(value);
                    getConfig().set(path, val);
                    this.rconEnabled = val;
                } else if (path.equalsIgnoreCase("private-only")) {
                    boolean val = Boolean.parseBoolean(value);
                    getConfig().set(path, val);
                    this.privateOnly = val;
                } else {
                    getConfig().set(path, value);
                }
                saveConfig();
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("tg-config-updated").replace("%path%", path).replace("%value%", value)).colorIfAbsent(NamedTextColor.GREEN));
            } catch (Exception e) {
                sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("mc-config-error").replace("%error%", e.getMessage())).colorIfAbsent(NamedTextColor.RED));
            }
            return true;
        }

        sender.sendMessage(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("tg-usage")).colorIfAbsent(NamedTextColor.RED));
        return true;
    }

    @Override
    public List<String> onTabComplete(@NotNull CommandSender sender, @NotNull Command command, @NotNull String alias, @NotNull String[] args) {
        if (!command.getName().equalsIgnoreCase("tg2fa")) return Collections.emptyList();

        List<String> completions = new ArrayList<>();
        if (args.length == 1) {
            String input = args[0].toLowerCase();
            if ("link".startsWith(input)) completions.add("link");
            if ("settings".startsWith(input)) completions.add("settings");
            if (sender.isOp() || sender instanceof ConsoleCommandSender) {
                if ("reload".startsWith(input)) completions.add("reload");
                if ("config".startsWith(input)) completions.add("config");
            }
        } else if (args.length == 2) {
            String subCommand = args[0].toLowerCase();
            String input = args[1].toLowerCase();
            if (subCommand.equals("settings")) {
                if ("always".startsWith(input)) completions.add("always");
                if ("session".startsWith(input)) completions.add("session");
                if ("whitelist".startsWith(input)) completions.add("whitelist");
                if ("disabled".startsWith(input)) completions.add("disabled");
            } else if (subCommand.equals("config") && (sender.isOp() || sender instanceof ConsoleCommandSender)) {
                List<String> paths = Arrays.asList("bot-token", "debug", "owner-id", "admin-ids", "language", "op-2fa-mode", "session-expiry-hours");
                for (String path : paths) {
                    if (path.startsWith(input)) completions.add(path);
                }
            }
        } else if (args.length == 3) {
            String subCommand = args[0].toLowerCase();
            String path = args[1].toLowerCase();
            String input = args[2].toLowerCase();
            if (subCommand.equals("config") && (sender.isOp() || sender instanceof ConsoleCommandSender)) {
                if (path.equals("op-2fa-mode")) {
                    if ("always".startsWith(input)) completions.add("always");
                    if ("session".startsWith(input)) completions.add("session");
                    if ("whitelist".startsWith(input)) completions.add("whitelist");
                } else if (path.equals("debug")) {
                    if ("true".startsWith(input)) completions.add("true");
                    if ("false".startsWith(input)) completions.add("false");
                } else if (path.equals("language")) {
                    if ("en".startsWith(input)) completions.add("en");
                    if ("ru".startsWith(input)) completions.add("ru");
                }
            }
        }

        return completions;
    }

    private String generateCode(UUID uuid) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        String code;
        do {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 10; i++) sb.append(alphabet.charAt(secureRandom.nextInt(alphabet.length())));
            code = sb.toString();
        } while (pendingLinks.containsKey(code));
        return code;
    }

    private String generateShortId() {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        String id;
        do {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 12; i++) sb.append(alphabet.charAt(secureRandom.nextInt(alphabet.length())));
            id = sb.toString();
        } while (pendingApprovals.containsKey(id) || ipManagerShortIds.containsKey(id));
        return id;
    }

    private static class PendingLink {
        final UUID uuid;
        final long timestamp;
        PendingLink(UUID uuid) {
            this.uuid = uuid;
            this.timestamp = System.currentTimeMillis();
        }
    }

    private static class PendingApproval {
        final UUID uuid;
        final String ip;
        final long timestamp;
        PendingApproval(UUID uuid, String ip) {
            this.uuid = uuid;
            this.ip = ip;
            this.timestamp = System.currentTimeMillis();
        }
    }

    private void cleanupExpiredIps() {
        long now = System.currentTimeMillis();
        approvedIps.values().forEach(ips -> ips.values().removeIf(expiry -> now > expiry));
        pendingLinks.entrySet().removeIf(entry -> now - entry.getValue().timestamp > 10 * 60 * 1000L);
        pendingApprovals.entrySet().removeIf(entry -> now - entry.getValue().timestamp > 5 * 60 * 1000L);
        ipManagerShortIdsTimestamp.entrySet().removeIf(entry -> now - entry.getValue() > 60 * 60 * 1000L);
        ipManagerShortIds.keySet().removeIf(shortId -> !ipManagerShortIdsTimestamp.containsKey(shortId));
        debug("Cleaned up expired 2FA sessions and pending states.");
    }

    private void pollTelegramUpdates() {
        getLogger().info("Telegram update polling started.");
        long offset = 0;
        boolean firstRun = true;
        while (isRunning) {
            try {
                if (firstRun) {
                    // Skip old updates
                    HttpRequest request = HttpRequest.newBuilder()
                            .uri(URI.create("https://api.telegram.org/bot" + botToken + "/getUpdates?offset=-1&limit=1"))
                            .timeout(Duration.ofSeconds(10))
                            .GET()
                            .build();
                    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                    if (response.statusCode() == 200) {
                        JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
                        if (json.has("result")) {
                            JsonArray result = json.getAsJsonArray("result");
                            if (result.size() > 0) {
                                offset = result.get(0).getAsJsonObject().get("update_id").getAsLong() + 1;
                                debug("Skipping old updates, starting from offset " + offset);
                            }
                        }
                    } else {
                        checkTokenError(response.statusCode());
                    }
                    firstRun = false;
                }

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create("https://api.telegram.org/bot" + botToken + "/getUpdates?offset=" + offset + "&timeout=30"))
                        .timeout(Duration.ofSeconds(45))
                        .GET()
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
                    if (!json.has("result")) {
                        getLogger().severe("Telegram API error: result field is missing. Response: " + response.body());
                        continue;
                    }
                    JsonArray result = json.getAsJsonArray("result");
                    for (JsonElement element : result) {
                        JsonObject update = element.getAsJsonObject();
                        offset = update.get("update_id").getAsLong() + 1;
                        debug("Received Telegram update: " + update);

                        if (update.has("message")) {
                            JsonObject message = update.getAsJsonObject("message");
                            long chatId = message.get("chat").getAsJsonObject().get("id").getAsLong();
                            long fromId = message.has("from") ? message.get("from").getAsJsonObject().get("id").getAsLong() : chatId;
                            String chatType = message.get("chat").getAsJsonObject().get("type").getAsString();
                            
                            if (privateOnly && !chatType.equals("private")) {
                                debug("Ignoring message from non-private chat: " + chatType);
                                continue;
                            }

                            if (message.has("text")) {
                                String text = message.get("text").getAsString();

                                if (text.startsWith("/start")) {
                                    handleStartCommand(chatId, fromId);
                                } else if (text.startsWith("/mclink")) {
                                    String[] parts = text.split(" ");
                                    if (parts.length < 2) {
                                        sendTelegramMessage(chatId, getMsg("tg-mclink-usage"));
                                    } else {
                                        String code = parts[1];
                                        if (pendingLinks.containsKey(code)) {
                                            UUID uuid = pendingLinks.remove(code).uuid;
                                            linkedChats.put(uuid, chatId);
                                            String name = Bukkit.getOfflinePlayer(uuid).getName();
                                            sendTelegramMessage(chatId, getMsg("tg-linked").replace("%player%", name != null ? escapeHtml(name) : "Unknown"));
                                            saveData();
                                        } else {
                                            sendTelegramMessage(chatId, getMsg("tg-invalid-code"));
                                        }
                                    }
                                } else if (pendingLinks.containsKey(text)) {
                                    UUID uuid = pendingLinks.remove(text).uuid;
                                    linkedChats.put(uuid, chatId);
                                    String name = Bukkit.getOfflinePlayer(uuid).getName();
                                    sendTelegramMessage(chatId, getMsg("tg-linked").replace("%player%", name != null ? escapeHtml(name) : "Unknown"));
                                    saveData();
                                } else if (isChatAdmin(fromId)) {
                                    if (text.startsWith("/rcon ") && rconEnabled) {
                                        chatStates.remove(chatId);
                                        handleRconCommand(chatId, text.substring(6));
                                    } else if (text.equalsIgnoreCase("/players")) {
                                        chatStates.remove(chatId);
                                        handlePlayersCommand(chatId);
                                    } else if (text.equalsIgnoreCase("/settings")) {
                                        chatStates.remove(chatId);
                                        handleSettingsCommand(chatId);
                                    } else if (text.equalsIgnoreCase("/cancel")) {
                                        chatStates.remove(chatId);
                                        sendTelegramMessage(chatId, getMsg("tg-cancelled"));
                                    } else if (chatStates.containsKey(chatId)) {
                                        handleStateMessage(chatId, text);
                                    } else if (text.startsWith("/") && rconEnabled) {
                                        chatStates.remove(chatId);
                                        handleRconCommand(chatId, text.substring(1));
                                    }
                                }
                            }
                        } else if (update.has("callback_query")) {
                            handleCallback(update.getAsJsonObject("callback_query"));
                        }
                    }
                } else {
                    getLogger().severe("Error polling Telegram updates: API returned " + response.statusCode() + " - " + response.body());
                    checkTokenError(response.statusCode());
                    try { Thread.sleep(5000); } catch (InterruptedException ignored) {}
                }
            } catch (Exception e) {
                if (isRunning && !(e instanceof java.io.IOException && e.getCause() instanceof java.lang.InterruptedException)) {
                    getLogger().severe("Error polling Telegram updates: " + e.getMessage());
                    try { Thread.sleep(5000); } catch (InterruptedException ignored) {}
                }
            }
        }
    }

    private List<UUID> getLinkedUuids(long chatId) {
        List<UUID> uuids = new ArrayList<>();
        for (Map.Entry<UUID, Long> entry : linkedChats.entrySet()) {
            if (entry.getValue() == chatId) {
                uuids.add(entry.getKey());
            }
        }
        return uuids;
    }

    private void handleStartCommand(long chatId, long fromId) {
        String welcome = getMsg("tg-start").replace("%chatId%", String.valueOf(chatId));
        JsonObject markup = new JsonObject();
        JsonArray keyboard = new JsonArray();

        if (isChatAdmin(fromId)) {
            JsonArray row1 = new JsonArray();
            row1.add(createButton(getMsg("tg-btn-players"), "player:list_all"));
            row1.add(createButton(getMsg("tg-btn-settings"), "settings:menu"));
            keyboard.add(row1);

            JsonArray row2 = new JsonArray();
            row2.add(createButton(getMsg("tg-btn-blacklist-admin"), "bl:list"));
            keyboard.add(row2);
        }

        List<UUID> linked = getLinkedUuids(chatId);
        if (!linked.isEmpty()) {
            JsonArray row = new JsonArray();
            row.add(createButton(getMsg("tg-btn-me"), "me:list"));
            keyboard.add(row);
        }

        if (keyboard.size() > 0) {
            markup.add("inline_keyboard", keyboard);
        }

        sendTelegramMessage(chatId, welcome, markup);
    }

    private void handleSettingsCommand(long chatId) {
        handleSettingsCommand(chatId, null);
    }

    private void handleSettingsCommand(long chatId, Integer messageId) {
        Set<String> disabled = disabledNotifications.getOrDefault(chatId, Set.of());

        JsonObject markup = new JsonObject();
        JsonArray keyboard = new JsonArray();

        keyboard.add(createToggleRow("server_status", getMsg("tg-btn-server-status"), disabled));
        keyboard.add(createToggleRow("join_leave", getMsg("tg-btn-join-leave"), disabled));
        keyboard.add(createToggleRow("commands", getMsg("tg-btn-commands"), disabled));
        keyboard.add(createToggleRow("security", getMsg("tg-btn-security"), disabled));

        JsonArray modeRow = new JsonArray();
        modeRow.add(createButton("⚙️ Default 2FA: " + op2faMode.toUpperCase(), "settings:df_2fa_m"));
        keyboard.add(modeRow);

        markup.add("inline_keyboard", keyboard);

        if (messageId != null) {
            editTelegramMessage(chatId, messageId, getMsg("tg-settings-menu"), markup);
        } else {
            sendTelegramMessage(chatId, getMsg("tg-settings-menu"), markup);
        }
    }

    private JsonArray createToggleRow(String category, String label, Set<String> disabled) {
        JsonArray row = new JsonArray();
        boolean isEnabled = !disabled.contains(category);
        String statusText = isEnabled ? getMsg("tg-enabled") : getMsg("tg-disabled");
        row.add(createButton(label + ": " + statusText, "settings:toggle:" + category));
        return row;
    }

    private void handleRconCommand(long chatId, String command) {
        if (!isChatAdmin(chatId)) {
            sendTelegramMessage(chatId, getMsg("tg-unauthorized"));
            return;
        }

        if (command.isEmpty()) {
            sendTelegramMessage(chatId, getMsg("tg-rcon-usage"));
            return;
        }

        Bukkit.getScheduler().runTask(this, () -> {
            TelegramCommandSender rconSender = new TelegramCommandSender(chatId);
            Bukkit.dispatchCommand(rconSender, command);
        });
    }

    private void handlePlayersCommand(long chatId) {
        Collection<? extends org.bukkit.entity.Player> onlinePlayers = Bukkit.getOnlinePlayers();
        if (onlinePlayers.isEmpty()) {
            sendTelegramMessage(chatId, getMsg("tg-no-players"));
            return;
        }

        JsonObject markup = new JsonObject();
        JsonArray keyboard = new JsonArray();

        int count = 0;
        for (org.bukkit.entity.Player player : onlinePlayers) {
            if (count++ >= 100) break;
            JsonArray row = new JsonArray();
            row.add(createButton("👤 " + player.getName(), "player:manage:" + player.getUniqueId()));
            keyboard.add(row);
        }

        markup.add("inline_keyboard", keyboard);
        sendTelegramMessage(chatId, getMsg("tg-select-player"), markup);
    }

    private void handleMeManage(long chatId, UUID uuid) {
        handleMeManage(chatId, uuid, null);
    }

    private void handleMeManage(long chatId, UUID uuid, @Nullable Integer messageId) {
        String name = Bukkit.getOfflinePlayer(uuid).getName();
        JsonObject markup = new JsonObject();
        JsonArray keyboard = new JsonArray();

        JsonArray row1 = new JsonArray();
        row1.add(createButton(getMsg("tg-btn-kick-me"), "me:kick:" + uuid));
        row1.add(createButton(getMsg("tg-btn-blacklist-me"), "me:bl:" + uuid));
        keyboard.add(row1);

        JsonArray row2 = new JsonArray();
        row2.add(createButton(getMsg("tg-btn-manage-blacklist"), "me:bl_l:" + uuid));
        row2.add(createButton(getMsg("tg-btn-manage-whitelist"), "me:wl_l:" + uuid));
        keyboard.add(row2);

        JsonArray row3 = new JsonArray();
        row3.add(createButton(getMsg("tg-btn-2fa-settings"), "me:2fa_menu:" + uuid));
        keyboard.add(row3);

        List<UUID> linked = getLinkedUuids(chatId);
        if (linked.size() > 1) {
            JsonArray rowBack = new JsonArray();
            rowBack.add(createButton(getMsg("tg-btn-back"), "me:list"));
            keyboard.add(rowBack);
        }

        markup.add("inline_keyboard", keyboard);
        String text = getMsg("tg-me-menu").replace("%player%", name != null ? escapeHtml(name) : "Unknown");

        if (messageId != null) {
            editTelegramMessage(chatId, messageId, text, markup);
        } else {
            sendTelegramMessage(chatId, text, markup);
        }
    }

    private void handle2FASettings(long chatId, UUID uuid, @Nullable Integer messageId, String prefix) {
        String name = Bukkit.getOfflinePlayer(uuid).getName();
        String currentMode = player2faModes.get(uuid);
        if (currentMode == null) {
            currentMode = Bukkit.getOfflinePlayer(uuid).isOp() ? op2faMode : nonOp2faMode;
        }

        JsonObject markup = new JsonObject();
        JsonArray keyboard = new JsonArray();

        keyboard.add(create2FAModeRow(uuid, "always", getMsg("tg-btn-mode-always"), currentMode, prefix));
        keyboard.add(create2FAModeRow(uuid, "session", getMsg("tg-btn-mode-session"), currentMode, prefix));
        keyboard.add(create2FAModeRow(uuid, "whitelist", getMsg("tg-btn-mode-whitelist"), currentMode, prefix));
        keyboard.add(create2FAModeRow(uuid, "disabled", getMsg("tg-btn-mode-disabled"), currentMode, prefix));

        JsonArray backRow = new JsonArray();
        backRow.add(createButton(getMsg("tg-btn-back"), prefix + ":manage:" + uuid));
        keyboard.add(backRow);

        markup.add("inline_keyboard", keyboard);

        String text = getMsg("tg-2fa-settings-menu").replace("%player%", name != null ? escapeHtml(name) : "Unknown")
                + "\n" + getMsg("tg-2fa-mode-current").replace("%mode%", currentMode);

        if (messageId != null) {
            editTelegramMessage(chatId, messageId, text, markup);
        } else {
            sendTelegramMessage(chatId, text, markup);
        }
    }

    private void handleDefault2FASettings(long chatId, @Nullable Integer messageId) {
        JsonObject markup = new JsonObject();
        JsonArray keyboard = new JsonArray();

        String[] modes = {"always", "session", "whitelist", "disabled"};
        
        // OP Defaults section
        JsonArray headerOp = new JsonArray();
        headerOp.add(createButton("--- " + getMsg("tg-btn-default-2fa-op") + " ---", "ignore"));
        keyboard.add(headerOp);
        
        for (String mode : modes) {
            JsonArray row = new JsonArray();
            String indicator = mode.equalsIgnoreCase(op2faMode) ? "✅ " : "";
            row.add(createButton(indicator + getMsg("tg-btn-mode-" + mode), "settings:df_2fa_s:op:" + mode));
            keyboard.add(row);
        }

        // Non-OP Defaults section
        JsonArray headerNonOp = new JsonArray();
        headerNonOp.add(createButton("--- " + getMsg("tg-btn-default-2fa-nonop") + " ---", "ignore"));
        keyboard.add(headerNonOp);
        
        for (String mode : modes) {
            JsonArray row = new JsonArray();
            String indicator = mode.equalsIgnoreCase(nonOp2faMode) ? "✅ " : "";
            row.add(createButton(indicator + getMsg("tg-btn-mode-" + mode), "settings:df_2fa_s:nonop:" + mode));
            keyboard.add(row);
        }

        JsonArray backRow = new JsonArray();
        backRow.add(createButton(getMsg("tg-btn-back"), "settings:menu"));
        keyboard.add(backRow);

        markup.add("inline_keyboard", keyboard);

        String text = getMsg("tg-default-2fa-menu") + "\n" 
                + getMsg("tg-btn-default-2fa-op") + ": " + op2faMode + "\n"
                + getMsg("tg-btn-default-2fa-nonop") + ": " + nonOp2faMode;

        if (messageId != null) {
            editTelegramMessage(chatId, messageId, text, markup);
        } else {
            sendTelegramMessage(chatId, text, markup);
        }
    }

    private JsonArray create2FAModeRow(UUID uuid, String mode, String label, String currentMode, String prefix) {
        JsonArray row = new JsonArray();
        String indicator = mode.equalsIgnoreCase(currentMode) ? "✅ " : "";
        row.add(createButton(indicator + label, prefix + ":2fa_set:" + uuid + ":" + mode));
        return row;
    }

    private void handleBlacklistAdmin(long chatId) {
        if (blacklistedIps.isEmpty()) {
            sendTelegramMessage(chatId, getMsg("tg-no-blacklist-found"));
            return;
        }

        JsonObject markup = new JsonObject();
        JsonArray keyboard = new JsonArray();

        int count = 0;
        for (UUID uuid : blacklistedIps.keySet()) {
            if (blacklistedIps.get(uuid).isEmpty()) continue;
            if (count++ >= 100) break;
            String name = Bukkit.getOfflinePlayer(uuid).getName();
            JsonArray row = new JsonArray();
            row.add(createButton("👤 " + (name != null ? name : uuid.toString()), "bl:pips:" + uuid));
            keyboard.add(row);
        }

        markup.add("inline_keyboard", keyboard);
        sendTelegramMessage(chatId, getMsg("tg-blacklist-players-menu"), markup);
    }

    private void handlePlayerBlacklist(long chatId, UUID uuid) {
        Set<String> ips = blacklistedIps.getOrDefault(uuid, Set.of());
        String name = Bukkit.getOfflinePlayer(uuid).getName();

        if (ips.isEmpty()) {
            sendTelegramMessage(chatId, getMsg("tg-no-blacklist-player").replace("%player%", name != null ? escapeHtml(name) : uuid.toString()));
            return;
        }

        JsonObject markup = new JsonObject();
        JsonArray keyboard = new JsonArray();

        long now = System.currentTimeMillis();
        int count = 0;
        for (String ip : ips) {
            if (count++ >= 49) break;
            String shortId = generateShortId();
            ipManagerShortIds.put(shortId, ip);
            ipManagerShortIdsTimestamp.put(shortId, now);
            JsonArray row = new JsonArray();
            row.add(createButton(ip, "ignore"));
            row.add(createButton(getMsg("tg-btn-remove"), "bl:rem:" + uuid + ":" + shortId));
            keyboard.add(row);
        }

        JsonArray backRow = new JsonArray();
        backRow.add(createButton(getMsg("tg-btn-back"), "bl:list"));
        keyboard.add(backRow);

        markup.add("inline_keyboard", keyboard);
        sendTelegramMessage(chatId, getMsg("tg-blacklist-ips-menu").replace("%player%", name != null ? escapeHtml(name) : "Unknown"), markup);
    }

    private void handlePlayerIpManagement(long chatId, UUID uuid, boolean isBlacklist, @Nullable Integer messageId) {
        String name = Bukkit.getOfflinePlayer(uuid).getName();
        JsonObject markup = new JsonObject();
        JsonArray keyboard = new JsonArray();

        if (isBlacklist) {
            Set<String> ips = blacklistedIps.getOrDefault(uuid, Set.of());
            if (ips.isEmpty()) {
                String msg = getMsg("tg-no-blacklist-player").replace("%player%", name != null ? escapeHtml(name) : uuid.toString());
                if (messageId != null) editTelegramMessage(chatId, messageId, msg, markup);
                else sendTelegramMessage(chatId, msg, markup);
                return;
            }
            long now = System.currentTimeMillis();
            int count = 0;
            for (String ip : ips) {
                if (count++ >= 49) break;
                String shortId = generateShortId();
                ipManagerShortIds.put(shortId, ip);
                ipManagerShortIdsTimestamp.put(shortId, now);
                JsonArray row = new JsonArray();
                row.add(createButton(ip, "ignore"));
                row.add(createButton(getMsg("tg-btn-remove"), "me:bl_r:" + uuid + ":" + shortId));
                keyboard.add(row);
            }
        } else {
            Map<String, Long> ips = approvedIps.getOrDefault(uuid, Map.of());
            if (ips.isEmpty()) {
                String msg = getMsg("tg-no-approved-ips").replace("%player%", name != null ? escapeHtml(name) : uuid.toString());
                if (messageId != null) editTelegramMessage(chatId, messageId, msg, markup);
                else sendTelegramMessage(chatId, msg, markup);
                return;
            }
            long now = System.currentTimeMillis();
            int count = 0;
            for (Map.Entry<String, Long> entry : ips.entrySet()) {
                if (count++ >= 49) break;
                String ip = entry.getKey();
                long expiry = entry.getValue();
                String shortId = generateShortId();
                ipManagerShortIds.put(shortId, ip);
                ipManagerShortIdsTimestamp.put(shortId, now);

                String timeStr;
                if (expiry == Long.MAX_VALUE) {
                    timeStr = getMsg("tg-time-permanent");
                } else {
                    long diff = expiry - now;
                    if (diff <= 0) continue;
                    long hours = diff / (1000 * 60 * 60);
                    long mins = (diff / (1000 * 60)) % 60;
                    timeStr = hours + "h " + mins + "m";
                }

                JsonArray row = new JsonArray();
                row.add(createButton(ip + " (" + timeStr + ")", "ignore"));
                row.add(createButton(getMsg("tg-btn-remove"), "me:wl_r:" + uuid + ":" + shortId));
                keyboard.add(row);
            }
        }

        JsonArray backRow = new JsonArray();
        backRow.add(createButton(getMsg("tg-btn-back"), "me:manage:" + uuid));
        keyboard.add(backRow);
        markup.add("inline_keyboard", keyboard);

        String text = isBlacklist ? getMsg("tg-my-blacklist") : getMsg("tg-my-whitelist");
        text = text.replace("%player%", name != null ? escapeHtml(name) : "Unknown");

        if (messageId != null) {
            editTelegramMessage(chatId, messageId, text, markup);
        } else {
            sendTelegramMessage(chatId, text, markup);
        }
    }

    private void handleStateMessage(long chatId, String text) {
        String state = chatStates.get(chatId);
        if (state == null) return;

        chatStates.remove(chatId); // Always clear state to prevent "sticky" modes

        if (state.startsWith("msg_to:")) {
            UUID targetUuid = UUID.fromString(state.substring(7));
            org.bukkit.entity.Player target = Bukkit.getPlayer(targetUuid);
            if (target != null && target.isOnline()) {
                String format = getMsg("mc-msg-format").replace("%message%", text);
                target.sendMessage(Component.text(format, NamedTextColor.GOLD));
                sendTelegramMessage(chatId, getMsg("tg-msg-sent").replace("%player%", escapeHtml(target.getName())));
            } else {
                sendTelegramMessage(chatId, getMsg("tg-not-online"));
            }
        }
    }

    private void handleCallback(JsonObject cb) {
        if (!cb.has("from")) return;
        long fromId = cb.get("from").getAsJsonObject().get("id").getAsLong();
        long chatId = cb.has("message") ? cb.get("message").getAsJsonObject().get("chat").getAsJsonObject().get("id").getAsLong() : fromId;
        String data = cb.get("data").getAsString();
        String id = cb.get("id").getAsString();

        if (data.equals("ignore")) {
            JsonObject answer = new JsonObject();
            answer.addProperty("callback_query_id", id);
            executeTelegramRequest("answerCallbackQuery", answer);
            return;
        }

        if (!isChatAdmin(fromId)) {
            // Check if it's a 2FA callback or "me" action
            if (!data.startsWith("approve:") && !data.startsWith("deny:") && !data.startsWith("bl:") && !data.startsWith("me:")) {
                JsonObject ans = new JsonObject();
                ans.addProperty("callback_query_id", id);
                executeTelegramRequest("answerCallbackQuery", ans);
                return;
            }
        }

        String[] parts = data.split(":");
        if (parts.length < 2) {
            JsonObject ans = new JsonObject();
            ans.addProperty("callback_query_id", id);
            executeTelegramRequest("answerCallbackQuery", ans);
            return;
        }

        String action = parts[0];

        if (action.equals("approve") || action.equals("deny") || (action.equals("bl") && pendingApprovals.containsKey(parts[1]))) {
            String approvalId = parts[1];
            PendingApproval pending = action.equals("deny") ? pendingApprovals.remove(approvalId) : pendingApprovals.get(approvalId);
            if (pending == null) return;

            UUID uuid = pending.uuid;
            String ip = pending.ip;

            // Security check: Only admins or the linked user can approve/deny/blacklist
            if (!isChatAdmin(fromId) && !linkedChats.getOrDefault(uuid, -1L).equals(fromId)) {
                return;
            }

            String name = Bukkit.getOfflinePlayer(uuid).getName();

            if (action.equals("approve")) {
                pendingApprovals.remove(approvalId);
                String pMode = player2faModes.get(uuid);
                String effMode = (pMode != null) ? pMode : (Bukkit.getOfflinePlayer(uuid).isOp() ? op2faMode : nonOp2faMode);
                long expiry;
                if (effMode.equalsIgnoreCase("whitelist")) {
                    expiry = Long.MAX_VALUE;
                } else if (effMode.equalsIgnoreCase("always")) {
                    expiry = System.currentTimeMillis() + 60000; // 1 minute to allow login
                } else {
                    expiry = System.currentTimeMillis() + expiryMs;
                }
                approvedIps.computeIfAbsent(uuid, k -> new ConcurrentHashMap<>()).put(ip, expiry);
                sendTelegramMessage(chatId, getMsg("tg-approved").replace("%ip%", escapeHtml(ip)).replace("%player%", name != null ? escapeHtml(name) : "Unknown"));
            } else if (action.equals("deny")) {
                sendTelegramMessage(chatId, getMsg("tg-denied").replace("%ip%", escapeHtml(ip)));
            } else if (action.equals("bl")) {
                pendingApprovals.remove(approvalId);
                blacklistedIps.computeIfAbsent(uuid, k -> ConcurrentHashMap.newKeySet()).add(ip);
                sendTelegramMessage(chatId, getMsg("tg-blacklisted").replace("%ip%", escapeHtml(ip)).replace("%player%", name != null ? escapeHtml(name) : "Unknown"));
            }
        } else if (action.equals("player")) {
            if (parts.length < 3) return;
            String subAction = parts[1];
            UUID uuid = UUID.fromString(parts[2]);
            org.bukkit.entity.Player target = Bukkit.getPlayer(uuid);
            String name = (target != null) ? target.getName() : Bukkit.getOfflinePlayer(uuid).getName();

            if (subAction.equals("manage")) {
                JsonObject markup = new JsonObject();
                JsonArray keyboard = new JsonArray();

                JsonArray row1 = new JsonArray();
                row1.add(createButton(getMsg("tg-btn-kick"), "player:kick:" + uuid));
                row1.add(createButton(getMsg("tg-btn-ban"), "player:ban:" + uuid));

                JsonArray row2 = new JsonArray();
                row2.add(createButton(getMsg("tg-btn-msg"), "player:msg:" + uuid));
                row2.add(createButton(getMsg("tg-btn-2fa-settings"), "player:2fa_menu:" + uuid));

                JsonArray row3 = new JsonArray();
                row3.add(createButton(getMsg("tg-btn-back"), "player:list_all"));

                keyboard.add(row1);
                keyboard.add(row2);
                keyboard.add(row3);
                markup.add("inline_keyboard", keyboard);

                sendTelegramMessage(chatId, getMsg("tg-manage-player").replace("%player%", name != null ? escapeHtml(name) : uuid.toString()), markup);
            } else if (subAction.equals("kick")) {
                Bukkit.getScheduler().runTask(this, () -> {
                    if (target != null && target.isOnline()) {
                        target.kick(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("mc-kick-reason")));
                        sendTelegramMessage(chatId, getMsg("tg-kicked").replace("%player%", escapeHtml(target.getName())));
                    } else {
                        sendTelegramMessage(chatId, getMsg("tg-not-online"));
                    }
                });
            } else if (subAction.equals("ban")) {
                Bukkit.getScheduler().runTask(this, () -> {
                    String finalName = (name != null) ? name : uuid.toString();
                    Bukkit.getBanList(org.bukkit.BanList.Type.NAME).addBan(finalName, getMsg("mc-ban-reason"), null, null);
                    if (target != null && target.isOnline()) {
                        target.kick(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("mc-ban-reason")));
                    }
                    sendTelegramMessage(chatId, getMsg("tg-banned").replace("%player%", escapeHtml(finalName)));
                });
            } else if (subAction.equals("msg")) {
                chatStates.put(chatId, "msg_to:" + uuid);
                sendTelegramMessage(chatId, getMsg("tg-msg-prompt").replace("%player%", name != null ? escapeHtml(name) : uuid.toString()));
            } else if (subAction.equals("list_all")) {
                handlePlayersCommand(chatId);
            } else if (subAction.equals("2fa_menu")) {
                if (cb.has("message")) {
                    int msgId = cb.get("message").getAsJsonObject().get("message_id").getAsInt();
                    handle2FASettings(chatId, uuid, msgId, "player");
                } else {
                    handle2FASettings(chatId, uuid, null, "player");
                }
            } else if (subAction.equals("2fa_set")) {
                if (parts.length < 4) return;
                String mode = parts[3];
                player2faModes.put(uuid, mode);
                approvedIps.remove(uuid); // Apply immediately
                if (cb.has("message")) {
                    int msgId = cb.get("message").getAsJsonObject().get("message_id").getAsInt();
                    handle2FASettings(chatId, uuid, msgId, "player");
                }
                String pName = Bukkit.getOfflinePlayer(uuid).getName();
                JsonObject answer = new JsonObject();
                answer.addProperty("callback_query_id", id);
                answer.addProperty("text", getMsg("tg-2fa-mode-updated").replace("%player%", pName != null ? pName : "Unknown").replace("%mode%", mode));
                executeTelegramRequest("answerCallbackQuery", answer);
            }
        } else if (action.equals("settings")) {
            if (parts.length < 2) return;
            String subAction = parts[1];
            if (subAction.equals("menu")) {
                handleSettingsCommand(chatId, cb.get("message").getAsJsonObject().get("message_id").getAsInt());
            } else if (subAction.equals("toggle")) {
                if (parts.length < 3) return;
                String category = parts[2];
                Set<String> disabled = disabledNotifications.computeIfAbsent(chatId, k -> ConcurrentHashMap.newKeySet());
                if (disabled.contains(category)) {
                    disabled.remove(category);
                } else {
                    disabled.add(category);
                }
                if (cb.has("message")) {
                    int msgId = cb.get("message").getAsJsonObject().get("message_id").getAsInt();
                    handleSettingsCommand(chatId, msgId);
                }
            } else if (subAction.equals("df_2fa_m")) {
                Integer msgId = cb.has("message") ? cb.get("message").getAsJsonObject().get("message_id").getAsInt() : null;
                handleDefault2FASettings(chatId, msgId);
            } else if (subAction.equals("df_2fa_s")) {
                if (parts.length < 4) return;
                String type = parts[2];
                String mode = parts[3];
                if (type.equals("op")) {
                    op2faMode = mode;
                    getConfig().set("op-2fa-mode", op2faMode);
                } else {
                    nonOp2faMode = mode;
                    getConfig().set("non-op-2fa-mode", nonOp2faMode);
                }
                saveConfig();
                approvedIps.clear(); // Clear cache so new mode is enforced immediately
                Integer msgId = cb.has("message") ? cb.get("message").getAsJsonObject().get("message_id").getAsInt() : null;
                handleDefault2FASettings(chatId, msgId);
            }
        } else if (action.equals("me")) {
            if (parts.length < 2) return;
            String subAction = parts[1];
            List<UUID> linked = getLinkedUuids(chatId);
            if (linked.isEmpty()) {
                sendTelegramMessage(chatId, getMsg("tg-no-linked-accounts"));
                return;
            }

            if (subAction.equals("list")) {
                if (linked.size() == 1) {
                    handleMeManage(chatId, linked.get(0));
                } else {
                    JsonObject markup = new JsonObject();
                    JsonArray keyboard = new JsonArray();
                    for (UUID uuid : linked) {
                        String name = Bukkit.getOfflinePlayer(uuid).getName();
                        JsonArray row = new JsonArray();
                        row.add(createButton("👤 " + (name != null ? name : uuid.toString()), "me:manage:" + uuid));
                        keyboard.add(row);
                    }
                    markup.add("inline_keyboard", keyboard);
                    String text = getMsg("tg-select-account");
                    if (cb.has("message")) {
                        int msgId = cb.get("message").getAsJsonObject().get("message_id").getAsInt();
                        editTelegramMessage(chatId, msgId, text, markup);
                    } else {
                        sendTelegramMessage(chatId, text, markup);
                    }
                }
            } else if (subAction.equals("manage")) {
                if (parts.length < 3) return;
                UUID uuid = UUID.fromString(parts[2]);
                if (!linked.contains(uuid)) return;
                if (cb.has("message")) {
                    int msgId = cb.get("message").getAsJsonObject().get("message_id").getAsInt();
                    handleMeManage(chatId, uuid, msgId);
                } else {
                    handleMeManage(chatId, uuid);
                }
            } else if (subAction.equals("2fa_menu")) {
                if (parts.length < 3) return;
                UUID uuid = UUID.fromString(parts[2]);
                if (!linked.contains(uuid)) return;
                if (cb.has("message")) {
                    int msgId = cb.get("message").getAsJsonObject().get("message_id").getAsInt();
                    handle2FASettings(chatId, uuid, msgId, "me");
                } else {
                    handle2FASettings(chatId, uuid, null, "me");
                }
            } else if (subAction.equals("2fa_set")) {
                if (parts.length < 4) return;
                UUID uuid = UUID.fromString(parts[2]);
                String mode = parts[3];
                if (!linked.contains(uuid)) return;
                player2faModes.put(uuid, mode);
                approvedIps.remove(uuid); // Clear old approvals to apply new mode immediately
                if (cb.has("message")) {
                    int msgId = cb.get("message").getAsJsonObject().get("message_id").getAsInt();
                    handle2FASettings(chatId, uuid, msgId, "me");
                }
                String name = Bukkit.getOfflinePlayer(uuid).getName();
                JsonObject answer = new JsonObject();
                answer.addProperty("callback_query_id", id);
                answer.addProperty("text", getMsg("tg-2fa-mode-updated").replace("%player%", name != null ? name : "Unknown").replace("%mode%", mode));
                executeTelegramRequest("answerCallbackQuery", answer);
            } else if (subAction.equals("kick")) {
                if (parts.length < 3) return;
                UUID uuid = UUID.fromString(parts[2]);
                if (!linked.contains(uuid)) return;
                Bukkit.getScheduler().runTask(this, () -> {
                    org.bukkit.entity.Player target = Bukkit.getPlayer(uuid);
                    if (target != null && target.isOnline()) {
                        target.kick(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("mc-kick-reason")));
                        sendTelegramMessage(chatId, getMsg("tg-kicked").replace("%player%", escapeHtml(target.getName())));
                    } else {
                        sendTelegramMessage(chatId, getMsg("tg-not-online"));
                    }
                });
            } else if (subAction.equals("bl")) {
                if (parts.length < 3) return;
                UUID uuid = UUID.fromString(parts[2]);
                if (!linked.contains(uuid)) return;
                
                org.bukkit.entity.Player target = Bukkit.getPlayer(uuid);
                if (target != null && target.isOnline()) {
                    String ip = target.getAddress().getAddress().getHostAddress();
                    blacklistedIps.computeIfAbsent(uuid, k -> ConcurrentHashMap.newKeySet()).add(ip);
                    Bukkit.getScheduler().runTask(this, () -> {
                        target.kick(LegacyComponentSerializer.legacyAmpersand().deserialize(getMsg("kick-blacklisted")));
                    });
                    sendTelegramMessage(chatId, getMsg("tg-blacklisted-self").replace("%ip%", escapeHtml(ip)).replace("%player%", escapeHtml(target.getName())));
                } else {
                    sendTelegramMessage(chatId, getMsg("tg-not-online"));
                }
            } else if (subAction.equals("bl_l")) {
                if (parts.length < 3) return;
                UUID uuid = UUID.fromString(parts[2]);
                if (!linked.contains(uuid)) return;
                Integer msgId = cb.has("message") ? cb.get("message").getAsJsonObject().get("message_id").getAsInt() : null;
                handlePlayerIpManagement(chatId, uuid, true, msgId);
            } else if (subAction.equals("wl_l")) {
                if (parts.length < 3) return;
                UUID uuid = UUID.fromString(parts[2]);
                if (!linked.contains(uuid)) return;
                Integer msgId = cb.has("message") ? cb.get("message").getAsJsonObject().get("message_id").getAsInt() : null;
                handlePlayerIpManagement(chatId, uuid, false, msgId);
            } else if (subAction.equals("bl_r")) {
                if (parts.length < 4) return;
                UUID uuid = UUID.fromString(parts[2]);
                if (!linked.contains(uuid)) return;
                String shortId = parts[3];
                String ip = ipManagerShortIds.remove(shortId);
                if (ip != null && blacklistedIps.containsKey(uuid)) {
                    blacklistedIps.get(uuid).remove(ip);
                    String name = Bukkit.getOfflinePlayer(uuid).getName();
                    sendTelegramMessage(chatId, getMsg("tg-ip-removed").replace("%ip%", escapeHtml(ip)).replace("%player%", name != null ? escapeHtml(name) : "Unknown"));
                    Integer msgId = cb.has("message") ? cb.get("message").getAsJsonObject().get("message_id").getAsInt() : null;
                    handlePlayerIpManagement(chatId, uuid, true, msgId);
                }
            } else if (subAction.equals("wl_r")) {
                if (parts.length < 4) return;
                UUID uuid = UUID.fromString(parts[2]);
                if (!linked.contains(uuid)) return;
                String shortId = parts[3];
                String ip = ipManagerShortIds.remove(shortId);
                if (ip != null && approvedIps.containsKey(uuid)) {
                    approvedIps.get(uuid).remove(ip);
                    String name = Bukkit.getOfflinePlayer(uuid).getName();
                    sendTelegramMessage(chatId, getMsg("tg-ip-removed-whitelist").replace("%ip%", escapeHtml(ip)).replace("%player%", name != null ? escapeHtml(name) : "Unknown"));
                    Integer msgId = cb.has("message") ? cb.get("message").getAsJsonObject().get("message_id").getAsInt() : null;
                    handlePlayerIpManagement(chatId, uuid, false, msgId);
                }
            }
        } else if (action.equals("bl")) {
            if (!isChatAdmin(fromId)) return;
            if (parts.length < 2) return;
            String subAction = parts[1];

            if (subAction.equals("list")) {
                handleBlacklistAdmin(chatId);
            } else if (subAction.equals("pips")) {
                if (parts.length < 3) return;
                UUID uuid = UUID.fromString(parts[2]);
                handlePlayerBlacklist(chatId, uuid);
            } else if (subAction.equals("rem")) {
                if (parts.length < 4) return;
                UUID uuid = UUID.fromString(parts[2]);
                String shortId = parts[3];
                String ip = ipManagerShortIds.remove(shortId);
                if (ip != null && blacklistedIps.containsKey(uuid)) {
                    blacklistedIps.get(uuid).remove(ip);
                    String name = Bukkit.getOfflinePlayer(uuid).getName();
                    sendTelegramMessage(chatId, getMsg("tg-ip-removed").replace("%ip%", escapeHtml(ip)).replace("%player%", name != null ? escapeHtml(name) : "Unknown"));
                    handlePlayerBlacklist(chatId, uuid);
                }
            }
        }

        // Answer callback to remove loading state in TG
        JsonObject answer = new JsonObject();
        answer.addProperty("callback_query_id", id);
        executeTelegramRequest("answerCallbackQuery", answer);
        saveData();
    }

    private void sendTelegramMessage(long chatId, String text) {
        sendTelegramMessage(chatId, text, null);
    }

    private void sendTelegramMessage(long chatId, String text, @Nullable JsonObject replyMarkup) {
        JsonObject json = new JsonObject();
        json.addProperty("chat_id", chatId);
        json.addProperty("text", text);
        if (replyMarkup != null) {
            json.add("reply_markup", replyMarkup);
        }
        executeTelegramRequest("sendMessage", json);
    }

    private void editTelegramMessage(long chatId, int messageId, String text, JsonObject replyMarkup) {
        JsonObject json = new JsonObject();
        json.addProperty("chat_id", chatId);
        json.addProperty("message_id", messageId);
        json.addProperty("text", text);
        if (replyMarkup != null) {
            json.add("reply_markup", replyMarkup);
        }
        executeTelegramRequest("editMessageText", json);
    }

    private void sendTelegramMessageSync(long chatId, String text) {
        JsonObject json = new JsonObject();
        json.addProperty("chat_id", chatId);
        json.addProperty("text", text);
        json.addProperty("parse_mode", "HTML");
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.telegram.org/bot" + botToken + "/sendMessage"))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(json.toString()))
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            checkTokenError(response.statusCode());
        } catch (Exception ignored) {}
    }

    private void sendTelegramMessageWithButtons(long chatId, String text, String approvalId) {
        JsonObject markup = new JsonObject();
        JsonArray keyboard = new JsonArray();
        JsonArray row1 = new JsonArray();
        row1.add(createButton(getMsg("tg-btn-approve"), "approve:" + approvalId));
        row1.add(createButton(getMsg("tg-btn-deny"), "deny:" + approvalId));
        JsonArray row2 = new JsonArray();
        row2.add(createButton(getMsg("tg-btn-blacklist"), "bl:" + approvalId));

        keyboard.add(row1);
        keyboard.add(row2);
        markup.add("inline_keyboard", keyboard);

        sendTelegramMessage(chatId, text, markup);
    }

    private void executeTelegramRequest(String method, JsonObject body) {
        if (!isRunning) return;
        if (method.equals("sendMessage") || method.equals("editMessageText")) {
            body.addProperty("parse_mode", "HTML");
        }
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.telegram.org/bot" + botToken + "/" + method))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();

        httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenAccept(response -> {
                    if (response.statusCode() != 200) {
                        String respBody = response.body();
                        if (respBody.contains("query is already answered") || respBody.contains("message is not modified")) {
                            return;
                        }
                        getLogger().severe("Telegram API error (" + method + "): " + response.statusCode() + " - " + respBody);
                        checkTokenError(response.statusCode());
                    }
                })
                .exceptionally(e -> {
                    getLogger().severe("Telegram API exception (" + method + "): " + e.getMessage());
                    return null;
                });
    }

    private JsonObject createButton(String text, String data) {
        JsonObject button = new JsonObject();
        button.addProperty("text", text);
        button.addProperty("callback_data", data);
        return button;
    }

    private synchronized void saveData() {
        JsonObject data = new JsonObject();
        JsonObject linked = new JsonObject();
        linkedChats.forEach((uuid, chatId) -> linked.addProperty(uuid.toString(), chatId));
        data.add("linkedChats", linked);

        JsonObject approved = new JsonObject();
        approvedIps.forEach((uuid, ips) -> {
            JsonObject ipMap = new JsonObject();
            ips.forEach(ipMap::addProperty);
            approved.add(uuid.toString(), ipMap);
        });
        data.add("approvedIps", approved);

        JsonObject blacklisted = new JsonObject();
        blacklistedIps.forEach((uuid, ips) -> {
            JsonArray arr = new JsonArray();
            ips.forEach(arr::add);
            blacklisted.add(uuid.toString(), arr);
        });
        data.add("blacklistedIps", blacklisted);

        JsonObject disabled = new JsonObject();
        disabledNotifications.forEach((chatId, categories) -> {
            JsonArray arr = new JsonArray();
            categories.forEach(arr::add);
            disabled.add(chatId.toString(), arr);
        });
        data.add("disabledNotifications", disabled);

        JsonObject pModes = new JsonObject();
        player2faModes.forEach((uuid, mode) -> pModes.addProperty(uuid.toString(), mode));
        data.add("player2faModes", pModes);

        try {
            String json = gson.toJson(data);
            Path tempFile = dataFile.resolveSibling(dataFile.getFileName().toString() + ".tmp");
            Files.writeString(tempFile, json);
            Files.move(tempFile, dataFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            getLogger().severe("Could not save data: " + e.getMessage());
        }
    }

    private void loadData() {
        if (!Files.exists(dataFile)) return;
        try {
            JsonObject data = JsonParser.parseString(Files.readString(dataFile)).getAsJsonObject();
            if (data.has("linkedChats")) {
                data.getAsJsonObject("linkedChats").entrySet().forEach(entry -> {
                    linkedChats.put(UUID.fromString(entry.getKey()), entry.getValue().getAsLong());
                });
            }
            if (data.has("approvedIps")) {
                data.getAsJsonObject("approvedIps").entrySet().forEach(entry -> {
                    UUID uuid = UUID.fromString(entry.getKey());
                    Map<String, Long> ips = new ConcurrentHashMap<>();
                    entry.getValue().getAsJsonObject().entrySet().forEach(ipEntry -> {
                        ips.put(ipEntry.getKey(), ipEntry.getValue().getAsLong());
                    });
                    approvedIps.put(uuid, ips);
                });
            }
            if (data.has("blacklistedIps")) {
                data.getAsJsonObject("blacklistedIps").entrySet().forEach(entry -> {
                    Set<String> ips = ConcurrentHashMap.newKeySet();
                    entry.getValue().getAsJsonArray().forEach(e -> ips.add(e.getAsString()));
                    blacklistedIps.put(UUID.fromString(entry.getKey()), ips);
                });
            }
            if (data.has("disabledNotifications")) {
                data.getAsJsonObject("disabledNotifications").entrySet().forEach(entry -> {
                    Set<String> categories = ConcurrentHashMap.newKeySet();
                    entry.getValue().getAsJsonArray().forEach(e -> categories.add(e.getAsString()));
                    disabledNotifications.put(Long.parseLong(entry.getKey()), categories);
                });
            }
            if (data.has("player2faModes")) {
                data.getAsJsonObject("player2faModes").entrySet().forEach(entry -> {
                    player2faModes.put(UUID.fromString(entry.getKey()), entry.getValue().getAsString());
                });
            }
        } catch (Exception e) {
            getLogger().severe("Could not load data: " + e.getMessage());
        }
    }

    @SuppressWarnings({"removal", "deprecation"})
    private class TelegramCommandSender implements ConsoleCommandSender {
        private final long chatId;

        public TelegramCommandSender(long chatId) {
            this.chatId = chatId;
        }

        @Override
        public void sendMessage(@NotNull String message) {
            if (message == null || message.isEmpty()) return;
            String stripped = PlainTextComponentSerializer.plainText().serialize(LegacyComponentSerializer.legacyAmpersand().deserialize(message));
            if (stripped.length() > 3800) {
                stripped = stripped.substring(0, 3800) + "... (truncated)";
            }
            sendTelegramMessage(chatId, "<code>" + escapeHtml(stripped) + "</code>");
        }

        @Override
        public void sendMessage(String @NotNull ... messages) {
            for (String msg : messages) sendMessage(msg);
        }

        @Override
        public void sendMessage(@Nullable UUID source, @NotNull String message) {
            sendMessage(message);
        }

        @Override
        public void sendMessage(@Nullable UUID source, String @NotNull ... messages) {
            sendMessage(messages);
        }

        @Override
        public @NotNull Server getServer() {
            return Bukkit.getServer();
        }

        @Override
        public @NotNull String getName() {
            return "TelegramRCON";
        }

        @Override
        public @NotNull Component name() {
            return Component.text(getName());
        }

        @Override
        public void sendMessage(@NotNull Component message) {
            sendMessage(PlainTextComponentSerializer.plainText().serialize(message));
        }

        public void sendMessage(@Nullable UUID source, @NotNull Component message) {
            sendMessage(message);
        }

        @Override
        public boolean isPermissionSet(@NotNull String name) {
            return true;
        }

        @Override
        public boolean isPermissionSet(@NotNull Permission perm) {
            return true;
        }

        @Override
        public boolean hasPermission(@NotNull String name) {
            return true;
        }

        @Override
        public boolean hasPermission(@NotNull Permission perm) {
            return true;
        }

        @Override
        public @NotNull PermissionAttachment addAttachment(@NotNull org.bukkit.plugin.Plugin plugin, @NotNull String name, boolean value) {
            return new PermissionAttachment(plugin, this);
        }

        @Override
        public @NotNull PermissionAttachment addAttachment(@NotNull org.bukkit.plugin.Plugin plugin) {
            return new PermissionAttachment(plugin, this);
        }

        @Override
        public @Nullable PermissionAttachment addAttachment(@NotNull org.bukkit.plugin.Plugin plugin, @NotNull String name, boolean value, int ticks) {
            return new PermissionAttachment(plugin, this);
        }

        @Override
        public @Nullable PermissionAttachment addAttachment(@NotNull org.bukkit.plugin.Plugin plugin, int ticks) {
            return new PermissionAttachment(plugin, this);
        }

        @Override
        public void removeAttachment(@NotNull PermissionAttachment attachment) {}

        @Override
        public void recalculatePermissions() {}

        @Override
        public @NotNull Set<PermissionAttachmentInfo> getEffectivePermissions() {
            return Set.of();
        }

        @Override
        public boolean isOp() {
            return true;
        }

        @Override
        public void setOp(boolean value) {}

        @Override
        public void sendRawMessage(@NotNull String message) {
            sendMessage(message);
        }

        @Override
        public void sendRawMessage(@Nullable UUID source, @NotNull String message) {
            sendMessage(message);
        }

        @Override
        public boolean isConversing() {
            return false;
        }

        @Override
        public void acceptConversationInput(@NotNull String input) {}

        @Override
        public boolean beginConversation(@NotNull org.bukkit.conversations.Conversation conversation) {
            return false;
        }

        @Override
        public void abandonConversation(@NotNull org.bukkit.conversations.Conversation conversation) {}

        @Override
        public void abandonConversation(@NotNull org.bukkit.conversations.Conversation conversation, @NotNull org.bukkit.conversations.ConversationAbandonedEvent event) {}

        @Override
        public @NotNull Spigot spigot() {
            return new Spigot();
        }
    }
}
