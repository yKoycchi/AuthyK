package org.koy.authyk;

import org.bukkit.ChatColor;
import org.bukkit.GameMode;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitRunnable;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerChatEvent;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class AuthyK extends JavaPlugin implements CommandExecutor, Listener {

    private Connection connection;
    private Set<String> loggedInPlayers = new HashSet<>();
    private Map<String, Integer> loginTasks = new HashMap<>();

    private Map<String, GameMode> lastGameModes = new HashMap<>();

    @Override
    public void onEnable() {
        this.getCommand("register").setExecutor(this);
        this.getCommand("login").setExecutor(this);
        this.getServer().getPluginManager().registerEvents(this, this);

        try {
            File dataFolder = this.getDataFolder();
            if (!dataFolder.exists()) {
                dataFolder.mkdirs();
            }
            File databaseFile = new File(dataFolder, "players.db");
            Class.forName("org.sqlite.JDBC");
            connection = DriverManager.getConnection("jdbc:sqlite:" + databaseFile);
            PreparedStatement statement = connection.prepareStatement("CREATE TABLE IF NOT EXISTS players (username TEXT, salt TEXT, password TEXT)");
            statement.execute();
            statement.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        player.setGameMode(GameMode.ADVENTURE);
        player.setInvisible(true);
        try {
            PreparedStatement statement = connection.prepareStatement("SELECT username FROM players WHERE username = ?");
            statement.setString(1, player.getName());
            ResultSet resultSet = statement.executeQuery();
            if (resultSet.next()) {
                startLoginTask(player, ChatColor.BOLD + "Digite '/login" + ChatColor.GREEN + "" + ChatColor.BOLD + " senha" + ChatColor.RESET + "' " + ChatColor.BOLD + "para logar");
            } else {
                startLoginTask(player, ChatColor.BOLD + "Digite '/register" + ChatColor.GREEN + "" + ChatColor.BOLD + " senha senha" + ChatColor.RESET + "' " + ChatColor.BOLD +  "para se registrar");
            }
            resultSet.close();
            statement.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void startLoginTask(Player player, String message) {
        BukkitRunnable task = new BukkitRunnable() {
            private int count = 0;

            @Override
            public void run() {
                if (count >= 6 || loggedInPlayers.contains(player.getName())) {
                    cancel();
                    loginTasks.remove(player.getName());
                } else if (count == 5) {
                    player.kickPlayer(ChatColor.RED + "" + ChatColor.BOLD + "Você demorou muito para logar!");
                } else {
                    player.sendMessage(message);
                    count++;
                }
            }
        };
        task.runTaskTimer(this, 0, 100);
        loginTasks.put(player.getName(), task.getTaskId());
    }


    @EventHandler
    public void onPlayerMove(PlayerMoveEvent event) {
        Player player = event.getPlayer();
        if (!loggedInPlayers.contains(player.getName())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onPlayerDamage(EntityDamageEvent event) {
        if (event.getEntity() instanceof Player) {
            Player player = (Player) event.getEntity();
            if (!loggedInPlayers.contains(player.getName())) {
                event.setCancelled(true);
            }
        }
    }

    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        Player player = event.getPlayer();
        loggedInPlayers.remove(player.getName()); // Desloga o jogador
        lastGameModes.put(player.getName(), player.getGameMode());
    }

    @EventHandler
    public void onPlayerChat(PlayerChatEvent event) {
        Player player = event.getPlayer();
        // Se o jogador não estiver logado, cancela o evento do chat
        if (!loggedInPlayers.contains(player.getName())) {
            String msg = event.getMessage().toLowerCase();
            // Permite apenas os comandos /register e /login
            if (!msg.startsWith("/register") && !msg.startsWith("/login")) {
                event.setCancelled(true);
            }
        }
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (sender instanceof Player) {
            Player player = (Player) sender;
            try {
                if (command.getName().equalsIgnoreCase("register")) {
                    PreparedStatement checkStatement = connection.prepareStatement("SELECT username FROM players WHERE username = ?");
                    checkStatement.setString(1, player.getName());
                    ResultSet checkResult = checkStatement.executeQuery();
                    if (checkResult.next()) {
                        player.sendMessage(ChatColor.RED + "" + ChatColor.BOLD + "Você já está registrado!");
                        checkResult.close();
                        checkStatement.close();
                        return true;
                    }
                    checkResult.close();
                    checkStatement.close();

                    if (args.length == 2 && args[0].equals(args[1])) {
                        SecureRandom random = new SecureRandom();
                        byte[] salt = new byte[16];
                        random.nextBytes(salt);
                        String hashedPassword = hashPassword(args[0], salt);
                        PreparedStatement statement = connection.prepareStatement("INSERT INTO players (username, salt, password) VALUES (?, ?, ?)");
                        statement.setString(1, player.getName());
                        statement.setString(2, Base64.getEncoder().encodeToString(salt));
                        statement.setString(3, hashedPassword);
                        statement.execute();
                        statement.close();
                        player.sendMessage(ChatColor.BOLD + "Você se" + ChatColor.GREEN + "" + ChatColor.BOLD + " registrou " + ChatColor.RESET + "" + ChatColor.BOLD + "com sucesso!");
                        loggedInPlayers.add(player.getName());
                        player.setInvisible(false);
                        this.getServer().getScheduler().cancelTask(loginTasks.get(player.getName()));
                        // Restaura o último GameMode do jogador
                        GameMode lastGameMode = lastGameModes.getOrDefault(player.getName(), GameMode.SURVIVAL);
                        player.setGameMode(lastGameMode);
                    }
                    return true;
                } else if (command.getName().equalsIgnoreCase("login")) {
                    if (loggedInPlayers.contains(player.getName())) {
                        player.sendMessage(ChatColor.RED + "" + ChatColor.BOLD + "Você já está logado!");
                        return true;
                    }

                    if (args.length == 1) {
                        PreparedStatement statement = connection.prepareStatement("SELECT salt, password FROM players WHERE username = ?");
                        statement.setString(1, player.getName());
                        ResultSet resultSet = statement.executeQuery();
                        if (resultSet.next()) {
                            String salt = resultSet.getString("salt");
                            String storedPassword = resultSet.getString("password");
                            String hashedPassword = hashPassword(args[0], Base64.getDecoder().decode(salt));
                            if (storedPassword.equals(hashedPassword)) {
                                player.sendMessage(ChatColor.GREEN + "" + ChatColor.BOLD + "Você está logado!");
                                loggedInPlayers.add(player.getName());
                                player.setInvisible(false);
                                this.getServer().getScheduler().cancelTask(loginTasks.get(player.getName()));
                                // Restaura o último GameMode do jogador
                                GameMode lastGameMode = lastGameModes.getOrDefault(player.getName(), GameMode.SURVIVAL);
                                player.setGameMode(lastGameMode);
                            } else {
                                player.sendMessage(ChatColor.RED + "" + ChatColor.BOLD + "Senha incorreta!");
                            }
                        }
                        resultSet.close();
                        statement.close();
                    }
                    return true;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return false;
    }


    private String hashPassword(String password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = factory.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(hash);
    }
}
