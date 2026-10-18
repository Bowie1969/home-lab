package dev.willcyber.agentnpcs;

import net.minecraft.commands.CommandSourceStack;
import net.minecraft.network.chat.Component;
import net.minecraft.server.MinecraftServer;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public final class AgentService {
    private final AgentGateway gateway;
    private final AgentNpcManager npcs;
    private final ExecutorService io = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "agent-npcs-gateway");
        thread.setDaemon(true);
        return thread;
    });
    private final AtomicBoolean syncing = new AtomicBoolean();
    private final Map<String, AgentSnapshot> agents = new ConcurrentHashMap<>();
    private int ticks;

    public AgentService(AgentGateway gateway, AgentNpcManager npcs) {
        this.gateway = gateway;
        this.npcs = npcs;
    }

    public Collection<AgentSnapshot> agents() {
        return List.copyOf(agents.values());
    }

    public Optional<AgentSnapshot> agent(String id) {
        return Optional.ofNullable(agents.get(id));
    }

    public void tick(MinecraftServer server) {
        ticks++;
        if (ticks >= 100) {
            ticks = 0;
            sync(server, null);
        }
    }

    public void sync(MinecraftServer server, CommandSourceStack feedback) {
        if (!syncing.compareAndSet(false, true)) {
            return;
        }
        io.execute(() -> {
            try {
                List<AgentSnapshot> fresh = gateway.listAgents();
                server.execute(() -> {
                    agents.clear();
                    fresh.forEach(agent -> agents.put(agent.id(), agent));
                    npcs.updateAll(server, fresh);
                    if (feedback != null) {
                        feedback.sendSuccess(() -> Component.literal("Synced " + fresh.size() + " agent(s)."), false);
                    }
                });
            } catch (Exception error) {
                server.execute(() -> {
                    if (feedback != null) {
                        feedback.sendFailure(Component.literal("Agent sync failed: " + concise(error)));
                    }
                });
            } finally {
                syncing.set(false);
            }
        });
    }

    public void command(CommandSourceStack source, String agentId, String action, String task) {
        MinecraftServer server = source.getServer();
        io.execute(() -> {
            try {
                gateway.sendCommand(agentId, action, task);
                server.execute(() -> {
                    source.sendSuccess(() -> Component.literal("Queued " + action + " for " + agentId + "."), true);
                    sync(server, null);
                });
            } catch (Exception error) {
                server.execute(() -> source.sendFailure(Component.literal("Agent command failed: " + concise(error))));
            }
        });
    }

    private static String concise(Exception error) {
        String message = error.getMessage();
        return message == null || message.isBlank() ? error.getClass().getSimpleName() : message;
    }
}
