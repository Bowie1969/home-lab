package dev.willcyber.agentnpcs;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class AgentCommands {
    private AgentCommands() {
    }

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher, AgentService service, AgentNpcManager npcs) {
        dispatcher.register(Commands.literal("agents")
                .then(Commands.literal("sync")
                        .executes(context -> sync(context.getSource(), service)))
                .then(Commands.literal("list")
                        .executes(context -> list(context.getSource(), service)))
                .then(Commands.literal("summon")
                        .then(Commands.argument("id", StringArgumentType.word())
                                .executes(context -> summon(
                                        context.getSource(), service, npcs,
                                        StringArgumentType.getString(context, "id")))))
                .then(Commands.literal("summon-all")
                        .executes(context -> summonAll(context.getSource(), service, npcs)))
                .then(Commands.literal("assign")
                        .then(Commands.argument("id", StringArgumentType.word())
                                .then(Commands.argument("task", StringArgumentType.greedyString())
                                        .executes(context -> command(
                                                context.getSource(), service,
                                                StringArgumentType.getString(context, "id"), "assign",
                                                StringArgumentType.getString(context, "task"))))))
                .then(action("pause", service))
                .then(action("resume", service))
                .then(action("cancel", service))
                .then(Commands.literal("dismiss")
                        .then(Commands.argument("id", StringArgumentType.word())
                                .executes(context -> dismiss(
                                        context.getSource(), npcs,
                                        StringArgumentType.getString(context, "id"))))));
    }

    private static com.mojang.brigadier.builder.LiteralArgumentBuilder<CommandSourceStack> action(
            String action, AgentService service) {
        return Commands.literal(action)
                .then(Commands.argument("id", StringArgumentType.word())
                        .executes(context -> command(
                                context.getSource(), service,
                                StringArgumentType.getString(context, "id"), action, null)));
    }

    private static int sync(CommandSourceStack source, AgentService service) {
        service.sync(source.getServer(), source);
        source.sendSuccess(() -> Component.literal("Syncing agents..."), false);
        return 1;
    }

    private static int list(CommandSourceStack source, AgentService service) {
        List<AgentSnapshot> agents = new ArrayList<>(service.agents());
        agents.sort(Comparator.comparing(AgentSnapshot::id));
        if (agents.isEmpty()) {
            source.sendFailure(Component.literal("No agents cached. Run /agents sync first."));
            return 0;
        }
        source.sendSuccess(() -> Component.literal("Agents (" + agents.size() + "):"), false);
        for (AgentSnapshot agent : agents) {
            String task = agent.currentTask() == null ? "" : " — " + agent.currentTask();
            source.sendSuccess(() -> Component.literal("• " + agent.id() + " [" + agent.displayStatus() + "]" + task), false);
        }
        return agents.size();
    }

    private static int summon(CommandSourceStack source, AgentService service, AgentNpcManager npcs, String id) {
        AgentSnapshot agent = service.agent(id).orElse(null);
        if (agent == null) {
            source.sendFailure(Component.literal("Unknown agent '" + id + "'. Run /agents sync first."));
            return 0;
        }
        try {
            ServerPlayer player = source.getPlayerOrException();
            npcs.summon(player, agent, 0);
            source.sendSuccess(() -> Component.literal("Summoned " + agent.displayName() + "."), true);
            return 1;
        } catch (Exception error) {
            source.sendFailure(Component.literal("This command must be run by a player."));
            return 0;
        }
    }

    private static int summonAll(CommandSourceStack source, AgentService service, AgentNpcManager npcs) {
        try {
            ServerPlayer player = source.getPlayerOrException();
            int offset = 0;
            for (AgentSnapshot agent : service.agents()) {
                npcs.summon(player, agent, offset++ * 2);
            }
            int count = offset;
            source.sendSuccess(() -> Component.literal("Summoned " + count + " agent NPC(s)."), true);
            return count;
        } catch (Exception error) {
            source.sendFailure(Component.literal("This command must be run by a player."));
            return 0;
        }
    }

    private static int command(CommandSourceStack source, AgentService service, String id, String action, String task) {
        service.command(source, id, action, task);
        return 1;
    }

    private static int dismiss(CommandSourceStack source, AgentNpcManager npcs, String id) {
        boolean removed = npcs.dismiss(source.getServer(), id);
        if (!removed) {
            source.sendFailure(Component.literal("No loaded NPC for '" + id + "'."));
            return 0;
        }
        source.sendSuccess(() -> Component.literal("Dismissed NPC for " + id + ". The agent was not stopped."), true);
        return 1;
    }
}
