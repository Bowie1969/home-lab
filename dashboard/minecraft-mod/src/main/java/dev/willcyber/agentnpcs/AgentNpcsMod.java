package dev.willcyber.agentnpcs;

import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerTickEvents;
import net.fabricmc.fabric.api.event.player.UseEntityCallback;
import net.minecraft.network.chat.Component;
import net.minecraft.world.InteractionResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

public final class AgentNpcsMod implements ModInitializer {
    public static final String MOD_ID = "agentnpcs";
    public static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);

    @Override
    public void onInitialize() {
        String configured = System.getProperty(
                "agentnpcs.api",
                System.getenv().getOrDefault("AGENT_NPC_API_URL", "http://127.0.0.1:8793")
        );
        String token = System.getProperty(
                "agentnpcs.token",
                System.getenv().getOrDefault("AGENT_NPC_API_TOKEN", "")
        );
        AgentNpcManager npcs = new AgentNpcManager();
        AgentService service = new AgentService(new AgentGateway(URI.create(configured), token), npcs);

        CommandRegistrationCallback.EVENT.register((dispatcher, registryAccess, environment) ->
                AgentCommands.register(dispatcher, service, npcs));
        ServerTickEvents.END_SERVER_TICK.register(service::tick);
        UseEntityCallback.EVENT.register((player, level, hand, entity, hitResult) -> {
            if (level.isClientSide()) {
                return InteractionResult.PASS;
            }
            String agentId = npcs.agentId(entity).orElse(null);
            if (agentId == null) {
                return InteractionResult.PASS;
            }
            AgentSnapshot agent = service.agent(agentId).orElse(null);
            if (agent == null) {
                player.sendSystemMessage(Component.literal("Agent " + agentId + " is not in the latest gateway snapshot."));
            } else {
                String task = agent.currentTask() == null ? "No active task" : agent.currentTask();
                player.sendSystemMessage(Component.literal(agent.displayName() + " • " + agent.displayStatus()));
                player.sendSystemMessage(Component.literal(task));
                player.sendSystemMessage(Component.literal(
                        "Use /agents assign " + agent.id() + " <task>, /agents pause " + agent.id() + ", or /agents resume " + agent.id()
                ));
            }
            return InteractionResult.SUCCESS;
        });

        LOGGER.info("Agent NPCs connected to {}", configured);
    }
}
