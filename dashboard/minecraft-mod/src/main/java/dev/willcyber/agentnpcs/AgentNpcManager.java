package dev.willcyber.agentnpcs;

import net.minecraft.ChatFormatting;
import net.minecraft.core.BlockPos;
import net.minecraft.network.chat.Component;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.EntityTypes;
import net.minecraft.world.entity.npc.villager.Villager;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class AgentNpcManager {
    private static final String NPC_TAG = "agentnpcs.npc";
    private static final String ID_TAG_PREFIX = "agentnpcs.id.";
    private final Map<String, UUID> entities = new ConcurrentHashMap<>();

    public Villager summon(ServerPlayer player, AgentSnapshot agent, int offset) {
        Entity existing = find(player.level().getServer(), agent.id());
        if (existing instanceof Villager villager) {
            villager.teleportTo(player.getX() + offset, player.getY(), player.getZ() + 2.0);
            update(villager, agent);
            return villager;
        }

        ServerLevel level = player.level();
        Villager villager = new Villager(EntityTypes.VILLAGER, level);
        villager.snapTo(player.getX() + offset, player.getY(), player.getZ() + 2.0, player.getYRot(), 0.0f);
        villager.setNoAi(true);
        villager.setPermanentlyInvulnerable(true);
        villager.setPersistenceRequired();
        villager.addTag(NPC_TAG);
        villager.addTag(ID_TAG_PREFIX + agent.id());
        update(villager, agent);
        level.addFreshEntity(villager);
        entities.put(agent.id(), villager.getUUID());
        return villager;
    }

    public void updateAll(MinecraftServer server, Collection<AgentSnapshot> agents) {
        for (AgentSnapshot agent : agents) {
            Entity entity = find(server, agent.id());
            if (entity instanceof Villager villager) {
                update(villager, agent);
            }
        }
    }

    public boolean dismiss(MinecraftServer server, String agentId) {
        Entity entity = find(server, agentId);
        if (entity == null) {
            return false;
        }
        entity.discard();
        entities.remove(agentId);
        return true;
    }

    public Optional<String> agentId(Entity entity) {
        if (!entity.entityTags().contains(NPC_TAG)) {
            return Optional.empty();
        }
        return entity.entityTags().stream()
                .filter(tag -> tag.startsWith(ID_TAG_PREFIX))
                .map(tag -> tag.substring(ID_TAG_PREFIX.length()))
                .findFirst();
    }

    private Entity find(MinecraftServer server, String agentId) {
        UUID known = entities.get(agentId);
        if (known != null) {
            for (ServerLevel level : server.getAllLevels()) {
                Entity entity = level.getEntity(known);
                if (entity != null) {
                    return entity;
                }
            }
        }
        for (ServerLevel level : server.getAllLevels()) {
            for (Entity entity : level.getAllEntities()) {
                if (agentId(entity).filter(agentId::equals).isPresent()) {
                    entities.put(agentId, entity.getUUID());
                    return entity;
                }
            }
        }
        return null;
    }

    private void update(Villager villager, AgentSnapshot agent) {
        ChatFormatting color = switch (agent.displayStatus()) {
            case "working" -> ChatFormatting.AQUA;
            case "queued" -> ChatFormatting.YELLOW;
            case "paused", "blocked" -> ChatFormatting.GOLD;
            case "done" -> ChatFormatting.GREEN;
            case "error" -> ChatFormatting.RED;
            case "offline" -> ChatFormatting.DARK_GRAY;
            default -> ChatFormatting.WHITE;
        };
        villager.setCustomName(Component.literal(agent.displayName() + " [" + agent.displayStatus() + "]").withStyle(color));
        villager.setCustomNameVisible(true);
        villager.setGlowingTag(agent.displayStatus().equals("working"));
    }
}
