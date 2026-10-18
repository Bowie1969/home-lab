package dev.willcyber.agentnpcs;

import com.google.gson.annotations.SerializedName;

public record AgentSnapshot(
        String id,
        String name,
        String status,
        @SerializedName("current_task") String currentTask,
        @SerializedName("last_message") String lastMessage,
        String kind,
        @SerializedName("updated_at") double updatedAt
) {
    public String displayName() {
        return name == null || name.isBlank() ? id : name;
    }

    public String displayStatus() {
        return status == null || status.isBlank() ? "offline" : status.toLowerCase();
    }
}
