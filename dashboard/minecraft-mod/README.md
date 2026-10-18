# Agent NPCs

Agent NPCs is a Fabric 26.3 server mod. Each external AI agent appears as a
stationary villager whose nameplate shows its latest state. Players can inspect
an NPC and queue a task or lifecycle request without giving Minecraft shell
access to the agent host.

## Build and install

Requirements: Java 25 and a Fabric 26.3 server with Fabric API.

```sh
cd minecraft-mod
JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64 ./gradlew build
```

Copy `build/libs/agent-npcs-0.2.0.jar` and the matching Fabric API jar into the
server's `mods/` directory. For singleplayer, put both in the instance's
`mods/` directory instead.

Start the dashboard gateway first:

```sh
cd ..
python3 server.py --host 127.0.0.1 --port 8793
```

The mod defaults to `http://127.0.0.1:8793`. Override it for a remote Minecraft
server with `AGENT_NPC_API_URL`, or with the JVM property
`-Dagentnpcs.api=http://host:8793`.

## Register an agent

An agent or adapter registers itself and reports subsequent state changes:

```sh
curl -X POST http://127.0.0.1:8793/api/agents/register \
  -H 'Content-Type: application/json' \
  -d '{"id":"architect","name":"Architect","kind":"codex","status":"idle"}'

curl -X POST http://127.0.0.1:8793/api/agents/architect/state \
  -H 'Content-Type: application/json' \
  -d '{"status":"working","current_task":"Design the storage layer"}'
```

For a network-exposed gateway, set `LAB_DASHBOARD_AGENT_TOKEN` on the dashboard
and the same value as `AGENT_NPC_API_TOKEN` on the Minecraft server. Adapters
must send it as `Authorization: Bearer <token>` on state-changing requests.

## In-game commands

Run `/agents sync` after registering agents, then use:

- `/agents list`
- `/agents summon <id>`
- `/agents summon-all`
- `/agents assign <id> <task>`
- `/agents pause <id>`
- `/agents resume <id>`
- `/agents cancel <id>`
- `/agents dismiss <id>` — removes only the NPC, not the real agent

Right-click an agent NPC to see its status, current task, and the management
commands. NPCs glow while their agent reports `working`.

## Adapter contract

Minecraft commands are appended as JSON objects to
`../data/agent_commands.jsonl`. Each contains `id`, `agent_id`, `action`,
`created_at`, and `source`; an `assign` command also contains `task`. An adapter
should consume only its own agent ID, decide whether to accept the request, and
POST authoritative state back to `/api/agents/<id>/state`.

The gateway accepts these states: `idle`, `queued`, `working`, `paused`,
`blocked`, `done`, `error`, and `offline`. Tasks are limited to 500 characters,
agent IDs are restricted to safe URL characters, and the gateway never turns a
queued task into a process or shell command.
