# Keystone Red vs Blue Engagement Plan

**Status:** Draft for authorization  
**Range:** Keystone  
**Offensive platform:** EvilKit  
**Exercise type:** Controlled, instrumented adversary emulation  
**Primary research question:** How reliably can EvilKit complete a representative attack chain, and how quickly and completely can the Keystone blue team detect, contain, and recover from it?

## 1. Exercise principles

- Keystone is the only authorized environment. The signed scope manifest controls over any assumption in this document.
- The range is assessed black-box. Red receives business context, authorized targets, and objectives, but not range source code, vulnerability inventories, flags, or intended solution paths.
- The exercise uses synthetic identities, synthetic business data, canary credentials, and inert objective artifacts.
- Red and blue are scored independently. A useful engagement can produce a high red score and a high blue score.
- All actions must be attributable, reversible, timestamped, and observable by the white cell.
- Safety violations override game scoring.

## 2. Research hypotheses

The engagement tests these hypotheses:

1. EvilKit can complete at least 70% of authorized objectives without operator correction.
2. Blue detects at least 60% of meaningful red actions and begins triage within 10 minutes of the first high-confidence signal.
3. A tuned replay improves median detection time by at least 30% without more than a 10% increase in false-positive workload.
4. The range can be restored to a verified clean state within 30 minutes of exercise stop.

These thresholds are starting values. Freeze them before the first scored run.

## 3. Roles

| Role | Responsibility |
|---|---|
| Will — exercise owner and observer/data lead | Observes without coaching, preserves the research record, owns authorization, resolves disputed scoring, and makes final restart decisions. |
| Existing white-cell agent | Enforces scope, monitors safety, timestamps injects, correlates evidence, proposes scoring, and coordinates the approved range reset procedure. |
| Red cell | Operates EvilKit from the approved jump host and records every action. |
| Blue cell | Monitors, investigates, contains, eradicates, and restores using normal defensive tooling. |

The white-cell agent may automatically call `STOP-KEYSTONE` when a mandatory stop condition is observed. It may isolate the approved red jump host and revoke exercise-only credentials through pre-authorized controls, but it may not expand scope, waive a stop condition, or restart the exercise. Will remains the human authority for authorization, disputed findings, and restart. Neither may coach red or blue during a scored run.

## 4. Required authorization packet

The exercise director must complete and sign the following before execution:

- Engagement ID and approved time window.
- Exact CIDRs, hostnames, applications, tenant IDs, and accounts in scope.
- Explicit exclusions, including range control plane, hypervisors, management interfaces, and operator workstations.
- Approved red jump-host identity and egress policy.
- Approved techniques and any technique-specific rate limits.
- Emergency contacts and the person authorized to call `STOP-KEYSTONE`.
- Data retention period and approved evidence location.
- Confirmation that no production routing, production identity provider, or real customer data is reachable.

An empty or ambiguous scope means no start.

## 5. EvilKit 8/10 readiness gate

Run this gate on a disposable Keystone clone or dedicated validation segment before the engagement. Each category is worth two points.

| Category | Two-point criterion |
|---|---|
| Reliability | Completes three consecutive dry runs without a crash, orphaned process, or manual repair. |
| Objective coverage | Exercises the approved initial-access, execution, discovery, movement, and objective-access simulations. |
| Telemetry fidelity | Every meaningful action produces a correlated red log, white-cell event, and expected endpoint or network signal. |
| Operator control | Pause, resume, per-action approval, target allow-list, and emergency stop all behave as designed. |
| Containment compliance | No out-of-scope traffic, uncontrolled propagation, real credential capture, or persistence beyond reset. |

Entry requires at least 8/10, with no zero-point category. The emergency stop must pass three consecutive tests and the white cell must verify a clean snapshot restore. Reliability or containment failures block the engagement regardless of total score.

## 6. Scenario

### Narrative

A simulated external actor targets Keystone to reach a synthetic high-value service and prove access to an inert crown-jewel record. Red chooses its route based only on externally observable behavior. Blue knows the exercise window and business-critical services but does not receive red's route, timing, indicators, or objective location.

### Red objectives

1. Establish a controlled foothold on an authorized exposed workload.
2. Demonstrate execution using an inert white-cell marker.
3. Enumerate only in-scope identities, services, and trust relationships.
4. Move to one additional authorized security zone or identity context.
5. Reach the synthetic crown-jewel service.
6. Read the objective token and stage a harmless manifest inside the range; do not exfiltrate files outside Keystone.
7. Demonstrate one approved persistence simulation using a white-cell-provided, self-expiring mechanism.
8. Remove red-created artifacts after exercise stop and provide the white cell with a cleanup manifest.

Red is not given a prescribed exploit path. Each action must have a plausible hypothesis and stay within the technique allow-list.

### Blue objectives

1. Maintain service availability and useful telemetry.
2. Detect and correlate red activity across identity, endpoint, application, and network sources.
3. Triage alerts into a defensible incident narrative.
4. Contain affected identities and workloads without broad, unnecessary outages.
5. Identify the initial access path, affected scope, and objective reached.
6. Eradicate red artifacts and restore normal service.
7. Produce a concise incident record with evidence, confidence, and remaining uncertainty.

Blue may take any normal defensive action except attacking red infrastructure, accessing the red operator console, or using out-of-band white-cell information.

## 7. Run design

Use one unscored validation and two scored conditions.

### Run 0 — instrumentation validation

- Blue is not scored and may observe.
- Red executes a short, benign subset of the chain.
- White verifies clock synchronization, event correlation, kill switch, range reset, and evidence capture.
- Any telemetry gap affecting a scored metric must be fixed before Run 1.

### Run 1 — blind baseline

- Restore the frozen clean snapshot.
- Blue receives only its normal context, the exercise window, and the business-service map.
- Red receives the authorization packet and objective, but no defender rules or expected alerts.
- White records actions and adjudicates outcomes without coaching.

### Purple interval

- Conduct a 45-minute hotwash after evidence is frozen.
- Disclose the action timeline and missed signals.
- Blue may add or tune detections and response playbooks.
- Red may fix reliability defects but may not change the tested capability set without creating a new condition.

### Run 2 — tuned replay

- Restore the same clean baseline.
- Keep topology, objective, background traffic, team size, and time budget constant.
- Change harmless identifiers such as account names, marker hashes, and timing jitter so Run 2 is not a simple indicator-matching test.
- Compare detection, triage, containment, and false-positive workload with Run 1.

For stronger research, repeat each condition three times. If only one blue team is available, report learning effects as a limitation rather than claiming a clean causal result.

## 8. Suggested six-hour schedule

| Time | Activity |
|---|---|
| T-30 min | White-cell preflight, snapshot check, clock check, and communications check. |
| 00:00 | Director reads scope, stop conditions, and code word; teams acknowledge. |
| 00:15 | Red actions begin; blue operates normally. |
| 01:30 | White issues a business-context inject if the scenario needs one. |
| 03:15 | Latest time for red to begin the objective phase. |
| 04:00 | Exercise actions stop; evidence freeze begins. |
| 04:15 | Blue completes containment and states affected scope. |
| 04:45 | White validates cleanup and range health. |
| 05:00 | Hotwash. |
| 06:00 | End; evidence sealed and follow-up owners assigned. |

## 9. Rules of engagement

### Allowed by default

- Reconnaissance and enumeration within the signed scope and rate limits.
- Use of white-cell-issued accounts, canary credentials, and synthetic data.
- Approved adversary-emulation techniques that are reversible and recorded.
- Controlled access to the objective token and creation of inert marker files.
- Blue-team isolation, credential revocation, service restart, and host rebuild actions inside scope.

### Prohibited by default

- Any traffic to a destination not present in the signed scope manifest.
- Internet egress, production connectivity, or pivoting through the host running Keystone.
- Interaction with the hypervisor, orchestration/control plane, logging back end, backup system, or safety tooling unless explicitly placed in scope.
- Destructive actions, ransomware behavior, destructive encryption, disk wiping, firmware changes, denial of service, resource exhaustion, or uncontrolled propagation.
- Capturing real credentials, personal data, browser sessions, or operator secrets.
- Disabling or tampering with safety monitoring, evidence collection, time synchronization, or the kill switch.
- Persistence that survives the approved snapshot reset or does not self-expire.
- Social engineering, physical access, third-party services, and attacks against red or blue operator workstations.
- Unbounded guessing, spraying, or brute force. Any credential testing needs a written account list, attempt cap, and lockout-safe rate.

### Safety penalties

- Out-of-scope attempt: minus 25 points and immediate white-cell review.
- Availability impact caused by an undeclared action: minus 15 points.
- Missing or materially false action log: minus 10 points per event.
- Confirmed scope escape, real-data exposure, uncontrolled propagation, or safety-control tampering: terminate the run and invalidate the score.

## 10. Stop and recovery plan

Anyone may say `STOP-KEYSTONE`. Only the exercise director may authorize restart.

White immediately stops the clock and performs these actions in order:

1. Isolate the approved red jump host at the range boundary.
2. Revoke exercise credentials and automation tokens.
3. Preserve volatile evidence needed to explain the event.
4. Confirm that no traffic left the authorized boundary.
5. Snapshot affected workloads if investigation is required.
6. Restore the frozen clean state or execute the approved cleanup manifest.
7. Validate critical services, logging, identity, and the objective store before restart.

Mandatory stop conditions are scope escape, unexplained external traffic, control-plane access, uncontrolled propagation, loss of safety telemetry for more than two minutes, real credential or personal-data discovery, or material instability affecting the range host.

## 11. Evidence and event model

Synchronize all systems to a common clock and store canonical timestamps in UTC. Keep secrets out of the dashboard; use evidence references into the protected evidence store.

Every meaningful event should contain:

```json
{
  "timestamp": "2026-10-14T00:00:00.000Z",
  "run_id": "KEYSTONE-R1",
  "action_id": "R-001",
  "team": "red|blue|white",
  "phase": "initial-access|execution|discovery|movement|objective|containment|recovery",
  "target_alias": "ks-app-01",
  "technique_id": "ATT&CK-or-local-technique-id",
  "event_type": "attempt|success|alert|triage|containment|restore|stop",
  "result": "success|failure|partial|not-applicable",
  "evidence_ref": "protected-store-reference"
}
```

Red logs intent, start/end time, target alias, technique, expected signal, result, operator intervention, and cleanup artifact. Blue logs alert source, first-seen time, triage start, confidence, affected scope, action taken, result, and evidence. White logs run boundaries, injects, objective validation, safety events, and scoring decisions.

## 12. Metrics

### Red effectiveness

- Objective completion rate.
- Action success rate and retries per successful action.
- Time to first foothold and time to objective.
- Percentage of actions requiring manual operator correction.
- Percentage of meaningful actions detected before red reached the next phase.
- Cleanup completeness and number of undeclared artifacts.

### Blue effectiveness

- Telemetry coverage by phase and data source.
- Mean and median time to detect, acknowledge, contain, eradicate, and recover.
- Detection precision: true red-correlated alerts divided by all alerts investigated during the window.
- Containment completeness: affected assets controlled divided by affected assets known to white.
- Scope accuracy, including false inclusions and missed assets.
- Service impact caused by response actions.

### Research quality

- Missing-event rate and clock skew.
- Background-alert workload.
- Differences in topology, data, staffing, or tool configuration between runs.
- Operator interventions and deviations from the plan.

Use medians for time comparisons and publish raw event counts alongside percentages. Do not treat missing telemetry as a successful evasion; score it as an instrumentation gap.

## 13. Scoring

### Red score — 100 points

| Category | Points |
|---|---:|
| Initial foothold established | 15 |
| Controlled execution demonstrated | 10 |
| In-scope discovery completed | 10 |
| Authorized movement demonstrated | 15 |
| Crown-jewel objective reached | 25 |
| Approved persistence simulation | 5 |
| Reliability and operator autonomy | 10 |
| Evidence and cleanup quality | 10 |

Apply safety penalties after the raw score. Detection does not erase points already earned; successful blue containment prevents later objectives from being earned.

### Blue score — 100 points

| Category | Points |
|---|---:|
| Telemetry coverage | 15 |
| Detection and correlation | 20 |
| Triage speed and accuracy | 15 |
| Containment speed and completeness | 20 |
| Root-cause and affected-scope accuracy | 10 |
| Eradication and clean recovery | 15 |
| Incident record and evidence quality | 5 |

White scores only evidence-backed outcomes. Publish red and blue scores side by side with the timing metrics; do not collapse them into a single winner.

## 14. Team briefings

### Red packet

Red receives the signed scope, approved jump host, technique allow-list, rate limits, objective narrative, time budget, evidence schema, stop procedure, and cleanup requirement. Red does not receive vulnerability details, intended routes, defensive rules, or objective location.

### Blue packet

Blue receives the business-service map, normal escalation process, approved defensive tools, exercise window, critical availability constraints, evidence schema, and stop procedure. Blue does not receive EvilKit configuration, red timing, route, markers, indicators, or objective location.

### White packet

The existing white-cell agent holds the operational white-cell packet: the full target-to-alias map, objective validation method, range reset procedure, safety monitoring view, red allow-list, expected telemetry map, scoring workbook, and adjudication log. Will receives a read-only observer view plus the authorization, emergency-stop, and final-adjudication controls.

The agent's decisions must be written to an append-only log with the triggering evidence, rule applied, confidence, and action taken. If it loses telemetry, becomes unresponsive, or cannot explain a safety decision, the run stops and control returns to Will.

## 15. Deliverables

Within one business day, produce:

- Signed scope and final rules of engagement.
- Normalized JSONL event set and protected evidence index.
- Red action timeline and cleanup manifest.
- Blue incident timeline and affected-scope statement.
- White-cell adjudication and separate red/blue scorecards.
- Run 1 versus Run 2 metric comparison.
- Detection gaps, EvilKit reliability defects, and safety-control findings.
- Prioritized remediation backlog with owner and due date.

The final report must distinguish confirmed observations, reasonable inferences, instrumentation gaps, and untested claims.

## 16. Go/no-go checklist

- [ ] Written authorization and exact scope are signed.
- [ ] Production and internet routes are proven absent.
- [ ] Red source address and jump host are allow-listed and monitored.
- [ ] EvilKit readiness is at least 8/10 with no zero category.
- [ ] Kill switch passes three consecutive tests.
- [ ] Clean snapshot restore is timed and verified.
- [ ] Clocks are synchronized and event correlation works.
- [ ] Synthetic identities, data, tokens, and objective are loaded.
- [ ] Red, blue, and white packets are separated.
- [ ] Stop code word and emergency contacts are acknowledged.
- [ ] Evidence location and retention policy are approved.
- [ ] Director gives explicit `GO`.

## 17. Decisions to freeze before scheduling

1. Exact Keystone scope manifest and exclusions.
2. Exercise duration and number of repetitions.
3. EvilKit capability set being evaluated.
4. Credential-testing allowance and rate limits, if any.
5. Synthetic crown-jewel objective and validation method.
6. Blue team's normal defensive toolset and availability constraints.
7. Evidence retention period and report audience.
