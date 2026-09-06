# Thermal safety — Fulmar 1.2.36 build 156

## Safety boundary

Fulmar treats thermal protection as an adaptive workload control with a separate
emergency admission and process-lifecycle boundary. The native host samples macOS `ProcessInfo.thermalState` and
the authenticated DeepSeek Harness running-session flag every two seconds. Samples
contain only timestamps, coarse thermal state, and a Boolean activity bit; prompt,
response, tool, path, and credential content never enters the circuit breaker.

The guard applies to the app-owned Ollama route. Cloud inference does not consume the
local-generation budget. Local concurrency remains one for every profile.
This includes unqualified Ollama models admitted through Compatibility mode. Their
normal output ceiling is already 2,048 tokens, so Eco mode retains that ceiling and
still enforces the five-second inter-generation rest. Fast/Balanced/Deep profile
selection remains available only for exact release-qualified `qwen3.8:27b-mlx`.

## Production policy

- Fair or unknown pressure immediately enters Eco mode without interrupting the
  active turn. Four minutes of sustained nominal generation also enters Eco mode.
- Eco mode caps later local outputs at 2,048 tokens and enforces at least five seconds
  between completed local generations. The native policy file is private, atomic,
  schema-bound, revalidated on every local request, and contains no conversation data.
- Nominal local generation has no arbitrary wall-clock cut-off.
- Fifteen continuously constrained active minutes retain a bounded emergency
  fail-safe. Nominal temperature resets this constrained-only budget.
- Tool gaps shorter than 90 seconds retain the active budget. A real idle interval
  resets it.
- Serious pressure stops immediately and starts a 90-second minimum cooldown.
- Critical pressure stops immediately and starts a ten-minute cooldown.
- A critical sample upgrades an existing hold; continued serious/critical pressure
  extends its deadline.
- Recovery requires both the deadline and one uninterrupted minute of nominal
  temperature. Fair, serious, critical, or unknown readings reset that recovery
  window.

Elapsed active time uses monotonic uptime and caps each sampling delta at ten seconds,
so sleep, clock changes, or a stalled event loop cannot invent an unbounded budget.

Eco mode remains usable and is shown in the native status area. A stable minute of
nominal temperature clears pressure-driven Eco mode; a real 90-second idle interval
clears sustained-work Eco mode. Provider switching remains available, and Eco limits
never alter DeepSeek, OpenAI, Anthropic, LAN, or custom API requests.

Returning to Normal is a verified persistence boundary. A failed write is not proof
that the durable file contains either Normal or Eco, so Fulmar blocks every new local
admission until it can save and read back Normal. It does not hard-stop an already
running turn solely for this persistence failure; any memory-pressure hold remains
held, a stopped cooldown runtime does not restart, and cloud routes remain available.
The native status stays orange and identifies the automatic policy-repair retry;
Performance Center and **Restart Local Services** remain available for recovery. Only
a verified Normal write may promote a newly started local endpoint from provider
control-plane access to inference, reopen the browser or schedule queue, release a
hold, restart the selected local model, acknowledge post-install/handoff health, or
publish green Ready.
Provider repair remains available through the isolated control plane, and switching
to a cloud/custom route bypasses the retained local-only thermal state. A blocked
local Ready callback fails its protected readiness waiter immediately with the
current policy- or memory-pressure error rather than timing out or reporting success.
If a background wake is deferred after migration preparation has already completed,
recovery resumes that same one-shot lifecycle from its waiting-for-runtime phase; it
does not strand the scheduler by trying to begin migration a second time.
If foreground protection arrives after child launch but before Ready publication,
Fulmar retains a one-shot token for that exact runtime generation and authenticated
endpoint. Recovery waits for its topology check, finalizes that same verified endpoint
once, or performs an exact stop and fresh start if either identity changed. A cooldown,
lock, protected transition, or runtime exit clears the token; startup blocked before
child launch continues through the separate deferred-start path.

The 2,048-token Eco output cap is a workload limit, not a conversation stop. When a
foreground root task reaches any provider output limit, Fulmar records the completed
segment and queues a fresh DSH follow-up that continues the unfinished user task. It
does not synthesize a missing assistant fragment or pretend that the user sent the
follow-up. New user input takes precedence, subagents remain under their parent task,
and a fixed twelve-follow-up budget ends with one bounded progress summary rather
than an infinite loop. Emergency thermal admission closure still takes precedence
and can stop local work immediately.

## Emergency trip sequence

On an emergency trip Fulmar synchronously closes browser, Quick Chat, schedule, and protected
runtime admissions; rotates the readiness generation; and stops only the exact DSH
and Ollama `Process` instances launched by its controller. A stop that cannot be
verified locks local inference rather than reopening it. Existing Workspace recovery
checkpoints remain available if a model was interrupted during a file mutation. The
conversation stays visible behind a translucent explanation with direct provider and
performance actions; completed work and task state remain saved.

The cooldown trigger and bounded deadline are stored in preferences. Deadline
extensions are persisted at most once per 30 seconds, except that escalation is
immediate. Relaunch cannot bypass an active hold. A lightweight background-schedule
launch does not load the selected local model while cooling; it can wait for verified recovery and then
resume the due lifecycle once.

The separate Ollama startup-readiness wait may last up to 90 seconds when macOS is
reclaiming warm model/GPU resources. That interval performs only bounded ownership and
health probes; it does not generate tokens, increase concurrency, or bypass thermal
admission. Cancellation or an emergency thermal trip still stops the exact child.

## Qualification and limitations

The deterministic suite covers Eco activation/recovery, fixed policy enforcement,
continuous-constrained accounting, state transitions, persistence bounds, extension
batching, short tool gaps, idle reset, sleep/clock jumps, cloud-route exclusion, and
fail-closed lockout. Existing lifecycle tests cover exact-child stop, escalation,
reaping, overlap, and unrelated-process isolation. Release qualification uses a
bounded real-Qwen tool matrix and a deterministic provider for long workflows; it
must not intentionally recreate a multi-minute uncontrolled thermal stress run.

This control materially reduces risk but cannot guarantee that macOS will never enter
thermal emergency sleep. Apple exposes a coarse state rather than temperature or fan
telemetry, firmware remains authoritative, and other applications or environmental
conditions can heat the machine. A user should still stop work and improve cooling if
the chassis becomes unusually hot, fans remain at maximum, or macOS reports a thermal
event.
