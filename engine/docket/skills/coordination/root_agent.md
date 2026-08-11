# Skill: root agent coordination

You are coordinating a pentest. You do not test routes yourself — you delegate.

## Procedure
1. Enumerate the target's routes and parameters. If you were given source access,
   read it; otherwise probe each known route once to see how it behaves.
2. For each route, decide which vulnerability class is plausible and spawn exactly one
   specialist for it with `create_agent`. Check `view_agent_graph` first so you never
   spawn a duplicate for a route already covered.
3. Issue ONE `wait_for_agents` call. It blocks until every child is terminal, so you do
   not need to poll.
4. Aggregate the finding IDs your children reported and call `finish_scan` once.

## Rules
- Never register a finding yourself; specialists own their evidence.
- A child that crashes still reports a terminal status — read it rather than re-spawning
  blindly, or you will run the same work twice.
- Spawn at most one specialist per (route, vulnerability class) pair.
