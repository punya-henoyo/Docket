# Skill: source-aware (whitebox) testing

When the target's source is available locally, use it to aim — not to conclude.

## Procedure
1. Map routes to handlers, and note for each: which request fields reach a sink, and
   what the sink is (SQL string, shell command, HTML render, file path, deserializer).
2. Rank routes by sink danger, not by how the code looks.
3. Hand each specialist the concrete file:line of the suspected sink so its finding can
   be anchored to real source (`location.file`), which is what makes the SARIF result
   land on the right line in code scanning.

## The rule that matters
Reading a dangerous-looking sink is a HYPOTHESIS, not a finding. It must still be
reproduced against the running app before `finding` is called. Source tells you where
to aim; only a reproduced request/response proves exploitability.
