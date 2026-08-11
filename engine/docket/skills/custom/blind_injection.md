# Skill: proving BLIND injection

A sink whose output never reaches the response is still exploitable — you just need a
side channel instead of an echo.

## Timing (most reliable, always available)
1. Send a baseline request; record elapsed time.
2. Send the same request with a delay injected (`; sleep 5`, `' AND SLEEP(5)-- `).
3. Compare. A delta close to the delay you injected, reproducible across repeats, is
   proof. One slow request is not — repeat it before filing.

## Boolean
Find a payload pair that differs only in a true/false condition and produces two
distinguishable responses (status, length, body). That difference IS the oracle.

## Reporting
State plainly in the PoC that the vulnerability is blind and name the channel you used.
"The response body was identical; the injected `sleep 3` moved latency from 4ms to
3012ms" is evidence. "The parameter appears injectable" is not.
