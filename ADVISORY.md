# Expression Language Injection leading to Remote Code Execution in Comviva Revenue Plus

## Summary

Comviva Revenue Plus (MobiLytix / Customer Value Management family) by Comviva
Technologies Ltd contains an **Expression Language (EL) injection** vulnerability
in the user-administration module. The `manageUser` endpoint evaluates the
**name** of an arbitrary request parameter server-side as a Java EL expression
before rendering the response. A method-name denylist intended to block
reflective calls can be bypassed, allowing an authenticated, low-privilege
remote attacker to execute arbitrary operating-system commands in the context of
the application-server process.

## Details

- **Vendor:** Comviva Technologies Ltd (Mahindra Comviva)
- **Product:** Revenue Plus (MobiLytix / Customer Value Management)
- **Affected version:** 3.0.0 (other 2.x / 3.x versions likely affected, not tested)
- **Vulnerability type:** CWE-917 (Expression Language Injection) → CWE-94 (Code Injection)
- **Affected component:** `POST /rp/manageUser` endpoint (`manageUsersAction`,
  user-administration module); injection occurs through the request **parameter name**
- **Attack vector:** Network; authentication required (any session able to reach `manageUsersAction`)
- **Severity:** Critical
- **CVSS v3.1:** 9.9 (Critical) — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`
- **Status:** Unsupported When Assigned — product past end of support
  (standard support ended 2022-10-31, extended support ended 2023-10-31)

## Description

The `manageUser` endpoint takes the raw **name** (not the value) of a request
parameter and evaluates it as a server-side Java EL expression before the
response is rendered. The only control protecting this evaluation is a denylist
of reflective method names (e.g. `getMethod`, `invoke`).

The denylist is built on the wrong abstraction: it blocks *method invocations*
by name but does not account for **constructor-based** access to equivalent
capability. A no-argument constructor call on a standard JDK class that exposes a
scripting runtime yields a script engine with full Java interop, from which OS
command execution is reachable — without ever calling a denylisted method name.
This is a design flaw in the control (denylist over a reflection/EL surface),
not a single missing filter entry.

Server-side evaluation can be confirmed non-destructively by supplying a harmless
string-transform expression as the parameter name and observing the **computed**
(not merely reflected) result in the response body:

```
Parameter name sent : ft9ao${"zhz".toString().replace("h","d")}sizq2
Response contains    : ft9aozdzsizq2
```

The transformation `zhz` → `zdz` only occurs if the expression was actually
evaluated server-side.

> A full weaponized exploit chain is intentionally **not** published. The product
> is end-of-life and will not be patched, and operators may still run it in
> production. This advisory describes the vulnerability class, root cause, and
> affected component — which is sufficient for coordination and to let operators
> assess and mitigate their exposure.

## Impact

An authenticated, low-privilege remote attacker can achieve arbitrary OS command
execution in the context of the application-server OS account. Confirmed
follow-on risk from that foothold includes reading application configuration and
database credentials from disk, server-side session hijacking of other users,
and pivoting into the internal network the application server resides on.

## Remediation

No patch is available; the product is end-of-life. Operators should:

- Migrate to a supported product.
- Restrict network access to the application (trusted administrative networks / VPN only).
- Do not evaluate user-controlled input (including parameter names) as EL
  expressions; treat them as data. If dynamic expression evaluation is required,
  use an allowlist of permitted variables and functions rather than a denylist of
  method names.
- Remove or disable scripting-engine (`ScriptEngineManager` / Nashorn) access
  from the component's runtime classpath if it is not a legitimate dependency.
- Run the application server under a least-privilege OS account.

## Timeline

- 2026-07-23 — Vulnerability reported to the vendor (Comviva); request for a security contact
- 2026-07-24 — Reported to VulnCheck (CNA); vendor coordination initiated
- 2026-11-24 — 120-day coordinated-disclosure deadline reached, no vendor response
- 2026-11-25 — Public disclosure

## References

- https://www.comviva.com/support/revenue-plus-end-of-support-notification/
- https://www.comviva.com/wp-content/uploads/2017/08/MahindraComviva_Revenue_Plus.pdf

## Credit

Discovered by TAH Joel Néhémie GUELASSE.
