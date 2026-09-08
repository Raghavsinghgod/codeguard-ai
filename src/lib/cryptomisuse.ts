// CrackScope Part 15 — crypto misuse detector.
// Detection of cryptographic implementation mistakes beyond the Part 1
// weak-hash rules: hardcoded IVs, ECB mode, static/reused nonces, weak key
// sizes, disabled padding/GCM misuse, and certificate/pinning pitfalls.
// Output uses the shared Finding shape; findings are taint-independent
// (crypto structure is dangerous regardless of input flow).
import type { Finding, ScanInput, Severity } from "./scanner";

const CATEGORY = "Cryptographic Failures";
const OWASP_A02 = "A02:2021 – Cryptographic Failures";

interface CryptoRule {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  remediation: string;
  payload: string;
  pattern: RegExp;
  maxMatchesPerFile: number;
  safeHints?: string[];
}

const RULES: CryptoRule[] = [
  {
    id: "CIV-001",
    title: "Hardcoded initialization vector (IV)",
    severity: "high",
    description:
      "A cipher IV is a literal constant. With a fixed IV, identical plaintexts encrypt to identical ciphertexts, enabling pattern analysis and dictionary attacks; with CBC, a chosen-plaintext attacker can detect message prefixes.",
    remediation:
      "Generate a fresh random IV per encryption (crypto.randomBytes(16) / os.urandom(16)) and prepend or transmit it alongside the ciphertext — IVs may be public but must never repeat with the same key.",
    payload: `Attack: encrypt known plaintexts with the hardcoded IV, build a codebook, match observed ciphertext blocks\nEffect: message content inferred without breaking the cipher.`,
    pattern: /(?:createCipheriv|createDecipheriv|crypto\.createCipheriv|Cipher\.)\s*\(\s*[^,]+,\s*[^,]+,\s*(?:["'][^"']{8,}["']|Buffer\.from\s*\(\s*["'][^"']+["'])|iv\s*[:=]\s*(?:Buffer\.from\s*\(\s*)?["'][0-9a-fA-F]{16,}["']/i,
    maxMatchesPerFile: 4,
    safeHints: ["randomBytes", "random", "urandom", "getRandomValues", "nonce"],
  },
  {
    id: "CIV-002",
    title: "ECB mode used for encryption",
    severity: "high",
    description:
      "ECB mode encrypts identical blocks to identical ciphertext. Structured data (images, JSON, repeated fields) leaks its pattern — the famous ECB penguin — and block-level replay becomes trivial.",
    remediation:
      "Use an authenticated mode: AES-256-GCM (preferred) or CBC + HMAC. Never use ECB except for single-block KDF-style primitives.",
    payload: `Attack: encrypt two records differing only in a secret field under ECB, compare ciphertext blocks\nEffect: which fields match / differ is visible; CBC bit-flipping style replay also applies.`,
    pattern: /(?:aes-?\d+-ecb|ECBMode|MODE_ECB|'ecb'|"ecb"|mode\s*:\s*['"]ecb['"])/i,
    maxMatchesPerFile: 4,
    safeHints: ["gcm", "cbc", "ctr"],
  },
  {
    id: "CIV-003",
    title: "Static nonce/counter reused across encryptions (GCM/CTR)",
    severity: "critical",
    description:
      "A nonce is a fixed literal or reused counter value with GCM or CTR mode. Nonce reuse in GCM leaks the authentication key (forgery becomes possible) and in CTR XORs keystreams to recover plaintexts — catastrophic, silent failure.",
    remediation:
      "Derive a unique nonce per message: random 12 bytes for GCM (2^32 message limit per key), or a monotonically increasing counter persisted with the key. Never hardcode, and never reset counters.",
    payload: `Attack: capture two ciphertexts encrypted with the same nonce/counter, XOR them\nEffect: C1⊕C2 = P1⊕P2 — plaintexts recovered without the key; GCM auth key recoverable → forgery.`,
    pattern: /(?:createCipheriv|aes-?\d+-(?:gcm|ctr))\s*\(\s*[^)]*(?:["'][0-9a-fA-F]{8,}["']|(?:nonce|iv|counter)\s*[:=]\s*(?:Buffer\.from\s*\(\s*)?["'][^"']+["'])/i,
    maxMatchesPerFile: 4,
    safeHints: ["randomBytes", "random", "getRandomValues", "counter++", "increment"],
  },
  {
    id: "CKEY-001",
    title: "Weak key size (RSA < 2048 bits or AES < 128 bits)",
    severity: "high",
    description:
      "RSA keys below 2048 bits and AES keys below 128 bits are within reach of well-funded attackers (RSA-1024 factoring is documented state-level capability). Keys too small fail modern compliance baselines outright.",
    remediation:
      "Use RSA-3072+ or ECC (P-256/Ed25519) for asymmetric, AES-256 for symmetric; rotate undersized keys and re-encrypt stored data.",
    payload: `Attack: CADO-NHS factoring of RSA-1024 (~$100k cloud cost, hours-to-days)\nEffect: private key recovered; all signatures and encrypted data compromised.`,
    pattern: /(?:generateKeyPairSync|generateKeyPair|rsa\.generateKey|crypto\.generateKey)\s*\([^)]*(?:modulusLength\s*:\s*(?:512|768|1024|1536)\b)|(?:aes-?\d+|AES-?\d+)\s*(?:-\d+)?/i,
    maxMatchesPerFile: 4,
    safeHints: ["2048", "3072", "4096", "256", "p-256", "ed25519"],
  },
  {
    id: "CKEY-002",
    title: "Encryption without authentication (no MAC/AEAD)",
    severity: "high",
    description:
      "Data is encrypted with CBC/CTR and no message authentication code. Ciphertext is malleable: bit-flipping attacks alter decrypted plaintext (e.g. change an amount or a username) without knowing the key, and padding-oracle decryption becomes possible.",
    remediation:
      "Use AES-GCM (authenticated) or add an HMAC-SHA256 over the ciphertext (encrypt-then-MAC) and verify before decrypting; reject on tag failure.",
    payload: `Attack: flip bits in the IV/first block of a CBC ciphertext to alter the first plaintext block; or exploit padding-oracle responses\nEffect: transaction amounts, user ids, or flags altered in transit — decryption oracle in the worst case.`,
    pattern: /createCipheriv\s*\(\s*["']aes-?\d+-(?:cbc|ctr)/i,
    maxMatchesPerFile: 4,
    safeHints: ["gcm", "hmac", "createHmac", "authTag", "setAuthTag", "poly1305"],
  },
  {
    id: "CPBK-001",
    title: "Weak password hashing (unsalted or fast hash)",
    severity: "critical",
    description:
      "Passwords are hashed with a fast digest (SHA-256/MD5 family) or with no salt. GPUs compute billions of SHA-256 hashes per second, so stolen databases fall to dictionary attacks within hours.",
    remediation:
      "Use a memory-hard KDF: bcrypt (cost ≥ 12), scrypt, or Argon2id. Store the salt with the hash (KDF output formats include it), and add per-user pepper where feasible.",
    payload: `Attack: 8×RTX-4090 hashcat run against the leaked table: ~100 GH/s SHA-256\nEffect: most user passwords cracked in hours; credential reuse spreads the damage.`,
    pattern: /createHash\s*\(\s*["']sha256["']\s*\)\s*\.\s*update\s*\(\s*(?:password|passwd|pwd|userPassword)|hashlib\.sha256\s*\(\s*(?:password|passwd|pwd)|sha256\s*\(\s*(?:password|passwd|pwd)/i,
    maxMatchesPerFile: 4,
    safeHints: ["bcrypt", "argon2", "scrypt", "pbkdf2", "hashPassword", "kdf"],
  },
  {
    id: "CPBK-002",
    title: "PBKDF2 with too few iterations",
    severity: "medium",
    description:
      "PBKDF2 is used with a low iteration count (below current OWASP guidance of 600k for SHA-256). Attack cost stays low enough for large-scale offline cracking of stolen password hashes.",
    remediation:
      "Raise iterations to at least 600,000 (SHA-256) or 210,000 (SHA-512), or migrate to Argon2id; tune so a login takes ~100–250 ms server-side.",
    payload: `Attack: hashcat -m 10900 against the stolen table at 10k iterations\nEffect: ~30x cheaper cracking than OWASP-baseline PBKDF2 — large-scale password recovery.`,
    pattern: /pbkdf2(?:Sync)?\s*\([^)]*(?:,\s*(?:1000|2048|4096|10000|100000)\s*[,)])/i,
    maxMatchesPerFile: 4,
    safeHints: ["600000", "210000", "argon2", "iterations"],
  },
  {
    id: "CCERT-001",
    title: "Certificate/hostname verification disabled in TLS client",
    severity: "high",
    description:
      "A TLS client is configured to skip certificate or hostname verification (checkServerIdentity override, ca: false, InsecureSkipVerify). MITM attackers impersonate the upstream service and capture credentials or inject responses.",
    remediation:
      "Remove the bypass; provide a private CA bundle for self-signed internal services, or pin the expected certificate/SPKI hash. Never ship verification-disabled code.",
    payload: `Attack: ARP-spoof / rogue AP between client and upstream, present any certificate\nEffect: full interception of requests and responses including API credentials.`,
    pattern: /checkServerIdentity\s*:\s*\(\s*\)\s*=>|ca\s*:\s*(?:false|null)\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|verify_mode\s*:\s*ssl\.CERT_NONE/i,
    maxMatchesPerFile: 4,
    safeHints: ["NODE_EXTRA_CA_CERTS", "pinned", "tofu"],
  },
  {
    id: "CRAND-001",
    title: "IV/salt/seed derived from timestamp or counter",
    severity: "medium",
    description:
      "Cryptographic randomness is sourced from Date.now(), a counter, or a low-entropy seed instead of a CSPRNG. Predictable IVs/salts enable precomputation and keystream recovery.",
    remediation:
      "Source all IVs, salts, and seeds from a CSPRNG (crypto.randomBytes, os.urandom, crypto.getRandomValues); timestamps may be mixed in but never as the sole source.",
    payload: `Attack: precompute ciphertexts for the predictable IV space (timestamps are guessable within seconds)\nEffect: keystream recovery for CTR/GCM or prefix detection for CBC — plaintext inference without the key.`,
    pattern: /(?:iv|salt|seed|nonce)\w*\s*[:=]\s*(?:Date\.now\(\)|new Date\(\)\.getTime\(\)|counter\b|Date\.now\(\)\.toString)/i,
    maxMatchesPerFile: 4,
    safeHints: ["randomBytes", "urandom", "getRandomValues", "randomUUID"],
  },
  {
    id: "CDES-001",
    title: "Legacy cipher (DES/3DES/RC4/Blowfish) in use",
    severity: "high",
    description:
      "A broken or deprecated cipher is used for encryption: DES (56-bit key, brute-forceable since 1998), 3DES (Sweet32 birthday attacks), RC4 (biased keystream, prohibited in TLS), Blowfish (weak key schedule).",
    remediation:
      "Migrate to AES-256-GCM. For legacy data, decrypt once and re-encrypt with a modern cipher during a planned migration window.",
    payload: `Attack: Sweet32 birthday attack on 3DES (64-bit blocks) — ~2^32 bytes of captured traffic\nEffect: plaintext blocks recovered from TLS/VPN sessions still using legacy ciphers.`,
    pattern: /(?:createCipheriv|createDecipheriv)\s*\(\s*["'](?:des|3des|des-ede|rc4|blowfish)|new\s+(?:DES|RC4|Blowfish)\w*\s*\(/i,
    maxMatchesPerFile: 4,
    safeHints: ["aes", "legacy-compat"],
  },
];

/** Run the crypto misuse pass over one file. `excludeLines` skips already-reported lines. */
export function detectCryptoMisuse(input: ScanInput, excludeLines: Set<number>): Finding[] {
  const lines = input.content.split("\n");
  const findings: Finding[] = [];
  const reportedLines = new Set<number>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("#")) continue;
    if (excludeLines.has(i + 1) || reportedLines.has(i + 1)) continue;

    for (const rule of RULES) {
      const m = rule.pattern.exec(line);
      if (!m) continue;
      if (rule.safeHints?.some((h) => line.toLowerCase().includes(h.toLowerCase()))) continue;

      findings.push({
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        category: CATEGORY,
        owasp: OWASP_A02,
        file: input.name,
        line: i + 1,
        snippet: trimmed.slice(0, 220),
        description: rule.description,
        remediation: rule.remediation,
        payload: rule.payload,
      });
      reportedLines.add(i + 1);
      break;
    }
  }
  return findings;
}
