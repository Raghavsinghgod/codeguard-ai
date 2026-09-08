import { motion } from "framer-motion";
import { Link } from "react-router";
import {
  ArrowRight,
  Bot,
  Bug,
  Crosshair,
  FileSearch,
  Fingerprint,
  Gauge,
  KeyRound,
  Radar,
  ShieldCheck,
  Swords,
  Terminal,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ROADMAP_PHASES, SHIPPED_PARTS, TOTAL_PARTS } from "@/lib/roadmap";

const fadeUp = {
  initial: { opacity: 0, y: 24 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: "-80px" },
  transition: { duration: 0.55, ease: "easeOut" as const },
};

const CAPABILITIES = [
  {
    icon: Bot,
    title: "Strix agent team",
    body: "A multi-agent red team modeled on usestrix/strix: recon, exploitation, validation, and reporting agents collaborate, chain findings, and produce working PoCs.",
  },
  {
    icon: Swords,
    title: "Exploit validation",
    body: "Every finding ships with the exploitation path a pentester would attempt — payloads, bypass chains, and blast radius — then gets validated with a real proof-of-concept.",
  },
  {
    icon: FileSearch,
    title: "Injection deep-scan",
    body: "SQL, command, code, and template injection sinks detected across JS/TS, Python, and more — mapped to OWASP A03:2021.",
  },
  {
    icon: KeyRound,
    title: "Secrets & credentials",
    body: "Hardcoded passwords, API keys, AWS key structures, and private key blocks flagged before they leak into git history.",
  },
  {
    icon: Fingerprint,
    title: "Auth & session attacks",
    body: "JWT 'none'-alg forgery, weak randomness for tokens, and IDOR-style access-control gaps with proof-of-concept requests.",
  },
  {
    icon: Radar,
    title: "SSRF & network surface",
    body: "User-controlled outbound requests flagged with the internal-network pivots (metadata endpoints, admin panels) they enable.",
  },
  {
    icon: Gauge,
    title: "Scored pentest report",
    body: "A weighted 0–100 security score with letter grade, severity breakdown, remediations, and Markdown export.",
  },
];

const STAGES = [
  { id: "recon", label: "Recon & fingerprint" },
  { id: "probes", label: "Injection probes" },
  { id: "auth", label: "Auth & session attacks" },
  { id: "crypto", label: "Crypto & secrets sweep" },
  { id: "report", label: "Report generation" },
];

export default function Landing() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Nav */}
      <header className="sticky top-0 z-40 border-b border-border/60 bg-background/80 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="flex size-8 items-center justify-center rounded-lg bg-primary/12 ring-1 ring-primary/30">
              <Crosshair className="size-4.5 text-primary" />
            </div>
            <span className="text-[15px] font-semibold tracking-tight">
              CrackScope
            </span>
          </Link>
          <div className="flex items-center gap-2">
            <Button asChild variant="ghost" className="text-muted-foreground hover:text-foreground">
              <Link to="/dashboard">Open app</Link>
            </Button>
            <Button asChild className="rounded-full px-4">
              <Link to="/auth">
                Start free <ArrowRight className="size-4" />
              </Link>
            </Button>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="grid-bg absolute inset-0" />
        <div
          className="absolute left-1/2 top-[-260px] h-[420px] w-[720px] -translate-x-1/2 rounded-full opacity-40 blur-3xl"
          style={{ background: "radial-gradient(closest-side, oklch(0.78 0.13 168 / 0.35), transparent)" }}
        />
        <div className="relative mx-auto max-w-6xl px-6 pb-20 pt-24 sm:pt-32">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease: "easeOut" }}
            className="mx-auto max-w-3xl text-center"
          >
            <Badge
              variant="outline"
              className="mb-6 gap-2 rounded-full border-primary/30 bg-primary/10 px-3 py-1 text-[13px] text-primary"
            >
              <Bot className="size-3.5" />
              Powered by the Strix multi-agent engine · open-source DeepSeek analysis
            </Badge>
            <h1 className="text-balance text-4xl font-semibold leading-[1.08] tracking-tight sm:text-6xl">
              It attacks your code
              <span className="text-glow block text-primary">before attackers do</span>
            </h1>
            <p className="mx-auto mt-6 max-w-2xl text-pretty text-base leading-7 text-muted-foreground sm:text-lg">
              CrackScope is an automated red-team for your codebase. Teams of AI
              pentester agents — modeled on Strix — simulate injection,
              auth-bypass, crypto, and SSRF attacks, validate every finding with
              a working PoC, and hand you a scored pentest report with fixes and
              ready-to-merge patches.
            </p>
            <div className="mt-9 flex flex-col items-center justify-center gap-3 sm:flex-row">
              <Button asChild size="lg" className="h-12 rounded-full px-7 text-[15px] scan-glow">
                <Link to="/auth">
                  Run your first scan <ArrowRight className="size-4" />
                </Link>
              </Button>
              <Button asChild size="lg" variant="outline" className="h-12 rounded-full px-7 text-[15px]">
                <Link to="/dashboard">See the workspace</Link>
              </Button>
            </div>
            <p className="mt-4 text-xs text-muted-foreground">
              Free to try · No code leaves your browser until you save a report
            </p>
          </motion.div>

          {/* Terminal mock */}
          <motion.div
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.15, ease: "easeOut" }}
            className="mx-auto mt-16 max-w-3xl"
          >
            <Card className="overflow-hidden border-border/70 bg-card/80 shadow-2xl backdrop-blur scan-glow">
              <div className="flex items-center gap-1.5 border-b border-border/60 px-4 py-3">
                <span className="size-3 rounded-full bg-[oklch(0.65_0.2_25)]/70" />
                <span className="size-3 rounded-full bg-[oklch(0.75_0.15_85)]/70" />
                <span className="size-3 rounded-full bg-primary/70" />
                <span className="ml-3 font-mono text-xs text-muted-foreground">
                  crackscope scan ./server.js
                </span>
              </div>
              <div className="p-5 font-mono text-[13px] leading-6">
                <p className="text-muted-foreground">→ spawning agent team · 4 agents queued…</p>
                <p className="text-foreground">
                  <span className="text-primary">[recon]</span> 1 file · 38 lines · JavaScript
                </p>
                <p className="text-foreground">
                  <span className="text-primary">[exploitation]</span> SQLi… CMD… XSS… crafting PoCs
                </p>
                <p className="text-foreground">
                  <span className="text-primary">[validation]</span> 2 validated · 1 probable · 1 attack chain linked
                </p>
                <p className="text-destructive">
                  <span className="font-semibold">[!]</span> CMD-001 critical ·
                  server.js:12 — command injection via exec(concat)
                </p>
                <p className="text-destructive">
                  <span className="font-semibold">[!]</span> SEC-001 critical ·
                  server.js:6 — hardcoded API key
                </p>
                <p className="text-[oklch(0.75_0.15_85)]">
                  <span className="font-semibold">[~]</span> CRYPTO-002 high ·
                  server.js:21 — Math.random() session token
                </p>
                <p className="mt-2 text-foreground">
                  <span className="text-primary">score</span> 37/100 · grade{" "}
                  <span className="text-destructive font-semibold">F</span> · 3
                  findings
                </p>
                <p className="text-muted-foreground">
                  report saved · agent team finished in 0.9s · CI gate FAIL (exit 1)
                </p>
              </div>
            </Card>
          </motion.div>
        </div>
      </section>

      {/* Capabilities */}
      <section className="border-t border-border/50 py-24">
        <div className="mx-auto max-w-6xl px-6">
          <motion.div {...fadeUp} className="mx-auto max-w-2xl text-center">
            <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">
              A full agent team, one submission
            </h2>
            <p className="mt-4 text-muted-foreground">
              Detection families modeled on how real pentesters work, run by a
              collaborating agent team — every finding verified against
              simulated exploitation, not just pattern noise.
            </p>
          </motion.div>
          <div className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {CAPABILITIES.map((cap, i) => (
              <motion.div
                key={cap.title}
                {...fadeUp}
                transition={{ ...fadeUp.transition, delay: i * 0.06 }}
              >
                <Card className="group h-full border-border/60 bg-card/60 transition-colors hover:border-primary/40 hover:bg-card">
                  <CardContent className="flex h-full flex-col gap-4 p-6">
                    <div className="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary ring-1 ring-primary/25">
                      <cap.icon className="size-5" />
                    </div>
                    <div>
                      <h3 className="font-medium tracking-tight">{cap.title}</h3>
                      <p className="mt-2 text-sm leading-6 text-muted-foreground">
                        {cap.body}
                      </p>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="border-t border-border/50 bg-secondary/30 py-24">
        <div className="mx-auto max-w-6xl px-6">
          <motion.div {...fadeUp} className="mx-auto max-w-2xl text-center">
            <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">
              How a scan runs
            </h2>
            <p className="mt-4 text-muted-foreground">
              Five red-team stages execute against your submission, in order —
              you watch each one land, then read the report.
            </p>
          </motion.div>
          <div className="mx-auto mt-14 max-w-3xl">
            <ol className="relative space-y-0 border-l border-border/70 pl-0">
              {STAGES.map((stage, i) => (
                <motion.li
                  key={stage.id}
                  {...fadeUp}
                  transition={{ ...fadeUp.transition, delay: i * 0.08 }}
                  className="relative flex gap-4 pb-6 last:pb-0"
                >
                  <span className="absolute -left-[13px] flex size-6 items-center justify-center rounded-full border border-primary/40 bg-background font-mono text-[11px] text-primary">
                    {i + 1}
                  </span>
                  <div className="ml-6 pt-0.5">
                    <p className="font-mono text-sm font-medium text-foreground">
                      {stage.label}
                    </p>
                  </div>
                </motion.li>
              ))}
            </ol>
          </div>
        </div>
      </section>

      {/* Roadmap */}
      <section className="border-t border-border/50 py-24">
        <div className="mx-auto max-w-6xl px-6">
          <motion.div {...fadeUp} className="mx-auto max-w-2xl text-center">
            <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">
              Built in {TOTAL_PARTS} parts
            </h2>
            <p className="mt-4 text-muted-foreground">
              A platform this large ships in phases. Here is the full build
              plan — {SHIPPED_PARTS} shipped, {TOTAL_PARTS - SHIPPED_PARTS} to
              go, and the workspace tracks progress live.
            </p>
          </motion.div>
          <div className="mt-12 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {ROADMAP_PHASES.map((phase, i) => (
              <motion.div
                key={phase.phase}
                {...fadeUp}
                transition={{ ...fadeUp.transition, delay: i * 0.05 }}
              >
                <Card className="h-full border-border/60 bg-card/60">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between">
                      <p className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
                        Phase {phase.phase}
                      </p>
                      <span className="text-xs text-muted-foreground">
                        {phase.parts.length} parts
                      </span>
                    </div>
                    <h3 className="mt-2 font-medium tracking-tight">{phase.name}</h3>
                    <ul className="mt-4 space-y-2.5">
                      {phase.parts.slice(0, 4).map((part) => (
                        <li key={part.part} className="flex items-start gap-2.5 text-sm">
                          <span
                            className={
                              part.status === "shipped"
                                ? "mt-1 size-1.5 shrink-0 rounded-full bg-primary"
                                : part.status === "up-next"
                                  ? "mt-1 size-1.5 shrink-0 rounded-full bg-[oklch(0.75_0.15_85)]"
                                  : "mt-1 size-1.5 shrink-0 rounded-full bg-muted-foreground/40"
                            }
                          />
                          <span className="leading-5">
                            <span className="font-medium">{part.title}</span>
                            {part.status === "shipped" && (
                              <ShieldCheck className="ml-1.5 inline size-3.5 text-primary" />
                            )}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
            <motion.div {...fadeUp} transition={{ ...fadeUp.transition, delay: 0.2 }}>
              <Card className="h-full border-primary/30 bg-primary/5">
                <CardContent className="flex h-full flex-col p-6">
                  <Bug className="size-5 text-primary" />
                  <p className="mt-4 text-sm leading-6 text-muted-foreground">
                    The full 25-part plan — including fuzzer, CI/CD guards,
                    team workspaces, and the public API — lives in the
                    workspace roadmap.
                  </p>
                  <Button asChild variant="outline" className="mt-auto w-fit gap-2 rounded-full">
                    <Link to="/dashboard">
                      View all 25 parts <ArrowRight className="size-4" />
                    </Link>
                  </Button>
                </CardContent>
              </Card>
            </motion.div>
          </div>
        </div>
      </section>

      {/* Final CTA */}
      <section className="border-t border-border/50 bg-secondary/30 py-24">
        <motion.div
          {...fadeUp}
          className="mx-auto max-w-2xl px-6 text-center"
        >
          <h2 className="text-balance text-3xl font-semibold tracking-tight sm:text-4xl">
            Your code has weaknesses. Find them first.
          </h2>
          <p className="mt-4 text-muted-foreground">
            Sign in, paste a file, and watch the attack simulation run — free.
          </p>
          <Button asChild size="lg" className="mt-8 h-12 rounded-full px-8 text-[15px] scan-glow">
            <Link to="/auth">
              Start scanning <ArrowRight className="size-4" />
            </Link>
          </Button>
        </motion.div>
      </section>

      <footer className="border-t border-border/50 py-8">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 text-xs text-muted-foreground">
          <p>CrackScope — automated red-team for source code. Use on code you own.</p>
          <p>Part {SHIPPED_PARTS}/{TOTAL_PARTS} · Build plan v1</p>
        </div>
      </footer>
    </div>
  );
}
