import { motion } from "framer-motion";
import { Link } from "react-router";
import {
  ShieldCheck,
  Crosshair,
  FileSearch,
  Terminal,
  ArrowRight,
  Lock,
  Bug,
  KeyRound,
  Radar,
  ChevronRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import logo from "@/assets/logo.svg";
import { ROADMAP_PHASES, TOTAL_PARTS, SHIPPED_PARTS } from "@/lib/roadmap";

const CAPABILITIES = [
  {
    icon: Crosshair,
    title: "Injection probes",
    body: "SQL, command, and template injection payloads fired against string-built queries and shell calls.",
  },
  {
    icon: Bug,
    title: "XSS & deserialization",
    body: "Raw-HTML sinks, prototype pollution, and unsafe deserialization gadget hunting.",
  },
  {
    icon: KeyRound,
    title: "Secrets sweep",
    body: "Hardcoded API keys, tokens, passwords, and committed .env credentials.",
  },
  {
    icon: Lock,
    title: "Crypto audit",
    body: "Weak hashes, predictable randomness, static IVs, and disabled TLS verification.",
  },
  {
    icon: Radar,
    title: "Attack simulation",
    body: "Every finding ships with the exact payload an attacker would try — and why it works.",
  },
  {
    icon: FileSearch,
    title: "Pentest report",
    body: "OWASP-mapped findings, severity scoring, simulated exploit narrative, and Markdown export.",
  },
];

const TERMINAL_LINES = [
  { text: "$ crackscope run ./checkout-service", tone: "cmd" },
  { text: "▸ Recon — 14 files, 2,318 lines fingerprinted", tone: "dim" },
  { text: "▸ Injection probes — SQL sink hit at billing.ts:41", tone: "warn" },
  { text: "▸ Secrets sweep — AWS key committed at .env:3", tone: "crit" },
  { text: "▸ Crypto audit — Math.random() token at auth.ts:88", tone: "warn" },
  { text: "✓ Report ready — score 34/100 · 2 critical · 3 high", tone: "ok" },
] as const;

function toneClass(tone: string) {
  if (tone === "cmd") return "text-foreground";
  if (tone === "crit") return "text-red-400";
  if (tone === "warn") return "text-amber-400";
  if (tone === "ok") return "text-primary";
  return "text-muted-foreground";
}

export default function Landing() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Nav */}
      <header className="sticky top-0 z-40 border-b border-border/60 bg-background/80 backdrop-blur-md">
        <div className="mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-6">
          <Link to="/" className="flex items-center gap-2.5">
            <img src={logo} alt="CrackScope" className="size-8 rounded-lg" />
            <span className="text-[15px] font-semibold tracking-tight">CrackScope</span>
            <Badge variant="secondary" className="ml-1 hidden sm:inline-flex">
              Part 1 / {TOTAL_PARTS}
            </Badge>
          </Link>
          <nav className="flex items-center gap-1">
            <a
              href="#capabilities"
              className="hidden rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:text-foreground sm:block"
            >
              Capabilities
            </a>
            <a
              href="#roadmap"
              className="hidden rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:text-foreground sm:block"
            >
              Roadmap
            </a>
            <Button asChild className="ml-2 cursor-pointer gap-1.5">
              <Link to="/auth">
                Launch scanner <ArrowRight className="size-4" />
              </Link>
            </Button>
          </nav>
        </div>
      </header>

      {/* Hero */}
      <section className="relative overflow-hidden">
        <div
          className="pointer-events-none absolute inset-0 -z-10 opacity-40"
          style={{
            background:
              "radial-gradient(600px 320px at 50% -60px, var(--primary) 0%, transparent 70%)",
          }}
        />
        <div className="mx-auto grid w-full max-w-6xl gap-12 px-6 pb-20 pt-20 lg:grid-cols-[1.05fr_1fr] lg:items-center lg:pb-28 lg:pt-28">
          <div>
            <motion.div
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              <Badge variant="outline" className="mb-5 gap-1.5 border-primary/30 text-primary">
                <ShieldCheck className="size-3.5" />
                AI-assisted offensive security, pointed at your own code
              </Badge>
            </motion.div>
            <motion.h1
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.55, delay: 0.05 }}
              className="text-balance text-4xl font-semibold leading-[1.08] tracking-tight sm:text-5xl lg:text-[3.4rem]"
            >
              Think like an attacker.
              <br />
              <span className="text-primary">Ship like an engineer.</span>
            </motion.h1>
            <motion.p
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.55, delay: 0.12 }}
              className="mt-5 max-w-xl text-pretty text-[17px] leading-7 text-muted-foreground"
            >
              CrackScope runs a battery of simulated penetration tests against your
              source code — injection, XSS, secrets, crypto misuse, broken auth —
              then hands you a scored pentest report with the exact exploit an
              attacker would attempt, and how to shut it down.
            </motion.p>
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.55, delay: 0.18 }}
              className="mt-8 flex flex-wrap items-center gap-3"
            >
              <Button asChild size="lg" className="cursor-pointer gap-2 shadow-lg shadow-primary/20">
                <Link to="/auth">
                  Run your first scan <ArrowRight className="size-4" />
                </Link>
              </Button>
              <Button asChild size="lg" variant="outline" className="cursor-pointer gap-2">
                <a href="#roadmap">
                  See the 25-part plan <ChevronRight className="size-4" />
                </a>
              </Button>
            </motion.div>
            <p className="mt-5 text-xs text-muted-foreground">
              Runs fully in your browser · nothing leaves your machine · no agents to install
            </p>
          </div>

          {/* Terminal card */}
          <motion.div
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="relative"
          >
            <div className="absolute -inset-3 -z-10 rounded-3xl bg-primary/10 blur-2xl" />
            <div className="overflow-hidden rounded-2xl border border-border/70 bg-card shadow-2xl shadow-black/30">
              <div className="flex items-center gap-2 border-b border-border/60 px-4 py-3">
                <span className="size-3 rounded-full bg-red-400/70" />
                <span className="size-3 rounded-full bg-amber-400/70" />
                <span className="size-3 rounded-full bg-emerald-400/70" />
                <span className="ml-3 flex items-center gap-1.5 text-xs text-muted-foreground">
                  <Terminal className="size-3.5" /> crackscope — attack simulation
                </span>
              </div>
              <div className="space-y-2.5 p-5 font-mono text-[13px] leading-relaxed">
                {TERMINAL_LINES.map((l, i) => (
                  <motion.p
                    key={l.text}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.5 + i * 0.35, duration: 0.35 }}
                    className={toneClass(l.tone)}
                  >
                    {l.text}
                  </motion.p>
                ))}
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Capabilities */}
      <section id="capabilities" className="border-t border-border/60 py-20">
        <div className="mx-auto w-full max-w-6xl px-6">
          <div className="max-w-2xl">
            <p className="text-sm font-medium text-primary">Capabilities</p>
            <h2 className="mt-2 text-3xl font-semibold tracking-tight">
              A full pentest battery, on every scan
            </h2>
            <p className="mt-3 text-muted-foreground">
              The Part 1 engine simulates six attack classes over 20+ detection rules,
              mapped to the OWASP Top 10. Deeper AST and AI analysis arrive in later parts.
            </p>
          </div>
          <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {CAPABILITIES.map((c, i) => (
              <motion.div
                key={c.title}
                initial={{ opacity: 0, y: 16 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-60px" }}
                transition={{ duration: 0.45, delay: i * 0.06 }}
                className="group rounded-2xl border border-border/70 bg-card p-6 shadow-sm transition-all hover:-translate-y-0.5 hover:border-primary/30 hover:shadow-md"
              >
                <div className="flex size-10 items-center justify-center rounded-xl bg-primary/10 text-primary transition-colors group-hover:bg-primary/15">
                  <c.icon className="size-5" />
                </div>
                <h3 className="mt-4 text-[15px] font-semibold">{c.title}</h3>
                <p className="mt-1.5 text-sm leading-6 text-muted-foreground">{c.body}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Roadmap */}
      <section id="roadmap" className="border-t border-border/60 bg-secondary/40 py-20">
        <div className="mx-auto w-full max-w-6xl px-6">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div className="max-w-2xl">
              <p className="text-sm font-medium text-primary">The build plan</p>
              <h2 className="mt-2 text-3xl font-semibold tracking-tight">
                25 parts, shipped in the open
              </h2>
              <p className="mt-3 text-muted-foreground">
                A full offensive-security platform is a long project. We build it in 25
                parts — {SHIPPED_PARTS} shipped, the rest sequenced across five phases.
              </p>
            </div>
            <div className="flex items-center gap-3 rounded-full border border-border/70 bg-card px-4 py-2 text-sm">
              <span className="font-semibold text-primary">
                {SHIPPED_PARTS}/{TOTAL_PARTS}
              </span>
              <span className="text-muted-foreground">parts complete</span>
            </div>
          </div>

          <div className="mt-10 space-y-8">
            {ROADMAP_PHASES.map((phase) => (
              <div key={phase.phase}>
                <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">
                  Phase {phase.phase} — {phase.name}
                </p>
                <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                  {phase.parts.map((part) => (
                    <div
                      key={part.part}
                      className={`rounded-xl border p-4 transition-colors ${
                        part.status === "shipped"
                          ? "border-primary/40 bg-primary/5"
                          : "border-border/70 bg-card"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs text-muted-foreground">
                          #{String(part.part).padStart(2, "0")}
                        </span>
                        <span
                          className={`text-[10px] font-semibold uppercase tracking-wider ${
                            part.status === "shipped"
                              ? "text-primary"
                              : part.status === "up-next"
                                ? "text-amber-400"
                                : "text-muted-foreground/60"
                          }`}
                        >
                          {part.status === "shipped"
                            ? "Shipped"
                            : part.status === "up-next"
                              ? "Up next"
                              : "Planned"}
                        </span>
                      </div>
                      <p className="mt-2 text-sm font-medium leading-snug">{part.title}</p>
                      <p className="mt-1 text-xs leading-5 text-muted-foreground">
                        {part.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="border-t border-border/60 py-20">
        <div className="mx-auto w-full max-w-3xl px-6 text-center">
          <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">
            Find it before they do.
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-muted-foreground">
            Paste a file or drop in a snippet. CrackScope fires its full attack battery
            and hands you the report in seconds.
          </p>
          <Button asChild size="lg" className="mt-8 cursor-pointer gap-2 shadow-lg shadow-primary/20">
            <Link to="/auth">
              Start scanning free <ArrowRight className="size-4" />
            </Link>
          </Button>
        </div>
      </section>

      <footer className="border-t border-border/60 py-8">
        <div className="mx-auto flex w-full max-w-6xl flex-wrap items-center justify-between gap-4 px-6 text-sm text-muted-foreground">
          <div className="flex items-center gap-2">
            <img src={logo} alt="" className="size-6 rounded-md" />
            <span>CrackScope — simulated offensive security for your own code.</span>
          </div>
          <span>Use only on code you own or are authorized to test.</span>
        </div>
      </footer>
    </div>
  );
}
