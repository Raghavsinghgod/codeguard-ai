import { motion } from "framer-motion";
import { CheckCircle2, Circle, CircleDot } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { ALL_PARTS, ROADMAP_PHASES, SHIPPED_PARTS, TOTAL_PARTS } from "@/lib/roadmap";

const STATUS_META = {
  shipped: {
    icon: CheckCircle2,
    label: "Shipped",
    className: "text-primary border-primary/40 bg-primary/10",
  },
  "up-next": {
    icon: CircleDot,
    label: "Up next",
    className: "text-[oklch(0.82_0.14_85)] border-[oklch(0.8_0.16_85)]/40 bg-[oklch(0.8_0.16_85)]/10",
  },
  planned: {
    icon: Circle,
    label: "Planned",
    className: "text-muted-foreground border-border bg-muted",
  },
} as const;

export function RoadmapView() {
  const pct = Math.round((SHIPPED_PARTS / TOTAL_PARTS) * 100);
  return (
    <div className="space-y-8">
      <Card className="border-border/60 bg-card/70">
        <CardContent className="p-6">
          <div className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h2 className="text-xl font-semibold tracking-tight">Build roadmap</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                CrackScope ships in 25 parts across 5 phases. {SHIPPED_PARTS} shipped,{" "}
                {SHIPPED_PARTS === 1 ? "24 to go" : `${TOTAL_PARTS - SHIPPED_PARTS} to go`}.
              </p>
            </div>
            <span className="font-mono text-sm text-muted-foreground">
              {SHIPPED_PARTS}/{TOTAL_PARTS} · {pct}%
            </span>
          </div>
          <Progress value={pct} className="mt-5 h-2" />
          <div className="mt-4 flex flex-wrap gap-2">
            {ALL_PARTS.filter((p) => p.status === "shipped").map((p) => (
              <span
                key={p.part}
                className="rounded-full border border-primary/40 bg-primary/10 px-2.5 py-1 font-mono text-xs text-primary"
              >
                Part {p.part} ✓
              </span>
            ))}
          </div>
        </CardContent>
      </Card>

      {ROADMAP_PHASES.map((phase, pi) => (
        <motion.div
          key={phase.phase}
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: pi * 0.05 }}
        >
          <div className="mb-3 flex items-center gap-3">
            <span className="font-mono text-xs uppercase tracking-widest text-muted-foreground">
              Phase {phase.phase}
            </span>
            <h3 className="font-semibold tracking-tight">{phase.name}</h3>
            <div className="h-px flex-1 bg-border/60" />
          </div>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {phase.parts.map((part) => {
              const meta = STATUS_META[part.status];
              const Icon = meta.icon;
              return (
                <Card
                  key={part.part}
                  className={`border-border/60 ${part.status === "shipped" ? "bg-primary/5" : "bg-card/60"}`}
                >
                  <CardContent className="p-5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-muted-foreground">
                        Part {part.part}
                      </span>
                      <span
                        className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${meta.className}`}
                      >
                        <Icon className="size-3" />
                        {meta.label}
                      </span>
                    </div>
                    <h4 className="mt-2.5 font-medium tracking-tight">{part.title}</h4>
                    <p className="mt-1.5 text-sm leading-6 text-muted-foreground">
                      {part.description}
                    </p>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </motion.div>
      ))}
    </div>
  );
}
