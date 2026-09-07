// CrackScope Part 11 — triage workflow controls.
// Per-finding status (open / false positive / accepted risk), note, and owner.
// The parent owns the Convex mutation; this component is presentational and
// fires onPatch with merged partial updates.
import { useEffect, useState } from "react";
import { Ban, RotateCcw, ShieldAlert, UserRound } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export type TriageStatus = "open" | "false_positive" | "accepted_risk";

export interface TriageState {
  status: TriageStatus;
  note?: string;
  owner?: string;
}

export const TRIAGE_BADGE: Record<Exclude<TriageStatus, "open">, { label: string; chip: string }> = {
  false_positive: {
    label: "false positive",
    chip: "border-muted-foreground/40 bg-muted text-muted-foreground",
  },
  accepted_risk: {
    label: "risk accepted",
    chip: "border-[oklch(0.8_0.16_85)]/40 bg-[oklch(0.8_0.16_85)]/10 text-[oklch(0.82_0.14_85)]",
  },
};

export function TriageBar({
  disabled,
  state,
  onPatch,
}: {
  disabled: boolean;
  state: TriageState;
  onPatch: (patch: Partial<TriageState>) => void;
}) {
  const triaged = state.status !== "open";
  // Local draft state for text inputs; committed on blur to avoid a
  // Convex mutation on every keystroke.
  const [note, setNote] = useState(state.note ?? "");
  const [owner, setOwner] = useState(state.owner ?? "");
  useEffect(() => {
    setNote(state.note ?? "");
    setOwner(state.owner ?? "");
  }, [state.note, state.owner]);

  return (
    <div className="rounded-lg border border-border/70 bg-secondary/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <p className="mr-1 font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
          Triage
        </p>
        <Button
          type="button"
          size="sm"
          variant={state.status === "false_positive" ? "default" : "outline"}
          className="h-7 gap-1.5 rounded-full text-xs"
          disabled={disabled}
          onClick={() => onPatch({ status: state.status === "false_positive" ? "open" : "false_positive" })}
        >
          <Ban className="size-3.5" /> False positive
        </Button>
        <Button
          type="button"
          size="sm"
          variant={state.status === "accepted_risk" ? "default" : "outline"}
          className="h-7 gap-1.5 rounded-full text-xs"
          disabled={disabled}
          onClick={() => onPatch({ status: state.status === "accepted_risk" ? "open" : "accepted_risk" })}
        >
          <ShieldAlert className="size-3.5" /> Accept risk
        </Button>
        {triaged && (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            className="h-7 gap-1.5 rounded-full text-xs text-muted-foreground"
            disabled={disabled}
            onClick={() => onPatch({ status: "open" })}
          >
            <RotateCcw className="size-3.5" /> Re-open
          </Button>
        )}
        {triaged && state.status !== "open" && (
          <Badge variant="outline" className={`rounded-full text-xs ${TRIAGE_BADGE[state.status].chip}`}>
            {TRIAGE_BADGE[state.status].label}
          </Badge>
        )}
        {disabled && (
          <span className="text-xs text-muted-foreground/70">
            available once the scan is saved
          </span>
        )}
      </div>
      <div className="mt-2.5 grid gap-2 sm:grid-cols-2">
        <Input
          placeholder="Triage note (why FP, who accepted, ticket link…)"
          value={note}
          disabled={disabled}
          onChange={(e) => setNote(e.target.value)}
          onBlur={() => {
            if ((state.note ?? "") !== note) onPatch({ note });
          }}
          className="h-8 rounded-lg text-xs"
        />
        <div className="relative">
          <UserRound className="absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Owner"
            value={owner}
            disabled={disabled}
            onChange={(e) => setOwner(e.target.value)}
            onBlur={() => {
              if ((state.owner ?? "") !== owner) onPatch({ owner });
            }}
            className="h-8 rounded-lg pl-8 text-xs"
          />
        </div>
      </div>
    </div>
  );
}
