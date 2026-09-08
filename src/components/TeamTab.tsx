// CrackScope Part 19 — Team workspaces UI.
// Workspace switcher/creator, member management with roles, join-code
// invites, shared scan reports, and a live activity feed.
import { useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { toast } from "sonner";
import {
  Activity,
  Check,
  Copy,
  Crown,
  Link2,
  LogOut,
  Plus,
  Shield,
  Trash2,
  UserMinus,
  Users,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { api } from "@/convex/_generated/api";
import type { Id } from "@/convex/_generated/dataModel";
import { SEVERITY_STYLE } from "@/components/ScanReport";

const ROLE_BADGE: Record<string, string> = {
  owner: "border-primary/40 bg-primary/10 text-primary",
  admin: "border-[oklch(0.75_0.12_220)]/40 bg-[oklch(0.75_0.12_220)]/10 text-[oklch(0.78_0.11_220)]",
  member: "border-border bg-muted text-muted-foreground",
};

const ACTIVITY_ICON: Record<string, typeof Users> = {
  workspace_created: Crown,
  member_joined: Users,
  member_removed: UserMinus,
  role_changed: Shield,
  scan_shared: Link2,
  scan_unshared: Link2,
  triage_updated: Check,
};

function timeAgo(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function TeamTab() {
  const workspaces = useQuery(api.workspaces.listMyWorkspaces) ?? [];
  const createWorkspace = useMutation(api.workspaces.createWorkspace);
  const joinWorkspace = useMutation(api.workspaces.joinWorkspace);
  const createInvite = useMutation(api.workspaces.createInvite);

  const [selected, setSelected] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
  const [joinCode, setJoinCode] = useState("");

  const workspaceId = (selected ?? workspaces[0]?._id ?? null) as Id<"workspaces"> | null;

  if (workspaces.length === 0 && !selected) {
    return (
      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="border-border/60 bg-card/60">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Users className="size-4 text-primary" /> Create a workspace
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Group your team around shared attack reports. You become the owner and can invite
              admins and members.
            </p>
            <Input
              placeholder="Workspace name (e.g. Platform Security)"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              maxLength={60}
            />
            <Button
              className="w-full rounded-full"
              disabled={!newName.trim()}
              onClick={async () => {
                try {
                  await createWorkspace({ name: newName.trim() });
                  setNewName("");
                  toast.success("Workspace created");
                } catch (e: any) {
                  toast.error(e.message ?? "Could not create workspace");
                }
              }}
            >
              <Plus className="size-4" /> Create workspace
            </Button>
          </CardContent>
        </Card>
        <Card className="border-border/60 bg-card/60">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Link2 className="size-4 text-primary" /> Join with a code
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Got an invite code from a teammate? Enter it here to join their workspace as a member.
            </p>
            <Input
              placeholder="8-character code"
              value={joinCode}
              onChange={(e) => setJoinCode(e.target.value.toUpperCase())}
              maxLength={8}
              className="font-mono tracking-widest uppercase"
            />
            <Button
              className="w-full rounded-full"
              disabled={joinCode.length !== 8}
              onClick={async () => {
                try {
                  const r = await joinWorkspace({ code: joinCode });
                  toast.success(r.alreadyMember ? "You are already a member" : "Joined workspace");
                  setJoinCode("");
                } catch (e: any) {
                  toast.error(e.message ?? "Could not join");
                }
              }}
            >
              Join workspace
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <TeamWorkspaceView
      workspaces={workspaces}
      selectedId={workspaceId}
      onSelect={(id) => setSelected(id)}
      onJoin={async (code) => {
        const r = await joinWorkspace({ code });
        toast.success(r.alreadyMember ? "You are already a member" : "Joined workspace");
      }}
    />
  );
}

function TeamWorkspaceView({
  workspaces,
  selectedId,
  onSelect,
  onJoin,
}: {
  workspaces: { _id: string; name: string; role: string }[];
  selectedId: Id<"workspaces"> | null;
  onSelect: (id: string) => void;
  onJoin: (code: string) => Promise<void>;
}) {
  const createWorkspace = useMutation(api.workspaces.createWorkspace);
  const createInvite = useMutation(api.workspaces.createInvite);
  const removeMember = useMutation(api.workspaces.removeMember);
  const leaveWorkspace = useMutation(api.workspaces.leaveWorkspace);
  const [newName, setNewName] = useState("");
  const [inviteCode, setInviteCode] = useState<string | null>(null);

  const members = useQuery(
    api.workspaces.listMembers,
    selectedId ? { workspaceId: selectedId } : "skip",
  ) ?? [];
  const shared = useQuery(
    api.workspaces.listSharedScans,
    selectedId ? { workspaceId: selectedId } : "skip",
  ) ?? [];
  const activity = useQuery(
    api.workspaces.listActivity,
    selectedId ? { workspaceId: selectedId } : "skip",
  ) ?? [];

  const myRole = workspaces.find((w) => w._id === selectedId)?.role ?? "member";
  const canManage = myRole === "owner" || myRole === "admin";

  return (
    <div className="space-y-6">
      {/* Workspace switcher */}
      <div className="flex flex-wrap items-center gap-2">
        {workspaces.map((w) => (
          <Button
            key={w._id}
            variant={w._id === selectedId ? "default" : "outline"}
            className="rounded-full"
            onClick={() => onSelect(w._id)}
          >
            {w.name}
            <Badge variant="outline" className={`ml-2 rounded-full ${ROLE_BADGE[w.role]}`}>
              {w.role}
            </Badge>
          </Button>
        ))}
        <Input
          className="h-9 w-44 rounded-full"
          placeholder="New workspace…"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
        />
        <Button
          variant="outline"
          className="rounded-full"
          disabled={!newName.trim()}
          onClick={async () => {
            try {
              const id = await createWorkspace({ name: newName.trim() });
              setNewName("");
              onSelect(id);
              toast.success("Workspace created");
            } catch (e: any) {
              toast.error(e.message ?? "Could not create workspace");
            }
          }}
        >
          <Plus className="size-4" />
        </Button>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Members */}
        <Card className="border-border/60 bg-card/60">
          <CardHeader>
            <CardTitle className="flex items-center justify-between text-base">
              <span className="flex items-center gap-2">
                <Users className="size-4 text-primary" /> Members
              </span>
              {canManage && selectedId && (
                <Button
                  size="sm"
                  variant="outline"
                  className="rounded-full"
                  onClick={async () => {
                    try {
                      const code = await createInvite({ workspaceId: selectedId });
                      setInviteCode(code);
                      await navigator.clipboard.writeText(code).catch(() => {});
                      toast.success("Invite code copied");
                    } catch (e: any) {
                      toast.error(e.message ?? "Could not create invite");
                    }
                  }}
                >
                  <Plus className="size-3.5" /> Invite
                </Button>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {inviteCode && (
              <div className="flex items-center gap-2 rounded-lg border border-primary/30 bg-primary/5 p-2.5">
                <span className="font-mono text-lg font-semibold tracking-widest">{inviteCode}</span>
                <Button
                  size="sm"
                  variant="ghost"
                  className="ml-auto"
                  onClick={() => {
                    navigator.clipboard.writeText(inviteCode);
                    toast.success("Copied");
                  }}
                >
                  <Copy className="size-3.5" />
                </Button>
              </div>
            )}
            {members.length === 0 && (
              <p className="text-sm text-muted-foreground">No members yet.</p>
            )}
            {members.map((m: any) => (
              <div key={m._id} className="flex items-center gap-3">
                <div className="flex size-8 shrink-0 items-center justify-center rounded-full bg-muted font-semibold uppercase">
                  {(m.name ?? "?").slice(0, 1)}
                </div>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{m.name}</p>
                  {m.email && <p className="truncate text-xs text-muted-foreground">{m.email}</p>}
                </div>
                <Badge variant="outline" className={`rounded-full capitalize ${ROLE_BADGE[m.role]}`}>
                  {m.role === "owner" && <Crown className="mr-1 size-3" />}
                  {m.role}
                </Badge>
                {canManage && m.role !== "owner" && selectedId && (
                  <Button
                    size="icon"
                    variant="ghost"
                    className="size-7"
                    onClick={async () => {
                      try {
                        await removeMember({ workspaceId: selectedId, membershipId: m._id });
                        toast.success("Member removed");
                      } catch (e: any) {
                        toast.error(e.message ?? "Could not remove member");
                      }
                    }}
                  >
                    <UserMinus className="size-3.5" />
                  </Button>
                )}
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Shared reports */}
        <Card className="border-border/60 bg-card/60">
          <CardHeader>
            <CardTitle className="text-base">Shared reports</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {shared.length === 0 && (
              <p className="text-sm text-muted-foreground">
                No shared scans yet. Admins can share scans from the History tab.
              </p>
            )}
            {shared.map((s: any) => (
              <div
                key={s.shareId}
                className="flex items-center gap-3 rounded-lg border border-border/60 p-3"
              >
                <span
                  className={`text-xl font-semibold ${s.score >= 75 ? "text-primary" : s.score >= 50 ? "text-[oklch(0.82_0.14_85)]" : "text-destructive"}`}
                >
                  {s.score}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{s.name}</p>
                  <p className="text-xs text-muted-foreground">
                    by {s.sharedByName} · {timeAgo(s.sharedAt)} · {s.findingsCount} findings
                  </p>
                </div>
                <Badge variant="outline" className={`rounded-full ${SEVERITY_STYLE[s.critical > 0 ? "critical" : s.high > 0 ? "high" : s.medium > 0 ? "medium" : "low"].chip}`}>
                  {s.critical > 0 ? `${s.critical} crit` : s.high > 0 ? `${s.high} high` : s.medium > 0 ? `${s.medium} med` : "clean"}
                </Badge>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Activity */}
        <Card className="border-border/60 bg-card/60">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Activity className="size-4 text-primary" /> Activity
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {activity.length === 0 && (
              <p className="text-sm text-muted-foreground">No activity yet.</p>
            )}
            {activity.map((a: any) => {
              const Icon = ACTIVITY_ICON[a.kind] ?? Activity;
              return (
                <div key={a._id} className="flex items-start gap-2.5">
                  <Icon className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm">
                      <span className="font-medium">{a.userName}</span>{" "}
                      <span className="text-muted-foreground">{a.detail}</span>
                    </p>
                    <p className="text-xs text-muted-foreground">{timeAgo(a.at)}</p>
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
