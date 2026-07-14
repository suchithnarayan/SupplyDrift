import {Copy, KeyRound, Plus, Trash2, UserPlus} from "lucide-react";
import {useState} from "react";
import {Cell, DataTable, Row} from "../components/ui/DataTable";
import {EmptyState, GlassCard, SectionTitle, Skeleton, Tag} from "../components/ui/primitives";
import {useToast} from "../components/ui/Toast";
import {api} from "../lib/api";
import {isAdmin, useAuth} from "../lib/auth";
import {cn} from "../lib/cn";
import {relativeTime} from "../lib/meta";
import type {ApiToken, AuthUser} from "../lib/types";
import {useFetch} from "../lib/useFetch";

const ROLES = ["admin", "member", "viewer"];
const SCOPES = ["runner", "ingest", "readonly"];

export function Admin() {
  const {user} = useAuth();
  return (
    <div className="space-y-8">
      {isAdmin(user?.role) && <UsersPane />}
      <TokensPane adminView={isAdmin(user?.role)} />
    </div>
  );
}

function UsersPane() {
  const {data, loading, reload} = useFetch(() => api.listUsers(), []);
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({username: "", password: "", role: "member"});

  const create = async () => {
    try {
      await api.createUser(form);
      setForm({username: "", password: "", role: "member"});
      setOpen(false);
      reload();
    } catch (e) {
      toast((e as Error).message, "error");
    }
  };
  const update = async (u: AuthUser, body: {role?: string; disabled?: boolean}) => {
    try {
      await api.updateUser(u.id, body);
      reload();
    } catch (e) {
      toast((e as Error).message, "error");
    }
  };
  const remove = async (u: AuthUser) => {
    if (!confirm(`Delete user ${u.username}?`)) return;
    try {
      await api.deleteUser(u.id);
      reload();
    } catch (e) {
      toast((e as Error).message, "error");
    }
  };

  return (
    <section>
      <SectionTitle
        title="Users"
        sub="Human accounts and their roles"
        right={
          <button onClick={() => setOpen((o) => !o)} className="inline-flex items-center gap-1.5 rounded-lg bg-brand/15 px-3 py-1.5 text-sm text-brand ring-1 ring-brand/30 hover:bg-brand/25">
            <UserPlus className="h-3.5 w-3.5" /> New user
          </button>
        }
      />
      {open && (
        <GlassCard className="mb-3 flex flex-wrap items-end gap-3">
          <Field label="Username">
            <input value={form.username} onChange={(e) => setForm({...form, username: e.target.value})} className={inputCls} />
          </Field>
          <Field label="Password">
            <input type="password" value={form.password} onChange={(e) => setForm({...form, password: e.target.value})} className={inputCls} />
          </Field>
          <Field label="Role">
            <select value={form.role} onChange={(e) => setForm({...form, role: e.target.value})} className={inputCls}>
              {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </Field>
          <button onClick={create} disabled={!form.username || form.password.length < 8} className="rounded-lg bg-brand/15 px-3 py-2 text-sm text-brand ring-1 ring-brand/30 hover:bg-brand/25 disabled:opacity-50">
            Create
          </button>
          <span className="text-[11px] text-faint">password ≥ 8 chars</span>
        </GlassCard>
      )}
      {loading ? (
        <Skeleton className="h-40 rounded-2xl" />
      ) : (
        <DataTable columns={["User", "Role", "Status", "Last login", ""]}>
          {(data || []).map((u) => (
            <Row key={u.id}>
              <Cell className="font-medium text-ink">{u.username}</Cell>
              <Cell>
                <select value={u.role} onChange={(e) => update(u, {role: e.target.value})} className="rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-xs text-ink outline-none">
                  {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              </Cell>
              <Cell>
                <button onClick={() => update(u, {disabled: !u.disabled})} className={cn("rounded-md px-2 py-0.5 text-[11px] font-medium ring-1", u.disabled ? "bg-critical/10 text-critical ring-critical/20" : "bg-good/10 text-good ring-good/20")}>
                  {u.disabled ? "disabled" : "active"}
                </button>
              </Cell>
              <Cell className="text-[12px] text-faint">{u.last_login_at ? relativeTime(u.last_login_at) : "never"}</Cell>
              <Cell>
                <button onClick={() => remove(u)} className="rounded-lg p-1.5 text-muted hover:bg-critical/10 hover:text-critical"><Trash2 className="h-4 w-4" /></button>
              </Cell>
            </Row>
          ))}
        </DataTable>
      )}
    </section>
  );
}

function TokensPane({adminView}: {adminView: boolean}) {
  const {data, loading, reload} = useFetch(() => api.listTokens(), []);
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({name: "", scope: "readonly"});
  const [fresh, setFresh] = useState<string | null>(null);

  const create = async () => {
    try {
      const t = await api.createToken(form);
      setFresh(t.token || "");
      setForm({name: "", scope: "readonly"});
      setOpen(false);
      reload();
    } catch (e) {
      toast((e as Error).message, "error");
    }
  };
  const revoke = async (t: ApiToken) => {
    try {
      await api.revokeToken(t.id);
      reload();
    } catch (e) {
      toast((e as Error).message, "error");
    }
  };

  return (
    <section>
      <SectionTitle
        title="API tokens"
        sub="Machine credentials for runners, ingest, and read-only automation"
        right={
          <button onClick={() => setOpen((o) => !o)} className="inline-flex items-center gap-1.5 rounded-lg bg-brand/15 px-3 py-1.5 text-sm text-brand ring-1 ring-brand/30 hover:bg-brand/25">
            <Plus className="h-3.5 w-3.5" /> New token
          </button>
        }
      />
      {fresh && (
        <GlassCard className="mb-3 border border-good/30">
          <div className="mb-1 text-xs text-good">Copy this token now — it is shown only once.</div>
          <div className="flex items-center gap-2">
            <code className="flex-1 truncate rounded-lg bg-black/30 px-3 py-2 font-mono text-xs text-ink">{fresh}</code>
            <button onClick={() => {navigator.clipboard?.writeText(fresh); toast("Copied", "success");}} className="rounded-lg p-2 text-muted hover:bg-white/5 hover:text-ink"><Copy className="h-4 w-4" /></button>
            <button onClick={() => setFresh(null)} className="rounded-lg px-2.5 py-1.5 text-xs text-muted hover:text-ink">Done</button>
          </div>
        </GlassCard>
      )}
      {open && (
        <GlassCard className="mb-3 flex flex-wrap items-end gap-3">
          <Field label="Name">
            <input value={form.name} onChange={(e) => setForm({...form, name: e.target.value})} placeholder="ci-pipeline" className={inputCls} />
          </Field>
          <Field label="Scope">
            <select value={form.scope} onChange={(e) => setForm({...form, scope: e.target.value})} className={inputCls}>
              {SCOPES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </Field>
          <button onClick={create} className="rounded-lg bg-brand/15 px-3 py-2 text-sm text-brand ring-1 ring-brand/30 hover:bg-brand/25">Create</button>
          <span className="text-[11px] text-faint">runner = claim+push · ingest = push · readonly = GET</span>
        </GlassCard>
      )}
      {loading ? (
        <Skeleton className="h-32 rounded-2xl" />
      ) : (data || []).length === 0 ? (
        <EmptyState title="No tokens" hint="Create a scoped token for a runner or CI job." />
      ) : (
        <DataTable columns={["Name", "Scope", ...(adminView ? ["Created by"] : []), "Last used", "Status", ""]}>
          {(data || []).map((t) => (
            <Row key={t.id}>
              <Cell className="font-medium text-ink">
                <KeyRound className="mr-1.5 inline h-3.5 w-3.5 text-faint" />{t.name}
              </Cell>
              <Cell><Tag>{t.scope}</Tag></Cell>
              {adminView && <Cell className="text-[12px] text-muted">{t.created_by || "—"}</Cell>}
              <Cell className="text-[12px] text-faint">{t.last_used_at ? relativeTime(t.last_used_at) : "never"}</Cell>
              <Cell>
                {t.revoked_at
                  ? <span className="text-[11px] text-faint">revoked</span>
                  : <span className="text-[11px] text-good">active</span>}
              </Cell>
              <Cell>
                {!t.revoked_at && (
                  <button onClick={() => revoke(t)} className="rounded-lg p-1.5 text-muted hover:bg-critical/10 hover:text-critical"><Trash2 className="h-4 w-4" /></button>
                )}
              </Cell>
            </Row>
          ))}
        </DataTable>
      )}
    </section>
  );
}

const inputCls = "rounded-lg border border-white/10 bg-white/[0.03] px-2.5 py-2 text-sm text-ink outline-none focus:border-accent/40";

function Field({label, children}: {label: string; children: React.ReactNode}) {
  return (
    <label className="flex flex-col gap-1 text-xs text-muted">
      {label}
      {children}
    </label>
  );
}
