import { useEffect, useMemo, useState } from "react";
import "./charts.css";

type Severity = "Critical" | "High" | "Medium";
type Status = "ready_for_approval" | "needs_evidence" | "retirement_candidate" | "amendment_applied";
type Review = {
  id: string; identity: string; severity: Severity; title: string; summary: string; status: Status;
  scores: { securityRisk: number; spendAuthority: number; evidenceConfidence: number };
  evidence: { source: string; detail: string; confidence: string }[];
  policyDelta: { current: string[]; retain: string[]; remove: string[] };
  blastRadius: { keepsWorking: string[]; changes: string[]; couldBreak: string[]; rollback: string };
  localLimitations: string[];
};
type ApiResponse = { reviews: Review[]; generatedAt: string; mode: string };
type Readiness = { localstack: { ready: boolean }; tools: { ready: boolean; writeEnabled: boolean }; trueforge: { ready: boolean; mcp?: { ready: boolean }; error?: string } };
type ApprovalState = "pending_human_review" | "dry_run_verified" | "rejected";
type Approval = { findingId: string; state: ApprovalState; writeBlocked: true; events: { at: string; label: string; detail: string }[]; validation?: unknown; simulation?: unknown; verification?: unknown };
const severityClass: Record<Severity, string> = { Critical: "critical", High: "high", Medium: "medium" };
const statusLabel: Record<Status, string> = { ready_for_approval: "Ready for approval", needs_evidence: "Evidence review", retirement_candidate: "Retirement candidate", amendment_applied: "Amendment applied" };

function Meter({ label, value }: { label: string; value: number }) {
  return <div className="meter"><div><span>{label}</span><b>{value}</b></div><div className="meter-track"><i style={{ width: `${value}%` }} /></div></div>;
}

function PermissionSurface({ review }: { review: Review }) {
  const granted = Math.max(review.policyDelta.current.length, 1);
  const retained = review.policyDelta.retain.length;
  const removed = review.policyDelta.remove.length;
  return <section className="permission-surface"><div className="chart-title"><p className="label">PERMISSION SURFACE</p><span>Declared action / resource paths</span></div><div className="surface-row"><span>Granted now</span><i><b style={{ width: "100%" }} /></i><strong>{granted}</strong></div><div className="surface-row retained"><span>Retained</span><i><b style={{ width: `${(retained / granted) * 100}%` }} /></i><strong>{retained}</strong></div><div className="surface-row removed"><span>Removed</span><i><b style={{ width: `${Math.min((removed / granted) * 100, 100)}%` }} /></i><strong>{removed}</strong></div></section>;
}

function EvidenceTimeline({ review }: { review: Review }) {
  const ready = review.status === "ready_for_approval";
  const applied = review.status === "amendment_applied";
  const contract = review.evidence.find((item) => item.source === "Sandbox workload contract")?.detail ?? "No workload contract is available.";
  return <section className="evidence-timeline"><div><p className="label">EVIDENCE TIMELINE</p><h3>{applied ? "The approved scope is now live." : "Why IAMender trusts this recommendation."}</h3></div><ol><li className="done"><time>01</time><span><b>Policy retrieved</b><small>Current attached policy was read from the local IAM endpoint.</small></span></li><li className="done"><time>02</time><span><b>Workload checked</b><small>{contract}</small></span></li><li className="done"><time>03</time><span><b>{applied ? "Scoped policy confirmed" : "Policy rehearsed"}</b><small>{applied ? "The current policy retains only the declared bucket read paths." : "Required and removed actions are evaluated before review."}</small></span></li><li className={applied || ready ? "active" : "waiting"}><time>04</time><span><b>{applied ? "Human approval applied" : ready ? "Ready for approval" : "More evidence needed"}</b><small>{applied ? "TrueForge approved the policy-version change; IAMender now shows the active least-privilege state." : ready ? "A human must still approve any policy-version change." : "IAMender will not guess a safe rewrite."}</small></span></li></ol></section>;
}

function ApprovalPanel({ approval, busy, onRequest, onDecision }: { approval: Approval | null; busy: boolean; onRequest: () => void; onDecision: (action: "approve" | "reject") => void }) {
  const state = approval?.state;
  return <section className="approval-panel"><div className="approval-panel-head"><div><p className="label">GUARDED APPROVAL RUN</p><h3>{state === "dry_run_verified" ? "Dry run verified." : state === "rejected" ? "Review rejected." : state === "pending_human_review" ? "Human decision required." : "Request a human review."}</h3><p>{state === "dry_run_verified" ? "Validation, policy simulation, and Lambda verification completed. No IAM policy version was created." : state === "rejected" ? "The proposed policy was left unchanged." : state === "pending_human_review" ? "Review the policy delta and blast radius before approving the safe rehearsal." : "This creates a review record only. IAMender cannot write a policy in this mode."}</p></div><span className={`approval-state ${state ?? "new"}`}>{state?.replaceAll("_", " ") ?? "not requested"}</span></div>
    {approval && <ol className="approval-events">{approval.events.map((item) => <li key={`${item.at}-${item.label}`}><time>{new Date(item.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</time><div><b>{item.label}</b><span>{item.detail}</span></div></li>)}</ol>}
    {state === "dry_run_verified" && <div className="verification-grid"><span><b>Policy check</b>{approval?.validation ? "Completed" : "Not run"}</span><span><b>Access rehearsal</b>{approval?.simulation ? "Completed" : "Not run"}</span><span><b>Lambda check</b>{approval?.verification ? "Passed" : "Skipped"}</span></div>}
    <div className="approval-actions">{!approval && <button type="button" disabled={busy} onClick={onRequest}>{busy ? "Requesting…" : "Request human review"}</button>}{state === "pending_human_review" && <><button type="button" disabled={busy} onClick={() => onDecision("approve")}>{busy ? "Rehearsing…" : "Approve safe rehearsal"}</button><button className="secondary" type="button" disabled={busy} onClick={() => onDecision("reject")}>Reject</button></>}<small>Write boundary active: no policy version can be created from this screen.</small></div>
  </section>;
}

function AppliedAmendment({ review, onOpenTrace }: { review: Review; onOpenTrace: () => void }) {
  return <section className="approval-panel applied-amendment"><div className="approval-panel-head"><div><p className="label">APPROVED AMENDMENT</p><h3>Human approval applied.</h3><p>IAMender has re-read the live IAM policy and confirmed that the scoped least-privilege permissions are now active.</p></div><span className="approval-state">policy active</span></div><div className="verification-grid"><span><b>Human gate</b>Approved in TrueForge</span><span><b>Live policy</b>{review.policyDelta.current.length} scoped permissions active</span><span><b>Rollback</b>Previous version retained</span></div><div className="approval-actions"><button type="button" onClick={onOpenTrace}>Open approval trace ↗</button><small>Any rollback requires a separate human approval.</small></div></section>;
}

function ServiceReadiness({ readiness, checking, onCheck }: { readiness: Readiness | null; checking: boolean; onCheck: () => void }) {
  const item = (label: string, ready: boolean | undefined) => <span className={ready ? "service-ready" : "service-waiting"}><b>{ready ? "●" : "○"}</b>{label}</span>;
  return <div className="service-readiness"><div>{item("LocalStack", readiness?.localstack.ready)}{item("IAMender tools", readiness?.tools.ready)}{item("TrueForge", readiness?.trueforge.ready)}</div><button type="button" onClick={onCheck} disabled={checking}>{checking ? "Checking…" : "Check services"}</button></div>;
}

export default function App() {
  const [data, setData] = useState<ApiResponse | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [openingApproval, setOpeningApproval] = useState(false);
  const [approvalError, setApprovalError] = useState<string | null>(null);
  const [approval, setApproval] = useState<Approval | null>(null);
  const [approvalBusy, setApprovalBusy] = useState(false);
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [checkingReadiness, setCheckingReadiness] = useState(false);
  const trueForgeUrl = import.meta.env.VITE_TRUEFORGE_URL || "http://localhost:8790";
  const refresh = async () => {
    setRefreshing(true); setError(null);
    try {
      const response = await fetch("/api/reviews", { cache: "no-store" });
      const body = await response.json() as ApiResponse & { error?: string };
      if (!response.ok) throw new Error(body.error ?? "The IAMender API could not analyze the sandbox.");
      setData(body); setSelectedId((current) => current && body.reviews.some((review) => review.id === current) ? current : body.reviews[0]?.id ?? null);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Unable to load findings."); }
    finally { setRefreshing(false); }
  };
  useEffect(() => { void refresh(); }, []);
  const checkReadiness = async () => {
    setCheckingReadiness(true);
    try {
      const response = await fetch("/api/readiness", { cache: "no-store" });
      setReadiness(await response.json() as Readiness);
    } catch { setReadiness(null); }
    finally { setCheckingReadiness(false); }
  };
  useEffect(() => { void checkReadiness(); }, []);
  const selected = useMemo(() => data?.reviews.find((review) => review.id === selectedId) ?? data?.reviews[0], [data, selectedId]);
  useEffect(() => {
    if (!selected) return;
    setApproval(null);
    void fetch(`/api/approvals?findingId=${encodeURIComponent(selected.id)}`, { cache: "no-store" })
      .then((response) => response.json() as Promise<{ approval: Approval | null }>)
      .then((body) => setApproval(body.approval ?? null))
      .catch(() => setApproval(null));
  }, [selected?.id]);
  const critical = data?.reviews.filter((review) => review.severity === "Critical").length ?? 0;
  const high = data?.reviews.filter((review) => review.severity === "High").length ?? 0;
  const ready = data?.reviews.filter((review) => review.status === "ready_for_approval").length ?? 0;
  const applied = data?.reviews.filter((review) => review.status === "amendment_applied").length ?? 0;
  const openTrace = () => selected && window.open(`${trueForgeUrl}?iamenderFinding=${selected.id}`, "_blank", "noopener,noreferrer");
  const startApprovalReview = async () => {
    if (!selected || selected.status !== "ready_for_approval") return openTrace();
    setOpeningApproval(true); setApprovalError(null);
    try {
      const response = await fetch("/api/trueforge/approval-sessions", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ findingId: selected.id }) });
      const body = await response.json() as { traceUrl?: string; error?: string };
      if (!response.ok || !body.traceUrl) throw new Error(body.error ?? "TrueForge could not start the approval review.");
      window.open(body.traceUrl, "_blank", "noopener,noreferrer");
    } catch (cause) { setApprovalError(cause instanceof Error ? cause.message : "TrueForge could not start the approval review."); }
    finally { setOpeningApproval(false); }
  };
  const updateApproval = async (url: string, body?: unknown) => {
    if (!selected) return;
    setApprovalBusy(true); setApprovalError(null);
    try {
      const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? { findingId: selected.id }) });
      const result = await response.json() as { approval?: Approval; error?: string };
      if (!response.ok || !result.approval) throw new Error(result.error ?? "Unable to update the guarded review.");
      setApproval(result.approval);
    } catch (cause) { setApprovalError(cause instanceof Error ? cause.message : "Unable to update the guarded review."); }
    finally { setApprovalBusy(false); }
  };
  if (!selected) return <main className="data-state"><p className="label">IAMENDER LIVE REVIEW</p><h1>{error ? "The agent needs attention." : "Scanning local access…"}</h1><p>{error ?? "Reading IAM policies, Lambda workload evidence, and policy recommendations."}</p><button type="button" onClick={() => void refresh()}>{error ? "Retry live scan" : "Refresh"}</button></main>;
  return <main>
    <header className="app-header"><a className="wordmark" href="#top">IAMender<span>®</span></a><nav><a href="#findings">Findings</a><a href="#review">Review</a></nav><button className="trace-link" type="button" onClick={openTrace}>Open TrueForge trace ↗</button></header>
    <section id="top" className="hero-grid"><div className="hero-copy"><p className="label">IAM SAFETY REVIEW · {data?.mode.toUpperCase()}</p><h1>Make access<br /><em>make sense.</em></h1><p>IAMender turns risky permissions into a visible, evidence-backed decision—before anything changes in IAM.</p><button type="button" onClick={() => document.getElementById("findings")?.scrollIntoView({ behavior: "smooth" })}>Explore findings <span>↓</span></button></div><div className="hero-board"><span className="label">LIVE ACCOUNT REVIEW</span><div className="scan-count"><strong>{data?.reviews.length}</strong><span>live identities<br />need attention</span></div><div className="scan-steps"><p className="complete"><b>✓</b> IAM policies retrieved</p><p className="complete"><b>✓</b> Risk and spend authority ranked</p><p className="complete"><b>✓</b> Least-privilege plan generated</p><p className={ready ? "in-progress" : "complete"}><b>{ready ? "↻" : "✓"}</b> {ready ? "Human approval pending" : applied ? "Human-approved amendment active" : "No approval run pending"}</p></div><ServiceReadiness readiness={readiness} checking={checkingReadiness} onCheck={() => void checkReadiness()} /><button className="hero-chip refresh-chip" type="button" onClick={() => { void refresh(); void checkReadiness(); }}>{refreshing ? "REFRESHING…" : "REFRESH LIVE DATA"}</button></div></section>
    <section className="summary-grid" aria-label="Live review summary"><article><span className="summary-number">{String(critical).padStart(2, "0")}</span><h2>Critical<br />permission</h2><p>Live count of administrator-like authority requiring evidence before change.</p></article><article><span className="summary-number">{String(high).padStart(2, "0")}</span><h2>High risk<br />findings</h2><p>Live wildcard and over-privileged identities needing attention.</p></article><article className="summary-ready"><span className="summary-number">{String(applied).padStart(2, "0")}</span><h2>Amendments<br />active</h2><p>Human-approved least-privilege policy versions currently in effect.</p></article></section>
    <section id="findings" className="review-layout"><aside className="finding-rail"><div className="section-title"><p className="label">PRIORITY QUEUE</p><h2>Find what<br />matters.</h2></div>{data?.reviews.map((review) => <button key={review.id} type="button" className={`finding-card ${selected.id === review.id ? "selected" : ""}`} onClick={() => setSelectedId(review.id)}><span className={`severity ${severityClass[review.severity]}`}>{review.severity}</span><strong>{review.identity}</strong><small>{review.title}</small><i>→</i></button>)}</aside>
      <section id="review" className="review-pane" aria-live="polite"><div className="review-top"><div><p className="label">IAMENDER INVESTIGATION</p><h2>{selected.identity}</h2><p>{selected.summary}</p></div><span className={`status ${selected.status === "ready_for_approval" || selected.status === "amendment_applied" ? "ready" : "watch"}`}>{statusLabel[selected.status]}</span></div><div className="risk-grid"><section className="risk-chart"><div className="chart-title"><p className="label">EVIDENCE PROFILE</p><span>Live 0—100</span></div><Meter label="Security risk" value={selected.scores.securityRisk} /><Meter label="Spend authority" value={selected.scores.spendAuthority} /><Meter label="Evidence confidence" value={selected.scores.evidenceConfidence} /></section><section className="policy-delta"><p className="label">POLICY DELTA</p><div><span>Granted now</span><b>{selected.policyDelta.current.join(" · ") || "No policy entries"}</b></div><div><span>Keep</span><b>{selected.policyDelta.retain.join(" · ") || "No safe rewrite yet"}</b></div><div><span>Remove</span><b>{selected.policyDelta.remove.join(" · ") || "No policy change proposed"}</b></div></section></div>
        <PermissionSurface review={selected} />
        <EvidenceTimeline review={selected} />
        <section className="impact-grid"><article><p className="label">KEEPS WORKING</p><h3>{selected.blastRadius.keepsWorking.join(" + ") || "No claim without evidence"}</h3><p>The agent retains only permissions supported by collected evidence.</p></article><article><p className="label">WHAT CHANGES</p><h3>{selected.blastRadius.changes.length} reviewed change</h3><p>{selected.blastRadius.changes.join(" · ")}</p></article><article><p className="label">WATCH FOR</p><h3>Known uncertainty</h3><p>{selected.blastRadius.couldBreak.join(" · ")}</p></article></section>
        {selected.status === "ready_for_approval" && <ApprovalPanel approval={approval} busy={approvalBusy} onRequest={() => void updateApproval("/api/approvals")} onDecision={(action) => void updateApproval(`/api/approvals/${encodeURIComponent(selected.id)}/decision`, { action })} />}
        {selected.status === "amendment_applied" && <AppliedAmendment review={selected} onOpenTrace={openTrace} />}
        {selected.localLimitations.length > 0 && <p className="local-note">Local mode: {selected.localLimitations.join(" ")}</p>}
        <footer className="approval-bar"><div><p className="label">APPROVAL BOUNDARY</p><strong>{selected.status === "amendment_applied" ? "Approved least-privilege policy is active" : selected.status === "ready_for_approval" ? "Ready to submit a policy-version change for human approval" : "More evidence is required before any change"}</strong><span>{approvalError ?? selected.blastRadius.rollback}</span></div><button type="button" disabled={openingApproval || selected.status === "ready_for_approval" && readiness !== null && !readiness.trueforge.ready} onClick={() => void startApprovalReview()}>{openingApproval ? "Preparing approval…" : selected.status === "ready_for_approval" && readiness !== null && !readiness.trueforge.ready ? "Check services above" : selected.status === "ready_for_approval" ? "Submit for human approval ↗" : "Open full trace ↗"}</button></footer>
      </section></section>
  </main>;
}
