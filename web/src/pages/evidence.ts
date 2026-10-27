import { api } from "../api.ts";
import {
  badge,
  button,
  emptyState,
  errorState,
  formatDate,
  h,
  jsonBlock,
  loading,
  pageHeader,
  section,
  severityBadge,
  statusBadge,
} from "../ui.ts";

type Finding = {
  id: string;
  audit_id: string;
  code: string;
  title: string;
  category: string;
  severity: string;
  status: string;
  root_cause: string;
  reproduction: string[];
  expected: string;
  observed: string;
  impact: string;
  remediation: string;
  files: Array<{ path: string; start_line: number; end_line: number }>;
};

type Candidate = { id: string; provenance?: string; payload: Record<string, unknown> } | null;
type Evidence = { id: string; kind: string; title: string; sha256: string; size: number; created_at: string };
type Retest = {
  id: string;
  status: string;
  verdict: string | null;
  reason: string;
  commit_sha: string | null;
  build_ref: string | null;
  environment_match: number | null;
  evidence_refs: string[];
  created_at: string;
};

type FindingDetail = {
  finding: Finding;
  candidate: Candidate;
  evidence: Evidence[];
  retests: Retest[];
  verifications: Array<{ id: string; kind: string; verdict: string; rationale: string; created_at: string }>;
};

type Proof = {
  manifest?: {
    object?: { object_id?: string; owner_identity?: string };
    checks?: Record<string, { identity: string; request: { method: string; path: string }; expect: { status: number | number[] } }>;
  };
  result?: { status?: string; positive?: boolean; exploit?: boolean; negative?: boolean; reason?: string };
  exchange_statuses?: Record<string, number>;
};

export async function renderEvidence(root: HTMLElement, id: string | null): Promise<void> {
  if (!id) {
    root.replaceChildren(
      pageHeader("Finding evidence", "Source quotes, dynamic exchanges, PoC, and retest history for one finding.", null),
      emptyState("No finding selected", "Open a finding from the findings list.", h("a", { class: "btn btn-primary", href: "#/findings" }, "Open findings")),
    );
    return;
  }
  root.replaceChildren(loading("Loading finding evidence"));
  try {
    const data = await api<FindingDetail>(`/api/findings/${id}`);
    const finding = data.finding;
    const proof = (data.candidate?.payload?.manifest ? data.candidate.payload : null) as Proof | null;
    const provenance = data.candidate?.provenance ?? (proof ? "dynamic" : "static");
    const evidenceRows = data.evidence.map((row) => {
      const output = h("pre", { class: "code small", hidden: true });
      const load = button("Load content", async () => {
        const loaded = await api<{ content: string }>(`/api/evidence/${row.id}`);
        output.textContent = loaded.content;
        output.hidden = false;
        load.disabled = true;
      }, "ghost", { class: "btn-sm" });
      return h("tr", {},
        h("td", {},
          h("div", { class: "table-title" }, row.title),
          h("div", { class: "table-sub mono tiny" }, `${row.kind} · ${row.sha256.slice(0, 24)}`),
          output,
        ),
        h("td", { class: "small col-optional" }, `${Math.round(row.size / 1024)} KiB`),
        h("td", { class: "small muted col-optional" }, formatDate(row.created_at)),
        h("td", {}, load),
      );
    });

    const proofBlock = proof
      ? section("Dynamic proof",
          h("div", { class: "stack" },
            h("p", { class: "small" },
              badge(`PoC ${proof.result?.status ?? "unknown"}`, proof.result?.status === "passed" ? "good" : "bad"),
              ` ${proof.manifest?.object?.object_id ?? "object"} owned by ${proof.manifest?.object?.owner_identity ?? "unknown"}`,
            ),
            h("table", { class: "table" },
              h("thead", {}, h("tr", {}, h("th", {}, "Check"), h("th", {}, "Identity"), h("th", {}, "Request"), h("th", {}, "HTTP"), h("th", {}, "Expected"))),
              h("tbody", {}, ...["positive", "exploit", "negative"].map((name) => {
                const check = proof.manifest?.checks?.[name];
                return h("tr", {},
                  h("td", {}, name),
                  h("td", { class: "mono tiny" }, check?.identity ?? "—"),
                  h("td", { class: "mono tiny" }, check ? `${check.request.method} ${check.request.path}` : "—"),
                  h("td", {}, String(proof.exchange_statuses?.[name] ?? "—")),
                  h("td", { class: "mono tiny" }, check ? String(check.expect.status) : "—"),
                );
              })),
            ),
            jsonBlock(proof),
          ),
        )
      : null;

    const retests = data.retests.length === 0
      ? h("p", { class: "small muted" }, "No retests recorded.")
      : h("table", { class: "table" },
          h("thead", {}, h("tr", {}, h("th", {}, "Status"), h("th", {}, "Verdict"), h("th", {}, "Reason"), h("th", { class: "col-optional" }, "Commit"), h("th", {}, "Requested"))),
          h("tbody", {}, ...data.retests.map((retest) =>
            h("tr", {},
              h("td", {}, statusBadge(retest.status)),
              h("td", {}, retest.verdict ? badge(retest.verdict, retest.verdict === "fixed" ? "good" : retest.verdict === "still_reproducible" ? "bad" : "warn") : "—"),
              h("td", { class: "small" }, retest.reason),
              h("td", { class: "mono tiny col-optional" }, retest.commit_sha ?? "—"),
              h("td", { class: "small muted" }, formatDate(retest.created_at)),
            ),
          )),
        );

    root.replaceChildren(
      pageHeader(
        `${finding.code} — ${finding.title}`,
        `${finding.category} · ${finding.severity.toUpperCase()} · ${provenance}`,
        h("a", { class: "btn btn-secondary", href: `#/audits/${finding.audit_id}` }, "Open audit"),
      ),
      h("div", { class: "row", style: { gap: "8px", flexWrap: "wrap", marginBottom: "12px" } },
        severityBadge(finding.severity),
        statusBadge(finding.status),
        badge(provenance, provenance === "dynamic" ? "good" : "neutral"),
      ),
      section("Finding", h("div", { class: "stack" },
        h("p", {}, finding.root_cause),
        h("div", { class: "grid-2" },
          h("div", {}, h("h4", {}, "Expected"), h("p", { class: "small" }, finding.expected)),
          h("div", {}, h("h4", {}, "Observed"), h("p", { class: "small" }, finding.observed)),
        ),
        h("h4", {}, "Reproduction"),
        h("ol", {}, ...finding.reproduction.map((step) => h("li", { class: "small" }, step))),
        finding.files.length > 0
          ? h("p", { class: "small muted" }, `Locations: ${finding.files.map((file) => `${file.path}:${file.start_line}-${file.end_line}`).join(", ")}`)
          : h("p", { class: "small muted" }, "No source location was attached. The finding rests on the dynamic proof."),
        h("h4", {}, "Impact"), h("p", { class: "small" }, finding.impact),
        h("h4", {}, "Remediation"), h("p", { class: "small" }, finding.remediation),
      )),
      ...(proofBlock ? [proofBlock] : []),
      section("Evidence index", evidenceRows.length === 0
        ? h("p", { class: "small muted" }, "No evidence rows.")
        : h("table", { class: "table" },
            h("thead", {}, h("tr", {}, h("th", {}, "Evidence"), h("th", { class: "col-optional" }, "Size"), h("th", { class: "col-optional" }, "Created"), h("th", {}, ""))),
            h("tbody", {}, ...evidenceRows),
          )),
      section("Retest history", retests),
    );
  } catch (error) {
    root.replaceChildren(errorState(error instanceof Error ? error.message : String(error)));
  }
}
