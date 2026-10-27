export type Migration = { version: number; name: string; sql: string; foreignKeysOff?: boolean };

export const migrations: Migration[] = [
  {
    version: 1,
    name: "initial_schema",
    sql: `
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','auditor','viewer')),
  disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0,1)),
  created_at TEXT NOT NULL
);

CREATE TABLE auth_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT
);
CREATE INDEX idx_auth_sessions_user ON auth_sessions(user_id);

CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT
);

CREATE TABLE provider_credentials (
  id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  env_var TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  iv TEXT NOT NULL,
  tag TEXT NOT NULL,
  last4 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (provider, env_var)
);

CREATE TABLE harnesses (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL UNIQUE CHECK (kind IN ('pi','claude-code')),
  label TEXT NOT NULL,
  executable TEXT NOT NULL,
  version TEXT,
  status TEXT NOT NULL CHECK (status IN ('ready','unauthenticated','missing','error','unknown')),
  detail TEXT,
  capabilities TEXT NOT NULL,
  config TEXT NOT NULL,
  detected_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE agent_defs (
  role TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  harness TEXT NOT NULL CHECK (harness IN ('pi','claude-code')),
  model TEXT,
  system_instructions TEXT NOT NULL,
  allowed_tools TEXT NOT NULL,
  max_duration_ms INTEGER NOT NULL,
  max_retries INTEGER NOT NULL,
  concurrency_limit INTEGER NOT NULL,
  budget_usd REAL,
  allow_shell INTEGER NOT NULL DEFAULT 0 CHECK (allow_shell IN (0,1)),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  updated_at TEXT NOT NULL
);

CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  source_path TEXT NOT NULL,
  default_branch TEXT,
  scope_include TEXT NOT NULL,
  scope_exclude TEXT NOT NULL,
  authorized_by TEXT NOT NULL,
  authorization_ref TEXT NOT NULL,
  max_concurrent_agents INTEGER,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE repositories (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  commit_sha TEXT,
  branch TEXT,
  languages TEXT NOT NULL,
  frameworks TEXT NOT NULL,
  inventory TEXT NOT NULL,
  graph TEXT NOT NULL,
  file_count INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL,
  imported_at TEXT NOT NULL
);
CREATE INDEX idx_repositories_project ON repositories(project_id);

CREATE TABLE audits (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  repository_id TEXT NOT NULL REFERENCES repositories(id),
  status TEXT NOT NULL CHECK (status IN ('queued','running','completed','completed_with_errors','failed','cancelling','cancelled')),
  current_phase INTEGER NOT NULL DEFAULT 1,
  config TEXT NOT NULL,
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  error TEXT
);
CREATE INDEX idx_audits_project ON audits(project_id);
CREATE INDEX idx_audits_status ON audits(status);

CREATE TABLE audit_phases (
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  phase INTEGER NOT NULL CHECK (phase BETWEEN 1 AND 6),
  name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','running','completed','blocked','failed','skipped')),
  started_at TEXT,
  finished_at TEXT,
  summary TEXT,
  PRIMARY KEY (audit_id, phase)
);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL,
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL,
  candidate_id TEXT,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  cwe TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  status TEXT NOT NULL CHECK (status IN ('confirmed','reverified','rejected','needs_correction','unresolved')),
  repository_commit TEXT,
  files TEXT NOT NULL,
  root_cause TEXT NOT NULL,
  preconditions TEXT NOT NULL,
  reproduction TEXT NOT NULL,
  expected TEXT NOT NULL,
  observed TEXT NOT NULL,
  impact TEXT NOT NULL,
  remediation TEXT NOT NULL,
  discovery_session_id TEXT,
  verification_session_id TEXT,
  retest_session_id TEXT,
  verification_decision TEXT,
  retest_decision TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (audit_id, code)
);
CREATE INDEX idx_findings_audit ON findings(audit_id);
CREATE INDEX idx_findings_status ON findings(status);

CREATE TABLE tasks (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  phase INTEGER NOT NULL CHECK (phase BETWEEN 1 AND 6),
  kind TEXT NOT NULL,
  task_key TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued','waiting_approval','running','completed','failed','cancelled','blocked')),
  priority INTEGER NOT NULL DEFAULT 0,
  payload TEXT NOT NULL,
  result TEXT,
  error TEXT,
  failure_kind TEXT,
  agent_role TEXT,
  harness TEXT,
  model TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 2,
  requires_approval INTEGER NOT NULL DEFAULT 0 CHECK (requires_approval IN (0,1)),
  approval_id TEXT,
  agent_session_id TEXT,
  deadline_at TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  UNIQUE (audit_id, task_key)
);
CREATE INDEX idx_tasks_audit ON tasks(audit_id);
CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_tasks_phase ON tasks(audit_id, phase);

CREATE TABLE coverage (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  area_id TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING','RUNNING','COMPLETED','BLOCKED','FAILED','NOT_APPLICABLE')),
  files TEXT NOT NULL,
  task_id TEXT,
  notes TEXT,
  updated_at TEXT NOT NULL,
  UNIQUE (audit_id, area_id)
);
CREATE INDEX idx_coverage_audit ON coverage(audit_id);

CREATE TABLE task_dependencies (
  task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  depends_on_task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  PRIMARY KEY (task_id, depends_on_task_id)
);

CREATE TABLE agent_sessions (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  task_id TEXT,
  role TEXT NOT NULL,
  harness TEXT NOT NULL,
  model TEXT,
  status TEXT NOT NULL CHECK (status IN ('starting','running','completed','failed','cancelled','timeout')),
  workspace TEXT NOT NULL,
  sandbox_mode TEXT NOT NULL,
  harness_session_ref TEXT,
  pid INTEGER,
  exit_code INTEGER,
  usage TEXT,
  metadata TEXT,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  error TEXT
);
CREATE INDEX idx_agent_sessions_audit ON agent_sessions(audit_id);
CREATE INDEX idx_agent_sessions_task ON agent_sessions(task_id);

CREATE TABLE candidates (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  area_id TEXT NOT NULL,
  discovery_task_id TEXT NOT NULL REFERENCES tasks(id),
  discovery_session_id TEXT NOT NULL REFERENCES agent_sessions(id),
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  cwe TEXT,
  severity TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('discovered','confirming','confirmed','refuted','inconclusive','duplicate','persisted')),
  finding_id TEXT,
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_candidates_audit ON candidates(audit_id);
CREATE INDEX idx_candidates_status ON candidates(status);

CREATE TABLE verifications (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  candidate_id TEXT REFERENCES candidates(id),
  finding_id TEXT REFERENCES findings(id),
  kind TEXT NOT NULL CHECK (kind IN ('confirmation','reverification')),
  agent_session_id TEXT NOT NULL REFERENCES agent_sessions(id),
  discovery_session_id TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('CONFIRMED','REFUTED','INCONCLUSIVE','DUPLICATE','REVERIFIED','REJECTED','NEEDS_CORRECTION','UNRESOLVED')),
  rationale TEXT NOT NULL,
  evidence_check TEXT NOT NULL,
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_verifications_audit ON verifications(audit_id);
CREATE INDEX idx_verifications_candidate ON verifications(candidate_id);
CREATE INDEX idx_verifications_finding ON verifications(finding_id);

CREATE TABLE evidence (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  task_id TEXT,
  agent_session_id TEXT,
  finding_id TEXT,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  content_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  chain_hash TEXT NOT NULL,
  size INTEGER NOT NULL,
  redacted INTEGER NOT NULL DEFAULT 0 CHECK (redacted IN (0,1)),
  created_at TEXT NOT NULL
);
CREATE INDEX idx_evidence_audit ON evidence(audit_id);
CREATE INDEX idx_evidence_task ON evidence(task_id);
CREATE INDEX idx_evidence_finding ON evidence(finding_id);

CREATE TABLE execution_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  task_id TEXT,
  agent_session_id TEXT,
  seq INTEGER NOT NULL,
  type TEXT NOT NULL,
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_events_audit_seq ON execution_events(audit_id, seq);
CREATE INDEX idx_events_task ON execution_events(task_id);

CREATE TABLE reports (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  format TEXT NOT NULL CHECK (format IN ('markdown','json','html','pdf')),
  status TEXT NOT NULL CHECK (status IN ('generated','failed')),
  path TEXT,
  sha256 TEXT,
  size INTEGER,
  meta TEXT NOT NULL,
  generated_at TEXT NOT NULL
);
CREATE INDEX idx_reports_audit ON reports(audit_id);

CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  audit_id TEXT,
  task_id TEXT,
  action TEXT NOT NULL,
  scope TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','denied')),
  requested_by TEXT,
  decided_by TEXT,
  reason TEXT,
  created_at TEXT NOT NULL,
  decided_at TEXT
);
CREATE INDEX idx_approvals_status ON approvals(status);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT,
  ip TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_audit_log_created ON audit_log(created_at);

CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;

CREATE TRIGGER evidence_no_delete BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;

CREATE TRIGGER verifications_no_update BEFORE UPDATE ON verifications
BEGIN SELECT RAISE(ABORT, 'verifications are append-only'); END;

CREATE TRIGGER verifications_no_delete BEFORE DELETE ON verifications
BEGIN SELECT RAISE(ABORT, 'verifications are append-only'); END;

CREATE TRIGGER findings_provenance_immutable
BEFORE UPDATE OF discovery_session_id, verification_session_id, retest_session_id, audit_id, candidate_id ON findings
WHEN (OLD.discovery_session_id IS NOT NULL AND NEW.discovery_session_id IS NOT OLD.discovery_session_id)
  OR (OLD.verification_session_id IS NOT NULL AND NEW.verification_session_id IS NOT OLD.verification_session_id)
  OR (OLD.retest_session_id IS NOT NULL AND NEW.retest_session_id IS NOT OLD.retest_session_id)
  OR NEW.audit_id IS NOT OLD.audit_id OR NEW.candidate_id IS NOT OLD.candidate_id
BEGIN SELECT RAISE(ABORT, 'finding provenance is immutable'); END;
`,
  },
  {
    version: 2,
    name: "local_skills_and_mcp",
    sql: `
CREATE TABLE local_resources (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('skill','mcp')),
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  path TEXT NOT NULL,
  sources TEXT NOT NULL,
  metadata TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  present INTEGER NOT NULL DEFAULT 1,
  enabled INTEGER NOT NULL DEFAULT 1,
  roles TEXT NOT NULL DEFAULT '[]',
  mcp_ids TEXT NOT NULL DEFAULT '[]',
  last_seen_at TEXT NOT NULL
);
CREATE INDEX idx_local_resources_kind ON local_resources(kind, present);
CREATE TABLE local_resource_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  resource_kind TEXT NOT NULL CHECK (resource_kind IN ('skill','mcp')),
  resource_id TEXT NOT NULL,
  event TEXT NOT NULL CHECK (event IN ('load','tool')),
  audit_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  role TEXT NOT NULL,
  harness TEXT NOT NULL,
  tool_name TEXT,
  call_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(resource_kind, resource_id, session_id, event, call_id)
);
CREATE INDEX idx_local_usage_resource ON local_resource_usage(resource_kind, resource_id, id);
`,
  },
  {
    version: 3,
    name: "inherit_runtime_tools",
    sql: `
ALTER TABLE agent_defs ADD COLUMN inherit_tools INTEGER NOT NULL DEFAULT 0 CHECK (inherit_tools IN (0,1));
UPDATE agent_defs SET inherit_tools = 1
WHERE role IN ('codebase_mapper','security_researcher','independent_validator','retest_auditor')
  AND allow_shell = 0
  AND ((harness = 'pi' AND json(allowed_tools) = '["read","grep","find","ls"]')
    OR (harness = 'claude-code' AND json(allowed_tools) = '["Read","Grep","Glob","LS"]'));
`,
  },
  {
    version: 4,
    name: "dynamic_targets_and_identities",
    sql: `
CREATE TABLE project_targets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  base_url TEXT NOT NULL,
  environment TEXT NOT NULL,
  repository_id TEXT REFERENCES repositories(id),
  allowed_hosts TEXT NOT NULL,
  allowed_cidrs TEXT NOT NULL,
  allowed_methods TEXT NOT NULL,
  max_rps REAL NOT NULL DEFAULT 5,
  tls_required INTEGER NOT NULL DEFAULT 1 CHECK (tls_required IN (0,1)),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_project_targets_project ON project_targets(project_id, status);

CREATE TABLE target_authorizations (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES project_targets(id) ON DELETE CASCADE,
  authorized_by TEXT NOT NULL,
  authorization_ref TEXT NOT NULL,
  valid_from TEXT NOT NULL,
  valid_until TEXT NOT NULL,
  authorized_actions TEXT NOT NULL,
  restrictions TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','expired','revoked')),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL
);
CREATE INDEX idx_target_authorizations_target ON target_authorizations(target_id, status, valid_until);

CREATE TABLE test_identities (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES project_targets(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  role TEXT NOT NULL,
  auth_kind TEXT NOT NULL CHECK (auth_kind IN ('none','header','cookie','basic')),
  secret_ref TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','expired','disabled')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_test_identities_target ON test_identities(target_id, status);
`,
  },
  {
    version: 5,
    name: "audit_mode_and_nullable_repository",
    foreignKeysOff: true,
    sql: `
CREATE TABLE audits_new (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  repository_id TEXT REFERENCES repositories(id),
  status TEXT NOT NULL CHECK (status IN ('queued','running','completed','completed_with_errors','failed','cancelling','cancelled')),
  current_phase INTEGER NOT NULL DEFAULT 1,
  config TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'static' CHECK (mode IN ('static','dynamic','hybrid')),
  stop_reason TEXT,
  exploration_status TEXT CHECK (exploration_status IN ('not_applicable','open','closing','closed')),
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  error TEXT
);
INSERT INTO audits_new
  (id, project_id, repository_id, status, current_phase, config, created_by, created_at, started_at, finished_at, error)
SELECT id, project_id, repository_id, status, current_phase, config, created_by, created_at, started_at, finished_at, error
FROM audits;
DROP TABLE audits;
ALTER TABLE audits_new RENAME TO audits;
CREATE INDEX idx_audits_project ON audits(project_id);
CREATE INDEX idx_audits_status ON audits(status);
`,
  },
  {
    version: 6,
    name: "audit_scope_snapshots",
    sql: `
CREATE TABLE audit_scope_snapshots (
  audit_id TEXT PRIMARY KEY REFERENCES audits(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  snapshot TEXT NOT NULL,
  sha256 TEXT NOT NULL
);
CREATE TRIGGER audit_scope_snapshots_no_update
BEFORE UPDATE ON audit_scope_snapshots
BEGIN SELECT RAISE(ABORT, 'audit scope snapshot is immutable'); END;
CREATE TRIGGER audit_scope_snapshots_no_delete
BEFORE DELETE ON audit_scope_snapshots
BEGIN SELECT RAISE(ABORT, 'audit scope snapshot is immutable'); END;
`,
  },
  {
    version: 7,
    name: "api_tokens",
    sql: `
CREATE TABLE api_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
  audit_id TEXT REFERENCES audits(id) ON DELETE CASCADE,
  expires_at TEXT,
  revoked_at TEXT,
  last_used_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_api_tokens_user ON api_tokens(user_id);
`,
  },
  {
    version: 8,
    name: "asset_and_exploration_graphs",
    sql: `
CREATE TABLE assets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('root_domain','subdomain','ip','service','app','endpoint')),
  asset_key TEXT NOT NULL,
  parent_id TEXT REFERENCES assets(id),
  data TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  UNIQUE (project_id, kind, asset_key)
);
CREATE INDEX idx_assets_project ON assets(project_id);

CREATE TABLE asset_edges (
  from_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  to_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  PRIMARY KEY (from_asset_id, to_asset_id, kind)
);

CREATE TABLE exploration_nodes (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('goal','intent','fact','finding','hint')),
  status TEXT NOT NULL CHECK (status IN ('proposed','approved','claimed','running','completed','failed','rejected')),
  task_id TEXT REFERENCES tasks(id),
  session_id TEXT REFERENCES agent_sessions(id),
  payload TEXT NOT NULL,
  retry_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_exploration_audit ON exploration_nodes(audit_id, status, kind);

CREATE TABLE exploration_edges (
  from_node_id TEXT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
  to_node_id TEXT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('spawns','derived_from','yields','proves','rejects')),
  PRIMARY KEY (from_node_id, to_node_id, kind)
);

CREATE TABLE anchors (
  node_id TEXT NOT NULL REFERENCES exploration_nodes(id) ON DELETE CASCADE,
  asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  PRIMARY KEY (node_id, asset_id)
);
CREATE INDEX idx_anchors_asset ON anchors(asset_id);
`,
  },
  {
    version: 9,
    name: "finding_retests",
    sql: `
CREATE TABLE retests (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  audit_id TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
  requested_by TEXT REFERENCES users(id),
  reason TEXT NOT NULL,
  fix_reference TEXT,
  authorization_snapshot TEXT NOT NULL,
  environment_manifest TEXT NOT NULL,
  commit_sha TEXT,
  build_ref TEXT,
  environment_match INTEGER CHECK (environment_match IN (0,1)),
  executed_by TEXT,
  positive_check TEXT,
  status TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed')),
  verdict TEXT CHECK (verdict IN ('still_reproducible','fixed','cannot_confirm')),
  evidence_refs TEXT,
  started_at TEXT,
  ended_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_retests_finding ON retests(finding_id, created_at);
`,
  },
];
