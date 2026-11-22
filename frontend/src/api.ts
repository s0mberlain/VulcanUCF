import type { RuleNameVariable } from "./lib/ruleName";
import type { Lang } from "./i18n";
import { translateServer } from "./serverTexts";
export type Role = "admin" | "analyst" | "auditor" | "red_team";

export interface User {
  id: number;
  username: string;
  display_name: string;
  email: string | null;
  role: Role;
  auth_source: "local" | "sso" | "service";
  active: boolean;
  totp_enabled: boolean;
  locale: Lang | null;
  last_login_at: string | null;
  created_at: string;
  /** red team accounts: the date set by hand, whether it follows the campaigns, the date that applies */
  expires_at?: string | null;
  expiry_follows_campaign?: boolean;
  effective_expires_at?: string | null;
}

export interface VersionInfo {
  name: string;
  version: string;
}

export interface CatalogueSummary {
  l1: number;
  l2: number;
  l3: number;
  business_drivers: number;
  compliance_drivers: number;
  references: Record<string, number>;
}

export interface AuditEntry {
  id: number;
  at: string;
  username: string;
  action: string;
  entity: string;
  entity_key: string;
  changes: Record<string, unknown>;
  ip: string | null;
}

export type Lifecycle = "onboarding" | "operational" | "maintenance" | "offloading" | "retired";
export const LIFECYCLES: Lifecycle[] = ["onboarding", "operational", "maintenance", "offloading", "retired"];
export type RefKind = "threat_actor" | "detection_technology" | "log_source" | "scope";

export interface Metrics {
  effectiveness: number | null;
  implementation: number | null;
  coverage: number | null;
  weight: number | null;
  potential: number | null;
}

export interface Kpis {
  soc_detection_score: number | null;
  catalogue_coverage: number | null;
  growth_potential: number | null;
  detection_gap: number | null;
  framework_completeness: number | null;
  l2_with_scored_rules: number;
  applicable_l2: number;
  assessment_coverage: number | null;
  assessed_rules: number;
  active_rules: number;
  verification_health: number | null;
  verified_in_time: number;
  verification_overdue: number;
  operational_rules: number;
  default_verification_days: number;
}

export interface GroupScore extends Metrics {
  code: string;
  name: string;
  rules: number;
  scored_rules: number;
}
export interface L1Score extends GroupScore {
  applicable: boolean;
  l2_count: number;
  scored_l2: number;
}
export interface L2Score extends GroupScore {
  l1_code: string;
}
export interface Scores {
  overall: Metrics;
  kpis: Kpis;
  l1: L1Score[];
  l2: L2Score[];
}

export interface DueRule {
  code: string;
  name: string;
  l2_code: string;
  lifecycle_status: Lifecycle;
  last_verified_at: string | null;
  last_verified_by: string | null;
  due: string | null;
  overdue: boolean;
  days_left: number | null;
  /** date of the latest check when it found issues (it does not count as verified) */
  issues_at: string | null;
}

export interface Verification {
  id: number;
  verified_at: string;
  username: string;
  result: "ok" | "issues";
  note: string;
  config_tag?: string | null;
  /** set when the entry comes from a test result */
  test_id?: number | null;
}

export interface L1 {
  id: number;
  code: string;
  name: string;
  threat_category: string;
  purpose: string;
  stakeholders: string;
  description: string;
  applicable: boolean;
  sort_order: number;
  l2_count: number;
  l3_count: number;
  /** inherited from its L2 use cases */
  business_drivers: string[];
  compliance_drivers: ComplianceRef[];
}

/** A compliance driver linked to a use case, with its source. */
export interface ComplianceRef {
  id: number;
  source_id: number;
  source: string;
  ref: string;
  name: string;
}

export interface L2 {
  id: number;
  code: string;
  l1_code: string;
  name: string;
  description: string;
  lifecycle_status: Lifecycle;
  risk_level: number | null;
  target_implementation: number | null;
  onboarded_at: string | null;
  last_verified_at: string | null;
  last_verified_by: string | null;
  updated_at: string | null;
  actors: string[];
  business_drivers: string[];
  compliance_driver_ids: number[];
  compliance_drivers: ComplianceRef[];
  l3_count: number;
  /** systems whose latest completed interview linked this use case */
  systems?: LinkedSystem[];
}

export interface LinkedSystem {
  id: number;
  name: string;
  archived: boolean;
}

export interface L3 {
  id: number;
  code: string;
  l1_code: string;
  l2_code: string;
  name: string;
  description: string;
  effectiveness: number | null;
  implementation: number | null;
  coverage: number | null;
  lifecycle_status: Lifecycle;
  comments: string;
  attack_techniques: string[];
  siem_rule_ids?: string[];
  /** built on the server from the SIEM name format (#50) */
  siem_name?: string | null;
  onboarded_at: string | null;
  last_verified_at: string | null;
  last_verified_by: string | null;
  verification_interval_days: number | null;
  risk_level: number | null;
  target_implementation: number | null;
  effective_risk: number | null;
  risk_source: "rule" | "l2" | "system" | null;
  /** the system that raised the risk level (risk_source "system") */
  risk_system?: string | null;
  effective_target: number | null;
  target_source: "rule" | "l2" | "risk" | null;
  implementation_gap: number | null;
  priority: number | null;
  log_sources: string[];
  detection_technologies: string[];
  scopes: string[];
  updated_at: string;
  /** inherited from the L2 use case */
  business_drivers: string[];
  compliance_drivers: ComplianceRef[];
  weight: number | null;
  potential: number | null;
  assessed: boolean;
  scored: boolean;
  verification_due: string | null;
  verification_overdue: boolean;
  /** date of the latest check when it found issues (it does not count as verified) */
  issues_at: string | null;
}

/** updated_at the edit started from: the save is refused (409) when someone saved in between. */
interface Expected {
  expected_updated_at?: string | null;
}

export type L2Input = Partial<
  Omit<L2, "id" | "l1_code" | "l3_count" | "last_verified_by" | "compliance_drivers" | "updated_at">
> &
  Expected;
export type L1Input = Partial<
  Pick<L1, "name" | "threat_category" | "purpose" | "stakeholders" | "description" | "applicable" | "sort_order">
>;
export type L3Input = Partial<
  Omit<
    L3,
    | "id"
    | "l1_code"
    | "l2_code"
    | "updated_at"
    | "weight"
    | "potential"
    | "assessed"
    | "scored"
    | "verification_due"
    | "verification_overdue"
    | "last_verified_by"
    | "effective_risk"
    | "risk_source"
    | "effective_target"
    | "target_source"
    | "implementation_gap"
    | "priority"
    | "business_drivers"
    | "compliance_drivers"
    | "issues_at"
  >
> &
  Expected;

export interface RefItem {
  id: number;
  kind: RefKind;
  name: string;
  description: string;
  /** Codes of what uses the entry: L2 use cases for threat actors, L3 rules otherwise.
   *  Only filled by the list endpoint. */
  used_by?: string[];
  /** log sources: systems whose interview lists the entry on a component (#39) */
  used_by_systems?: string[];
}
export interface BusinessDriver {
  id: number;
  code: string;
  name: string;
  description: string;
}
export interface ComplianceDriver {
  id: number;
  source_id: number;
  ref: string;
  name: string;
  description: string;
}
export interface ComplianceSource {
  id: number;
  name: string;
  drivers: ComplianceDriver[];
}
export interface DriverCoverage {
  id: number;
  /** business driver code or compliance reference */
  code: string;
  name: string;
  source_id: number | null;
  source: string | null;
  l2_count: number;
  l3_count: number;
  scored_l2: number;
  coverage: number | null;
  gap: boolean;
  low: boolean;
  l2_codes: string[];
}
export interface SourceCoverage {
  id: number;
  name: string;
  drivers: number;
  linked_drivers: number;
  l2_count: number;
  l3_count: number;
  coverage: number | null;
  gap_drivers: number;
  low_drivers: number;
}
export interface DriverCoverageReport {
  low_threshold: number;
  business: DriverCoverage[];
  compliance: DriverCoverage[];
  sources: SourceCoverage[];
}
export interface LinkedUseCase {
  code: string;
  name: string;
  l3_count: number;
}

export interface AuthConfig {
  local_login_enabled: boolean;
  sso_enabled: boolean;
  sso_label: string;
}

export interface ConfigTag {
  name: string;
  created_by: string;
  created_at: string;
}
export interface ConfigCommit {
  rev: number;
  sha: string;
  short: string;
  parent_sha: string | null;
  message: string;
  author: string;
  created_at: string;
  restored_from: string | null;
  git_sha?: string | null;
  /** "git" when the commit was made directly in the connected repository (two-way sync). */
  source?: "app" | "git";
  tags: ConfigTag[];
}
export interface ConfigState {
  head: ConfigCommit | null;
  content: string;
  commits: number;
}
export interface DiffLine {
  kind: "hunk" | "ctx" | "add" | "del";
  text: string;
  old?: number | null;
  new?: number | null;
}
export interface ConfigDiff {
  from: ConfigCommit | null;
  to: ConfigCommit;
  lines: DiffLine[];
  unified: string;
  added: number;
  removed: number;
}
export interface RecentCommit extends ConfigCommit {
  level: "l2" | "l3";
  code: string;
  name: string;
}
export interface RuleNameSettings {
  format: string;
  variables: RuleNameVariable[];
  builtins: string[];
  updated_at: string | null;
  updated_by: string | null;
}

export interface ConfigCheck {
  valid: boolean;
  error: string | null;
  line: number | null;
  column: number | null;
}
export interface ImportReport {
  mode: "merge" | "replace";
  dry_run: boolean;
  sheets: string[];
  counts: Record<string, { created: number; updated: number; unchanged: number; deleted: number }>;
  warnings: { sheet: string; row: number | null; message: string }[];
  errors: { sheet: string; row: number | null; message: string }[];
}

export interface LifecycleMeta {
  dod_items: { key: string; label: string; hint: string }[];
  drivers: Record<string, { key: string; label: string }[]>;
}
export interface LifecycleEvent {
  id: number;
  level: Level;
  code: string;
  name: string;
  from_status: Lifecycle | null;
  to_status: Lifecycle;
  driver_type: string;
  driver: string;
  note: string;
  dod_override: boolean;
  username: string;
  at: string;
}
export interface LifecycleState {
  status: Lifecycle;
  dod: { key: string; done: boolean; by: string | null; at: string | null }[];
  dod_complete: boolean;
  /** statuses the use case may change to from here */
  allowed: Lifecycle[];
  events: LifecycleEvent[];
}
export interface LifecycleChange {
  to_status: Lifecycle;
  driver_type: string;
  driver: string;
  note: string;
  override?: boolean;
}
export type KpiMap = Record<string, number | null>;
export interface Snapshot {
  id: number;
  label: string;
  kind: "manual" | "scheduled" | "demo" | "live";
  taken_at: string;
  taken_by: string;
  kpis: KpiMap;
}
export interface TrendPoint {
  id: number | null;
  label: string;
  kind: Snapshot["kind"];
  taken_at: string;
  kpis: KpiMap;
  lifecycle_changes: number;
  config_commits: number;
}
export interface Trends {
  metrics: { key: string; label: string; unit: "pct" | "count" }[];
  schedule: string;
  points: TrendPoint[];
}
export interface GroupChange {
  code: string;
  name: string;
  change: "added" | "removed" | "changed";
  a: Record<string, unknown> | null;
  b: Record<string, unknown> | null;
}
export interface SnapshotCompare {
  a: Snapshot;
  b: Snapshot;
  kpis: Record<string, { a: number | null; b: number | null }>;
  l1: GroupChange[];
  l2: GroupChange[];
  rules: GroupChange[];
}
export interface GitStatus {
  enabled: boolean;
  remote: string;
  branch: string;
  auth: string;
  auto_sync: boolean;
  running: boolean;
  last_attempt_at: string | null;
  last_success_at: string | null;
  last_error: string | null;
  head_sha: string | null;
  commits_total: number;
  commits_unsynced: number;
  pull: boolean;
  pull_interval_minutes: number;
  webhook: boolean;
  commits_from_git: number;
  last_import_at: string | null;
  last_imported_sha: string | null;
  import_notes: string[];
}

export interface ApiTokenInfo {
  id: number;
  name: string;
  prefix: string;
  role: Role;
  scopes: TokenScope[];
  username: string;
  created_by: string;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
}
export type TokenScope = "siem" | "read";
export interface ApiTokenCreated extends ApiTokenInfo {
  token: string;
}
export interface SiemUnlinked {
  rule_id: string;
  name: string;
  enabled: boolean;
  severity: string;
  techniques: string[];
  suggestions: string[];
}
export interface SiemSourceInfo {
  name: string;
  inventory_at: string | null;
  inventory_by: string | null;
  alerts_at: string | null;
  alerts_by: string | null;
  alerts_report: { created?: number; updated?: number; matched?: number; unmatched?: string[]; errors?: string[] };
  rules_total: number;
  enabled: number;
  linked: number;
  unlinked: SiemUnlinked[];
  disabled_but_operational: { rule_id: string; name: string; code: string }[];
}
export interface SiemOverview {
  sources: SiemSourceInfo[];
  missing_in_siem: { code: string; name: string; rule_id: string; status: Lifecycle }[];
  linked_rules: number;
}

export interface GapRow {
  code: string;
  name: string;
  l2_code: string;
  l2_name: string;
  lifecycle_status: Lifecycle;
  effectiveness: number | null;
  implementation: number | null;
  coverage: number | null;
  weight: number | null;
  potential: number | null;
  risk: number | null;
  risk_source: string | null;
  risk_system?: string | null;
  target: number | null;
  target_source: string | null;
  gap: number | null;
  priority: number | null;
  business_drivers: string[];
  compliance_drivers: string[];
  driver_boost: number;
}
export interface Gaps {
  summary: {
    rules: number;
    with_target: number;
    below_target: number;
    no_risk: number;
    avg_gap: number | null;
    by_risk: Record<string, { rules: number; below_target: number }>;
    risk_targets: Record<string, number>;
  };
  rows: GapRow[];
  driver_gaps: DriverCoverage[];
  driver_low_threshold: number;
}
export interface TotpSetup {
  secret: string;
  uri: string;
  qr_svg: string;
}

/** 409 from a config save: someone committed in between. */
export interface AttackHit {
  code: string;
  name: string;
  weight: number | null;
  direct: boolean;
}
export interface AttackTech {
  id: string;
  name: string;
  best: number | null;
  rules: AttackHit[];
  subs: AttackTech[];
}
export interface AttackTactic {
  id: string;
  short: string;
  name: string;
  techniques: AttackTech[];
  covered: number;
  total: number;
}
export interface AttackOutdated {
  code: string;
  name: string;
  id: string;
  status: "revoked" | "deprecated" | "unknown";
  replacement: string | null;
}
export interface AttackCoverage {
  version: string;
  tactics: AttackTactic[];
  techniques_total: number;
  techniques_with_rules: number;
  techniques_scored: number;
  rules_total: number;
  rules_mapped: number;
  outdated: AttackOutdated[];
}
export interface RemapResult {
  version: string;
  rules: number;
  ids_replaced: number;
  applied: boolean;
  changes: { code: string; name: string; before: string[]; after: string[]; kept: string[] }[];
}
export interface OutputMetric {
  period: string;
  alerts: number;
  incidents: number;
  false_positives: number;
  false_negatives: number | null;
  fp_rate: number | null;
  note: string;
  source: string;
  updated_by: string;
}
export type OutputMetricInput = Pick<
  OutputMetric,
  "alerts" | "incidents" | "false_positives" | "false_negatives" | "note"
>;
export interface OutputTotal {
  period: string;
  rules: number;
  alerts: number;
  incidents: number;
  false_positives: number;
  false_negatives: number;
  fp_rate: number | null;
}
export interface OutputRuleTotal {
  code: string;
  name: string;
  months: number;
  alerts: number;
  incidents: number;
  false_positives: number;
  false_negatives: number;
  fp_rate: number | null;
}
export interface OutputSummary {
  months: OutputTotal[];
  rules: OutputRuleTotal[];
  rules_reporting: number;
  totals: OutputTotal;
}
export interface CsvReport {
  dry_run: boolean;
  rows: number;
  created: number;
  updated: number;
  errors: string[];
}

/* ------------------------------------------------------------------ systems and interviews (#17) */

export type Stride =
  | "spoofing"
  | "tampering"
  | "repudiation"
  | "information_disclosure"
  | "denial_of_service"
  | "elevation_of_privilege";
export interface CustomThreat {
  key: string;
  title: string;
  description: string;
  techniques: string[];
  likelihood: number | null;
  impact: number | null;
}

/** a STRIDE category or a custom ATT&CK threat of a component (#60) */
export type ThreatCategory = Stride | `custom:${string}`;
export type ThreatState = "applies" | "does_not_apply" | "not_discussed";
export type Classification = "public" | "internal" | "confidential" | "restricted";
export type InterviewStatus = "draft" | "completed" | "confirmed";

export interface SystemInput {
  name: string;
  description: string;
  owner_name: string;
  owner_department: string;
  owner_email: string | null;
  criticality: number;
  internet_facing: boolean;
  data_classification: Classification;
  review_interval_months: number;
  archived: boolean;
}

export interface SystemRow extends SystemInput {
  id: number;
  updated_at: string | null;
  linked: number;
  coverage: number | null;
  gaps: number;
  last_interview: string | null;
  next_due: string | null;
  state: "none" | "due" | "ok";
  draft_id: number | null;
  can_delete: boolean;
}

export type UseCaseLevel = "L2" | "L3";
export type Detection = "no_rules" | "unknown" | "blind" | "partial" | "ok";
export type RiskCoverageState = "covered" | "partial" | "gap" | "below" | "unrated";

/** A use case chosen by hand: a whole L2 or a single L3 rule. */
export type AddedUseCase = { l2_id: number; l3_id?: undefined; threats: ThreatRef[] } | { l3_id: number; l2_id?: undefined; threats: ThreatRef[] };

/** Implementation status of a detection request (PROJ-1). */
export type RequestStatus = "open" | "in_progress" | "implemented" | "rejected" | "not_feasible";

export const REQUEST_STATUSES: RequestStatus[] = ["open", "in_progress", "implemented", "rejected", "not_feasible"];

/** What implemented a request: an L2 use case or a single L3 rule. */
export interface RequestLink {
  l2_id: number | null;
  l3_id: number | null;
  code: string;
  deleted: boolean;
}

/** The status part of a detection request; shared by all interviews of the system. */
export interface RequestState {
  status: RequestStatus;
  status_note: string;
  link: RequestLink | null;
  status_by: string | null;
  status_at: string | null;
}

/** A detection request as the API shows it (title and description are frozen with the interview). */
export interface DetectionRequest extends RequestState {
  key: string;
  title: string;
  description: string;
  component: string;
  component_name: string;
  category: ThreatCategory;
}

/** A request in the overview of all systems (PROJ-2). */
export interface OverviewRequest extends RequestState {
  key: string;
  title: string;
  description: string;
  system_id: number;
  system_name: string;
  archived: boolean;
  /** component name */
  component: string;
  category: ThreatCategory;
  /** risk score (1..25) of the threat; null when unrated */
  risk_score: number | null;
}

/** One applying threat with the accepted use cases that address it (risk overview). */
export interface RiskRow {
  component: string;
  component_name: string;
  category: ThreatCategory;
  /** #60: custom ATT&CK threat */
  custom?: boolean;
  title?: string | null;
  techniques?: string[];
  description: string;
  likelihood: number | null;
  impact: number | null;
  score: number | null;
  level: number | null;
  above_threshold: boolean;
  coverage: RiskCoverageState;
  use_cases: {
    level: UseCaseLevel;
    l2_id: number;
    l3_id: number | null;
    code: string;
    name: string;
    l2_code: string | null;
    detection: Detection | null;
    /** how far the use case covers the threat */
    state: "ok" | "partial" | "gap";
    weight: number | null;
    manual: boolean;
    /** #57: proposed for this risk by the mapping, not only added by hand */
    auto?: boolean;
    deleted: boolean;
  }[];
  requests: { key: string; title: string; status: RequestStatus }[];
}

export interface SystemLinkInfo {
  level: UseCaseLevel;
  l2_id: number;
  l3_id: number | null;
  code: string;
  name: string;
  l2_code: string;
  detection: Detection | null;
  weight: number | null;
  risk_score: number;
  risk_level: number | null;
  sources: { component: string; category: ThreatCategory; score: number | null }[];
}

export interface InterviewRow {
  id: number;
  status: InterviewStatus;
  interview_date: string;
  analyst: string;
  completed_at: string | null;
  confirmed_by: string | null;
  confirmed_at: string | null;
  previous_id: number | null;
}

export interface SystemDetail extends SystemRow {
  links: SystemLinkInfo[];
  /** risk overview of the latest completed interview with the current state of its links */
  risks: RiskRow[];
  threshold: number | null;
  /** components of that interview (threat matrix rows) */
  components: { key: string; name: string; custom_threats?: { category: ThreatCategory; title: string; techniques: string[] }[] }[];
  gap_no_rules: { code: string; name: string }[];
  /** #41: grouped per L2; `blind` = no active rule gets any log source it needs (counts as gap) */
  gap_log_sources: {
    l2_code: string;
    l2_name: string;
    components: string[];
    blind: boolean;
    rules: { rule_code: string; rule_name: string; missing: string[]; partial: boolean }[];
  }[];
  /** all detection requests of the latest completed interview, with their status */
  gap_requests: (RequestState & { key: string; title: string; description: string; component: string; category: ThreatCategory })[];
  /** #59: risks above the threshold that no linked use case addresses */
  gap_risks?: { component: string; component_name: string; category: ThreatCategory; score: number | null; level: number | null }[];
  interviews: InterviewRow[];
}

export interface ThreatView {
  category: ThreatCategory;
  /** #60: custom threat linked to MITRE ATT&CK */
  custom?: boolean;
  title?: string;
  techniques?: string[];
  state: ThreatState;
  description: string;
  likelihood: number | null;
  impact: number | null;
  score: number | null;
  complete: boolean;
}

export interface ComponentView {
  key: string;
  name: string;
  description: string;
  log_sources: { id: number; name: string }[];
  threats: ThreatView[];
}

export interface ThreatRef {
  component: string;
  category: ThreatCategory;
}

export interface ProposalRule {
  code: string;
  name: string;
  lifecycle_status: Lifecycle;
  log_sources: string[];
  missing: string[];
  unknown: boolean;
  /** #40: only onboarding, operational and maintenance rules count */
  active: boolean;
  coverage: "unknown" | "blind" | "partial" | "ok" | "inactive";
}

export interface Proposal {
  /** missing in interviews completed before L3 rules could be chosen: L2 */
  level?: UseCaseLevel;
  l2_id: number;
  /** L3 rule chosen by hand (level L3) */
  l3_id?: number | null;
  l2_code?: string;
  l2_name?: string;
  code: string;
  name: string;
  l1_code: string;
  l1_applicable: boolean;
  risk_score: number | null;
  sources: { component: string; component_name: string; category: ThreatCategory; score: number | null }[];
  auto: boolean;
  manual: boolean;
  rules: ProposalRule[];
  /** #38/#41: how well the active rules see the threatened components */
  detection?: Detection;
  reason?: string;
  /** #57: removed only from these risks (the rest of the L2 stays accepted) */
  threats?: { component: string; component_name: string; category: ThreatCategory }[];
  /** completed interviews: the use case was deleted since */
  deleted?: boolean;
}

export interface InterviewView {
  threshold: number;
  mapping_empty: boolean;
  components: ComponentView[];
  incomplete: { component: string; category: ThreatCategory }[];
  proposals: Proposal[];
  removed: Proposal[];
  below_threshold: {
    component: string;
    component_name: string;
    category: ThreatCategory;
    score: number;
    l2s: { l2_id: number; code: string; name: string; l1_code: string; l1_applicable: boolean }[];
  }[];
  added: AddedUseCase[];
  removed_ids: number[];
  risks: RiskRow[];
  requests: DetectionRequest[];
  log_source_gaps: { l2_code: string; rule_code: string; rule_name: string; missing: string[]; partial?: boolean }[];
  /** #38: accepted use cases without any active rule */
  no_detection?: string[];
  /** #38: components with applying threats but no log sources */
  components_without_log_sources?: string[];
  /** #36: proposals are limited to L2s whose rules use a log source of the component */
  log_source_filter: boolean;
  /** #36: L2s the filter held back */
  log_source_mismatch: {
    l2_id: number;
    code: string;
    name: string;
    l1_code: string;
    l1_applicable: boolean;
    risk_score: number | null;
    log_sources: string[];
    sources: {
      component: string;
      component_name: string;
      category: ThreatCategory;
      score: number | null;
      component_log_sources: string[];
    }[];
  }[];
}

/** Evidence file of an interview (#34). */
export interface InterviewAttachment {
  id: number;
  interview_id: number;
  filename: string;
  content_type: string;
  size: number;
  sha256: string;
  uploaded_by: string;
  uploaded_at: string;
  viewable: boolean;
  kind: "pdf" | "image" | "diagram" | "threat_model";
  /** the business owner's sign-off (#42) */
  signoff?: boolean;
}

export interface EvidenceStorage {
  files: number;
  used_bytes: number;
  limit_bytes: number;
}

export interface Interview {
  id: number;
  system_id: number;
  system_name: string;
  owner_name: string;
  archived: boolean;
  status: InterviewStatus;
  interview_date: string;
  participants: string;
  notes: string;
  analyst: string;
  version: number;
  updated_by: string;
  updated_at: string | null;
  completed_at: string | null;
  completed_by: string | null;
  confirmed_by: string | null;
  confirmed_at: string | null;
  confirmation_recorded_by: string | null;
  previous_id: number | null;
  min_date: string | null;
  view: InterviewView;
  attachments: InterviewAttachment[];
}

export interface InterviewSave {
  expected_version: number;
  interview_date: string;
  participants: string;
  notes: string;
  components: {
    key: string;
    name: string;
    description: string;
    log_source_ids: number[];
    threats: { category: Stride; state: ThreatState; description: string; likelihood: number | null; impact: number | null }[];
    /** #60: threats beyond STRIDE, linked to MITRE ATT&CK techniques (they always apply) */
    custom_threats: CustomThreat[];
  }[];
  added: AddedUseCase[];
  /** without threats the whole L2 is removed; with threats only from those risks (#57) */
  removed: { l2_id: number; reason: string; threats?: ThreatRef[] }[];
  requests: { key: string; title: string; description: string; threat: ThreatRef }[];
}

export interface InterviewCompare {
  previous_id: number;
  previous_date: string;
  components_added: string[];
  components_removed: string[];
  threats_added: { component: string; category: ThreatCategory }[];
  threats_removed: { component: string; category: ThreatCategory }[];
  threats_rerated: { component: string; category: ThreatCategory; old_score: number | null; new_score: number | null }[];
  use_cases_added: { code: string; name: string }[];
  use_cases_removed: { code: string; name: string }[];
}

export interface StrideMapping {
  threshold: number;
  log_source_filter: boolean;
  categories: {
    category: Stride;
    l2s: { l2_id: number; code: string; name: string; l1_applicable: boolean }[];
  }[];
}

export class ConflictError extends Error {
  constructor(
    message: string,
    public head: ConfigCommit | null,
    public diff: { lines: DiffLine[]; added: number; removed: number },
  ) {
    super(message);
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    /** the JSON body of the error answer, e.g. the use cases that block a delete */
    public data: unknown = null,
  ) {
    super(message);
  }
}

/** Called on any 401 so the app can send the user to the login page. */
// True from the moment the session ends (expired or signed out): pages then let the redirect to
// the login page through instead of asking about unsaved changes.
let leavingSession = false;
export function isLeavingSession(): boolean {
  return leavingSession;
}
export function setLeavingSession(v: boolean) {
  leavingSession = v;
}

let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    if (res.status === 409 && data && typeof data === "object" && "diff" in data) {
      const d = data as { detail: string; head: ConfigCommit | null; diff: ConflictError["diff"] };
      throw new ConflictError(d.detail, d.head, d.diff);
    }
    if (res.status === 401 && !path.startsWith("/api/auth/")) {
      leavingSession = true;
      onUnauthorized();
    }
    throw new ApiError(res.status, detailMessage(data) ?? `${res.status} ${res.statusText}`, data);
  }
  return data as T;
}

function detailMessage(data: unknown): string | null {
  if (!data || typeof data !== "object" || !("detail" in data)) return null;
  const d = (data as { detail: unknown }).detail;
  if (typeof d === "string") return translateServer(d);
  if (Array.isArray(d)) return d.map((e) => e?.msg ?? String(e)).join("; ");
  return null;
}

export const api = {
  version: () => request<VersionInfo>("GET", "/api/version"),
  login: (username: string, password: string, otp?: string) =>
    request<User>("POST", "/api/auth/login", { username, password, ...(otp ? { otp } : {}) }),
  logout: () => request<void>("POST", "/api/auth/logout"),
  me: () => request<User>("GET", "/api/auth/me"),
  apiTokens: () => request<ApiTokenInfo[]>("GET", "/api/integrations/tokens"),
  createApiToken: (body: {
    name: string;
    role: "analyst" | "auditor";
    scopes: TokenScope[];
    expires_days: number | null;
  }) =>
    request<ApiTokenCreated>("POST", "/api/integrations/tokens", body),
  revokeApiToken: (id: number) => request<void>("DELETE", `/api/integrations/tokens/${id}`),
  siem: () => request<SiemOverview>("GET", "/api/integrations/siem"),
  deleteSiemSource: (name: string) => request<void>("DELETE", `/api/integrations/siem/${enc(name)}`),
  setLocale: (locale: Lang | null) => request<User>("PUT", "/api/auth/me/locale", { locale }),
  changePassword: (current_password: string, new_password: string) =>
    request<void>("POST", "/api/auth/me/password", { current_password, new_password }),
  summary: () => request<CatalogueSummary>("GET", "/api/catalogue/summary"),
  users: () => request<User[]>("GET", "/api/users"),
  createUser: (u: {
    username: string;
    display_name: string;
    role: Role;
    password: string;
    email?: string | null;
    expires_at?: string | null;
    expiry_follows_campaign?: boolean;
  }) => request<User>("POST", "/api/users", u),
  updateUser: (
    id: number,
    u: Partial<{
      display_name: string;
      role: Role;
      active: boolean;
      password: string;
      expires_at: string | null;
      expiry_follows_campaign: boolean;
    }>,
  ) => request<User>("PATCH", `/api/users/${id}`, u),
  deleteUser: (id: number) => request<void>("DELETE", `/api/users/${id}`),
  audit: (limit = 100) => request<AuditEntry[]>("GET", `/api/audit?limit=${limit}`),

  scores: () => request<Scores>("GET", "/api/scores"),
  due: (withinDays = 30) => request<DueRule[]>("GET", `/api/verification/due?within_days=${withinDays}`),
  verify: (level: "l2" | "l3", code: string, body: { result: "ok" | "issues"; note: string; verified_at?: string }) =>
    request<Verification>("POST", `/api/${level}/${enc(code)}/verify`, body),
  verifications: (level: "l2" | "l3", code: string) =>
    request<Verification[]>("GET", `/api/${level}/${enc(code)}/verifications`),

  l1s: () => request<L1[]>("GET", "/api/l1"),
  createL1: (body: L1Input & { code: string; name: string }) => request<L1>("POST", "/api/l1", body),
  updateL1: (code: string, body: L1Input) => request<L1>("PATCH", `/api/l1/${enc(code)}`, body),
  deleteL1: (code: string) => request<void>("DELETE", `/api/l1/${enc(code)}`),
  l2s: (l1?: string) => request<L2[]>("GET", `/api/l2${l1 ? `?l1=${enc(l1)}` : ""}`),
  l2: (code: string) => request<L2>("GET", `/api/l2/${enc(code)}`),
  createL2: (body: L2Input & { code: string; name: string }) => request<L2>("POST", "/api/l2", body),
  updateL2: (code: string, body: L2Input) => request<L2>("PATCH", `/api/l2/${enc(code)}`, body),
  /** Refused with 409 and `systems` while systems link the L2 and confirm is false (#48). */
  deleteL2: (code: string, confirm = false) =>
    request<void>("DELETE", `/api/l2/${enc(code)}${confirm ? "?confirm=true" : ""}`),
  evidenceStorage: () => request<EvidenceStorage>("GET", "/api/evidence/storage"),
  l3s: (filter: { l2?: string; l1?: string } = {}) =>
    request<L3[]>("GET", `/api/l3?${new URLSearchParams(filter as Record<string, string>)}`),
  l3: (code: string) => request<L3>("GET", `/api/l3/${enc(code)}`),
  createL3: (body: L3Input & { code: string; name: string }) => request<L3>("POST", "/api/l3", body),
  updateL3: (code: string, body: L3Input) => request<L3>("PATCH", `/api/l3/${enc(code)}`, body),
  deleteL3: (code: string) => request<void>("DELETE", `/api/l3/${enc(code)}`),
  nextL3Code: (l2: string) => request<{ code: string }>("GET", `/api/l3/next-code/${enc(l2)}`),

  ruleNameSettings: () => request<RuleNameSettings>("GET", "/api/settings/rule-name"),
  saveRuleNameSettings: (body: { format: string; variables: RuleNameVariable[] }) =>
    request<RuleNameSettings>("PUT", "/api/settings/rule-name", body),

  refs: (kind: RefKind) => request<RefItem[]>("GET", `/api/references/${kind}`),
  createRef: (kind: RefKind, body: { name: string; description: string }) =>
    request<RefItem>("POST", `/api/references/${kind}`, body),
  updateRef: (kind: RefKind, id: number, body: { name: string; description: string }) =>
    request<RefItem>("PATCH", `/api/references/${kind}/${id}`, body),
  /** Refused with 409 and `used_by` (use case codes) while the entry is in use and not confirmed. */
  deleteRef: (kind: RefKind, id: number, confirm = false) =>
    request<void>("DELETE", `/api/references/${kind}/${id}${confirm ? "?confirm=true" : ""}`),

  drivers: () => request<BusinessDriver[]>("GET", "/api/business-drivers"),
  createDriver: (body: Omit<BusinessDriver, "id">) => request<BusinessDriver>("POST", "/api/business-drivers", body),
  updateDriver: (id: number, body: Omit<BusinessDriver, "id">) =>
    request<BusinessDriver>("PATCH", `/api/business-drivers/${id}`, body),
  deleteDriver: (id: number) => request<void>("DELETE", `/api/business-drivers/${id}?confirm=true`),
  driverUseCases: (id: number) => request<LinkedUseCase[]>("GET", `/api/business-drivers/${id}/use-cases`),
  complianceDriverUseCases: (id: number) =>
    request<LinkedUseCase[]>("GET", `/api/compliance/drivers/${id}/use-cases`),
  sourceUseCases: (id: number) => request<LinkedUseCase[]>("GET", `/api/compliance/${id}/use-cases`),
  driverCoverage: () => request<DriverCoverageReport>("GET", "/api/drivers/coverage"),
  compliance: () => request<ComplianceSource[]>("GET", "/api/compliance"),
  createSource: (name: string) => request<ComplianceSource>("POST", "/api/compliance", { name }),
  renameSource: (id: number, name: string) =>
    request<ComplianceSource>("PATCH", `/api/compliance/${id}`, { name }),
  deleteSource: (id: number) => request<void>("DELETE", `/api/compliance/${id}?confirm=true`),
  createComplianceDriver: (sourceId: number, body: { ref: string; name: string; description: string }) =>
    request<ComplianceDriver>("POST", `/api/compliance/${sourceId}/drivers`, body),
  updateComplianceDriver: (id: number, body: { ref: string; name: string; description: string }) =>
    request<ComplianceDriver>("PATCH", `/api/compliance/drivers/${id}`, body),
  deleteComplianceDriver: (id: number) => request<void>("DELETE", `/api/compliance/drivers/${id}?confirm=true`),

  authConfig: () => request<AuthConfig>("GET", "/api/auth/config"),

  config: (level: Level, code: string) => request<ConfigState>("GET", cfgUrl(level, code)),
  saveConfig: (level: Level, code: string, body: { content: string; message: string; base_sha: string | null }) =>
    request<ConfigCommit>("PUT", cfgUrl(level, code), body),
  configHistory: (level: Level, code: string) => request<ConfigCommit[]>("GET", `${cfgUrl(level, code)}/history`),
  configCommit: (level: Level, code: string, ref: string) =>
    request<ConfigCommit & { content: string }>("GET", `${cfgUrl(level, code)}/commits/${enc(ref)}`),
  configDiff: (level: Level, code: string, to: string, from?: string) =>
    request<ConfigDiff>("GET", `${cfgUrl(level, code)}/diff?${new URLSearchParams({ to, ...(from ? { from } : {}) })}`),
  restoreConfig: (level: Level, code: string, ref: string, message = "") =>
    request<ConfigCommit>("POST", `${cfgUrl(level, code)}/restore/${enc(ref)}`, { message }),
  tagConfig: (level: Level, code: string, name: string, ref?: string) =>
    request<ConfigCommit>("POST", `${cfgUrl(level, code)}/tags`, { name, ref }),
  configDownloadUrl: (level: Level, code: string, ref?: string) =>
    `${cfgUrl(level, code)}/download${ref ? `?ref=${enc(ref)}` : ""}`,
  validateConfig: (content: string) => request<ConfigCheck>("POST", "/api/config/validate", { content }),
  recentCommits: (limit = 6) => request<RecentCommit[]>("GET", `/api/config/recent?limit=${limit}`),
  configHeads: (level: Level, prefix = "") =>
    request<Record<string, ConfigCommit>>("GET", `/api/config/heads/${level}?prefix=${enc(prefix)}`),

  importExcel: async (file: File, mode: "merge" | "replace", dryRun: boolean): Promise<ImportReport> => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("mode", mode);
    fd.append("dry_run", String(dryRun));
    const res = await fetch("/api/import/excel", { method: "POST", body: fd, credentials: "same-origin" });
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new ApiError(res.status, detailMessage(data) ?? `${res.status} ${res.statusText}`, data);
    return data as ImportReport;
  },

  lifecycleMeta: () => request<LifecycleMeta>("GET", "/api/lifecycle/meta"),
  lifecycle: (level: Level, code: string) => request<LifecycleState>("GET", `/api/${level}/${enc(code)}/lifecycle`),
  changeStatus: (level: Level, code: string, body: LifecycleChange) =>
    request<LifecycleState>("POST", `/api/${level}/${enc(code)}/lifecycle`, body),
  setDod: (level: Level, code: string, items: Record<string, boolean>) =>
    request<LifecycleState>("PUT", `/api/${level}/${enc(code)}/dod`, { items }),
  changes: (limit = 50, driverType = "") =>
    request<LifecycleEvent[]>(
      "GET",
      `/api/changes?${new URLSearchParams({ limit: String(limit), ...(driverType ? { driver_type: driverType } : {}) })}`,
    ),
  snapshots: () => request<Snapshot[]>("GET", "/api/snapshots"),
  takeSnapshot: (label: string) => request<Snapshot>("POST", "/api/snapshots", { label }),
  deleteSnapshot: (id: number) => request<void>("DELETE", `/api/snapshots/${id}`),
  compareSnapshots: (a: string, b: string) =>
    request<SnapshotCompare>("GET", `/api/snapshots/compare?${new URLSearchParams({ a, b })}`),
  trends: () => request<Trends>("GET", "/api/trends"),
  gitStatus: () => request<GitStatus>("GET", "/api/admin/git"),
  gitSync: () => request<GitStatus>("POST", "/api/admin/git/sync"),

  gaps: (f: { l1?: string; min_risk?: number; below_target?: boolean } = {}) =>
    request<Gaps>(
      "GET",
      `/api/growth/gaps?${new URLSearchParams(
        Object.entries(f)
          .filter(([, v]) => v !== undefined && v !== "")
          .map(([k, v]) => [k, String(v)]),
      )}`,
    ),
  totpSetup: (password: string) => request<TotpSetup>("POST", "/api/auth/me/totp/setup", { password }),
  totpEnable: (code: string) => request<{ recovery_codes: string[] }>("POST", "/api/auth/me/totp/enable", { code }),
  totpDisable: (password: string, code: string) =>
    request<void>("POST", "/api/auth/me/totp/disable", { password, code }),
  totpNewCodes: (password: string, code: string) =>
    request<{ recovery_codes: string[] }>("POST", "/api/auth/me/totp/recovery-codes", { password, code }),
  resetTotp: (userId: number) => request<User>("DELETE", `/api/users/${userId}/totp`),

  attackCoverage: () => request<AttackCoverage>("GET", "/api/attack/coverage"),
  /** #60: all current ATT&CK techniques */
  attackTechniques: () => request<{ id: string; name: string }[]>("GET", "/api/attack/techniques"),
  remapPreview: () => request<RemapResult>("GET", "/api/attack/remap"),
  remapApply: () => request<RemapResult>("POST", "/api/attack/remap"),
  outputMetrics: (code: string, months = 12) =>
    request<OutputMetric[]>("GET", `/api/l3/${enc(code)}/output-metrics?months=${months}`),
  setOutputMetric: (code: string, period: string, body: OutputMetricInput) =>
    request<OutputMetric>("PUT", `/api/l3/${enc(code)}/output-metrics/${period}`, body),
  deleteOutputMetric: (code: string, period: string) =>
    request<void>("DELETE", `/api/l3/${enc(code)}/output-metrics/${period}`),
  outputSummary: (months = 12) => request<OutputSummary>("GET", `/api/output-metrics/summary?months=${months}`),
  importOutputCsv: async (file: File, dryRun: boolean): Promise<CsvReport> => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("dry_run", String(dryRun));
    const res = await fetch("/api/import/output-metrics", { method: "POST", body: fd, credentials: "same-origin" });
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new ApiError(res.status, detailMessage(data) ?? `${res.status} ${res.statusText}`, data);
    return data as CsvReport;
  },

  systems: (f: { archived?: boolean; due?: boolean } = {}) =>
    request<SystemRow[]>(
      "GET",
      `/api/systems?${new URLSearchParams({ archived: String(!!f.archived), due: String(!!f.due) })}`,
    ),
  systemsDue: () => request<{ due: number }>("GET", "/api/systems/due-count"),
  system: (id: number) => request<SystemDetail>("GET", `/api/systems/${id}`),
  createSystem: (body: SystemInput) => request<SystemDetail>("POST", "/api/systems", body),
  updateSystem: (id: number, body: SystemInput) => request<SystemDetail>("PATCH", `/api/systems/${id}`, body),
  deleteSystem: (id: number) => request<void>("DELETE", `/api/systems/${id}`),
  startInterview: (systemId: number) => request<Interview>("POST", `/api/systems/${systemId}/interviews`),
  interview: (id: number) => request<Interview>("GET", `/api/interviews/${id}`),
  saveInterview: (id: number, body: InterviewSave) => request<Interview>("PUT", `/api/interviews/${id}`, body),
  /** PROJ-2: the requests of the latest completed interview of every system */
  detectionRequests: () => request<{ requests: OverviewRequest[] }>("GET", "/api/detection-requests"),
  /** PROJ-1: works on draft and completed interviews; the last write wins */
  setRequestStatus: (
    systemId: number,
    key: string,
    body: { status: RequestStatus; note: string; l2_id?: number | null; l3_id?: number | null },
  ) =>
    request<RequestState & { key: string }>(
      "PUT",
      `/api/systems/${systemId}/detection-requests/${enc(key)}/status`,
      body,
    ),
  deleteInterview: (id: number) => request<void>("DELETE", `/api/interviews/${id}`),
  completeInterview: (id: number, version: number) =>
    request<Interview>("POST", `/api/interviews/${id}/complete`, { expected_version: version }),
  confirmInterview: (id: number, body: { confirmed_by: string; confirmed_at: string }) =>
    request<Interview>("PUT", `/api/interviews/${id}/confirmation`, body),
  unconfirmInterview: (id: number, reason: string) =>
    request<Interview>("DELETE", `/api/interviews/${id}/confirmation`, { reason }),
  compareInterview: (id: number) => request<InterviewCompare>("GET", `/api/interviews/${id}/compare`),
  interviewPdfUrl: (id: number, lang: Lang) => `/api/interviews/${id}/pdf?lang=${lang}`,
  strideMapping: () => request<StrideMapping>("GET", "/api/stride-mapping"),
  setStrideMapping: (category: ThreatCategory, l2_ids: number[]) =>
    request<StrideMapping>("PUT", `/api/stride-mapping/${category}`, { l2_ids }),
  setProposalThreshold: (value: number) =>
    request<StrideMapping>("PUT", "/api/stride-mapping/threshold", { proposal_threshold: value }),
  setLogSourceFilter: (enabled: boolean) =>
    request<StrideMapping>("PUT", "/api/stride-mapping/log-source-filter", { enabled }),
  uploadAttachment: async (interviewId: number, file: File, signoff = false): Promise<InterviewAttachment> => {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`/api/interviews/${interviewId}/attachments${signoff ? "?signoff=true" : ""}`, {
      method: "POST",
      body: fd,
      credentials: "same-origin",
    });
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new ApiError(res.status, detailMessage(data) ?? `${res.status} ${res.statusText}`, data);
    return data as InterviewAttachment;
  },
  deleteAttachment: (id: number) => request<void>("DELETE", `/api/interview-attachments/${id}`),
  attachmentUrl: (id: number, download = false) =>
    `/api/interview-attachments/${id}/content${download ? "?download=1" : ""}`,
  resetStrideMapping: () => request<StrideMapping>("POST", "/api/stride-mapping/reset"),

  // tests and campaigns (PROJ-3)
  campaigns: () => request<CampaignRow[]>("GET", "/api/campaigns"),
  campaign: (id: number) => request<CampaignDetail>("GET", `/api/campaigns/${id}`),
  createCampaign: (b: CampaignInput) => request<CampaignRow>("POST", "/api/campaigns", b),
  updateCampaign: (id: number, b: CampaignInput) => request<CampaignRow>("PUT", `/api/campaigns/${id}`, b),
  deleteCampaign: (id: number) => request<void>("DELETE", `/api/campaigns/${id}`),
  setCampaignStatus: (id: number, status: CampaignStatus) =>
    request<CampaignRow>("POST", `/api/campaigns/${id}/status`, { status }),
  proposals: (id: number, b: { l2_codes: string[]; l3_codes: string[] }) =>
    request<TestProposals>("POST", `/api/campaigns/${id}/proposals`, b),
  redTeamAccounts: () => request<CampaignAccount[]>("GET", "/api/red-team-accounts"),
  addTest: (campaignId: number, b: TestInput) => request<TestCaseOut>("POST", `/api/campaigns/${campaignId}/tests`, b),
  test: (id: number) => request<TestCaseOut>("GET", `/api/tests/${id}`),
  updateTest: (id: number, b: TestInput) => request<TestCaseOut>("PUT", `/api/tests/${id}`, b),
  deleteTest: (id: number) => request<void>("DELETE", `/api/tests/${id}`),
  recordRed: (
    id: number,
    b: { exec_status: TestStatus; executed_at: string | null; red_notes: string; expected_version: number },
  ) => request<TestCaseOut>("PUT", `/api/tests/${id}/red`, b),
  recordBlue: (
    id: number,
    b: { outcome: TestOutcome | null; detected_at: string | null; blue_notes: string; expected_version: number },
  ) => request<TestCaseOut>("PUT", `/api/tests/${id}/blue`, b),
  testDetail: (id: number) => request<TestDetail>("GET", `/api/tests/${id}`),
  testEvents: (id: number, before: number) =>
    request<TestEvent[]>("GET", `/api/tests/${id}/events?before=${before}`),
  openRound: (id: number) => request<TestDetail>("POST", `/api/tests/${id}/rounds`),
  deleteRound: (id: number, n: number) => request<TestDetail>("DELETE", `/api/tests/${id}/rounds/${n}`),
  recordRoundRed: (id: number, n: number, b: RoundRedInput) =>
    request<TestDetail>("PUT", `/api/tests/${id}/rounds/${n}/red`, b),
  recordRoundBlue: (id: number, n: number, b: RoundBlueInput) =>
    request<TestDetail>("PUT", `/api/tests/${id}/rounds/${n}/blue`, b),
  addComment: (id: number, text: string, round_number: number | null) =>
    request<TestDetail>("POST", `/api/tests/${id}/comments`, { text, round_number }),
  removeComment: (id: number, eid: number) => request<TestDetail>("DELETE", `/api/tests/${id}/comments/${eid}`),
  setCollaboration: (cid: number, collaboration: Collaboration) =>
    request<{ collaboration: Collaboration }>("POST", `/api/campaigns/${cid}/collaboration`, { collaboration }),
  saveToLibrary: (id: number) => request<TestTemplate>("POST", `/api/tests/${id}/library`),
  quickTests: (f: { outcome?: TestOutcome; technique?: string; open_gaps?: boolean } = {}) =>
    request<TestCaseOut[]>(
      "GET",
      `/api/quick-tests?${new URLSearchParams(
        Object.entries(f).filter(([, v]) => v !== undefined && v !== "" && v !== false) as [string, string][],
      )}`,
    ),
  createQuickTest: (b: QuickTestInput) => request<TestCaseOut>("POST", "/api/quick-tests", b),
  library: (f: { technique?: string; q?: string } = {}) =>
    request<TestTemplate[]>(
      "GET",
      `/api/library?${new URLSearchParams(Object.entries(f).filter(([, v]) => v) as [string, string][])}`,
    ),
  createTemplate: (b: Omit<TestTemplate, "id" | "uses" | "created_by" | "created_at" | "updated_at" | "technique_name">) =>
    request<TestTemplate>("POST", "/api/library", b),
  updateTemplate: (
    id: number,
    b: Omit<TestTemplate, "id" | "uses" | "created_by" | "created_at" | "updated_at" | "technique_name">,
  ) => request<TestTemplate>("PUT", `/api/library/${id}`, b),
  deleteTemplate: (id: number) => request<void>("DELETE", `/api/library/${id}`),
  testGaps: (accepted = false) => request<TestGap[]>("GET", `/api/test-gaps?accepted=${accepted}`),
  testGapCount: () => request<{ open: number }>("GET", "/api/test-gaps/count"),
  acceptGap: (b: { l3_code: string | null; technique: string; scope: string; test_id: number; reason: string }) =>
    request<void>("POST", "/api/test-gaps/accept", b),
  ruleTests: (code: string) => request<RuleTests>("GET", `/api/l3/${encodeURIComponent(code)}/tests`),
  l2TestSummary: (code: string) => request<L2TestSummary>("GET", `/api/l2/${encodeURIComponent(code)}/tests-summary`),
  testAttachmentUrl: (id: number, download = false) => `/api/test-attachments/${id}/content${download ? "?download=1" : ""}`,
  uploadTestAttachment: async (testId: number, file: File, round?: number): Promise<TestAttachmentInfo> => {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`/api/tests/${testId}/attachments${round ? `?round=${round}` : ""}`, { method: "POST", body: fd, credentials: "same-origin" });
    const data = await res.json().catch(() => null);
    if (!res.ok) throw new ApiError(res.status, detailMessage(data) ?? `${res.status} ${res.statusText}`, data);
    return data as TestAttachmentInfo;
  },
  deleteTestAttachment: (id: number) => request<void>("DELETE", `/api/test-attachments/${id}`),

  demoDataAllowed: () => request<{ allowed: boolean }>("GET", "/api/admin/demo-data"),
  demoData: (seed: number) => request<Record<string, number>>("POST", "/api/admin/demo-data", { seed }),
};

const enc = encodeURIComponent;
export type Level = "l2" | "l3";
const cfgUrl = (level: Level, code: string) => `/api/${level}/${enc(code)}/config`;


// ---------------------------------------------------------------- tests and campaigns (PROJ-3)

export type TestStatus = "not_run" | "executed" | "not_executable";
export type TestOutcome = "blocked" | "alerted" | "logged" | "not_detected";
export type CampaignStatus = "planned" | "running" | "closed";
export type Collaboration = "hidden" | "open";
export type RoundState = "open" | "waiting" | "done";
export type RuleTestState = "verified" | "partial" | "issues" | "due" | "none";

export interface TestLink {
  l3_code: string;
  rule_name: string;
  scopes: string[];
  deleted: boolean;
  rule_scopes: string[];
}

export interface TestAttachmentInfo {
  id: number;
  side: "red" | "blue";
  round: number | null;
  filename: string;
  size: number;
  uploaded_by: string;
  uploaded_at: string;
  viewable: boolean;
}

export interface TestCaseOut {
  id: number;
  campaign_id: number | null;
  campaign_name: string | null;
  title: string;
  technique: string;
  technique_name: string | null;
  /** Markdown */
  description: string;
  procedure: string;
  tools: string;
  prerequisites: string;
  expected_detection: string;
  created_by: string;
  created_by_red_team: boolean;
  links: TestLink[];
  needs_rules: boolean;
  status: RoundState;
  round_count: number;
  exec_status: TestStatus;
  executed_at: string | null;
  red_notes: string;
  red_by: string | null;
  red_at: string | null;
  outcome: TestOutcome | null;
  detected_at: string | null;
  blue_notes: string | null;
  blue_by: string | null;
  blue_at: string | null;
  time_to_detect_seconds: number | null;
  attachments: TestAttachmentInfo[];
  version: number;
  red_version: number;
  blue_version: number;
  open_gaps: number;
  can_edit_definition: boolean;
  can_record_red: boolean;
  can_record_blue: boolean;
  can_delete: boolean;
}

export interface RoundDetection {
  name: string;
  item_id: number | null;
}

export interface TestRound {
  number: number;
  state: RoundState;
  opened_by: string;
  opened_at: string;
  exec_status: TestStatus;
  started_at: string | null;
  ended_at: string | null;
  executed_what: string;
  red_notes: string;
  red_by: string | null;
  red_at: string | null;
  /** The blue side is hidden from this red-team account (campaign setting). */
  blue_hidden: boolean;
  outcome: TestOutcome | null;
  detected_at: string | null;
  detected_by: RoundDetection[];
  blue_notes: string | null;
  blue_by: string | null;
  blue_at: string | null;
  time_to_detect_seconds: number | null;
  attachments: TestAttachmentInfo[];
  red_version: number;
  blue_version: number;
  can_record_red: boolean;
  can_record_blue: boolean;
  can_delete: boolean;
}

export interface TestEvent {
  id: number;
  round_number: number | null;
  kind: string;
  side: "red" | "blue" | "system";
  author: string;
  at: string;
  text: string;
  data: Record<string, unknown>;
  removed: boolean;
  removed_by: string | null;
  removed_at: string | null;
  can_remove: boolean;
}

export interface TestDetail extends TestCaseOut {
  rounds: TestRound[];
  events: TestEvent[];
  events_more: boolean;
  collaboration: Collaboration | null;
  can_comment: boolean;
  can_open_round: boolean;
  max_rounds: number;
}

export interface RoundRedInput {
  exec_status: TestStatus;
  started_at: string | null;
  ended_at: string | null;
  executed_what: string;
  red_notes: string;
  expected_version: number;
}

export interface RoundBlueInput {
  outcome: TestOutcome | null;
  detected_at: string | null;
  detected_by: string[];
  blue_notes: string;
  expected_version: number;
}

export interface TestInput {
  title: string;
  technique: string;
  description: string;
  procedure: string;
  tools: string;
  prerequisites: string;
  expected_detection: string;
  template_id?: number | null;
  links: { l3_code: string; scopes: string[] }[];
  expected_version?: number | null;
}

export interface QuickTestInput extends TestInput {
  exec_status: TestStatus;
  executed_at: string | null;
  red_notes: string;
  outcome: TestOutcome | null;
  detected_at: string | null;
  blue_notes: string;
}

export interface TestTemplate {
  id: number;
  title: string;
  technique: string;
  technique_name: string | null;
  description: string;
  procedure: string;
  tools: string;
  prerequisites: string;
  expected_detection: string;
  uses: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface CampaignAccount {
  id: number;
  username: string;
  display_name: string;
}

export interface CampaignRow {
  id: number;
  name: string;
  description: string;
  planned_start: string;
  planned_end: string;
  status: CampaignStatus;
  collaboration: Collaboration;
  tests: number;
  outcomes: Record<TestOutcome, number> | null;
  open_points: number;
  accounts: CampaignAccount[];
  can_delete: boolean;
}

export interface CampaignDetail extends CampaignRow {
  test_cases: TestCaseOut[];
}

export interface CampaignInput {
  name: string;
  description: string;
  planned_start: string;
  planned_end: string;
  account_ids: number[];
}

export interface ProposalRuleInfo {
  code: string;
  name: string;
  scopes: string[];
}

export interface TestProposal {
  technique: string;
  technique_name: string | null;
  rules: ProposalRuleInfo[];
  templates: TestTemplate[];
  existing_tests: number;
}

export interface TestProposals {
  proposals: TestProposal[];
  no_technique: ProposalRuleInfo[];
  notes: string[];
}

export interface TestGap {
  l3_code: string | null;
  rule_name: string | null;
  technique: string;
  technique_name: string | null;
  scope: string;
  outcome: TestOutcome;
  test_id: number;
  test_title: string;
  executed_at: string;
  campaign_id: number | null;
  campaign_name: string | null;
  accepted: boolean;
  accepted_reason: string | null;
  accepted_by: string | null;
  accepted_at: string | null;
}

export interface ScopeState {
  scope: string;
  status: "covered" | "expired" | "problem" | "open";
  test_id: number | null;
  test_title: string | null;
  outcome: TestOutcome | null;
  date: string | null;
  until: string | null;
}

export interface RuleTests {
  state: RuleTestState;
  covered: number;
  total: number;
  verified_date: string | null;
  scopes: ScopeState[];
  tests: TestCaseOut[];
  gaps: TestGap[];
  interval_days: number;
}

export interface L2TestSummary {
  tests: number;
  last_test: string | null;
  open_gaps: number;
  states: Record<RuleTestState, number>;
}
