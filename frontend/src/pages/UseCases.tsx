import { useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import {
  api,
  ApiError,
  type BusinessDriver,
  type ComplianceSource,
  type ConfigCommit,
  type L1,
  type L2,
  type L3,
  type RefKind,
  type Scores,
  type Stride,
  type StrideMapping,
  type SystemRow,
} from "../api";
import { useAuth } from "../auth";
import { Markdown, MarkdownField } from "../components/Markdown";
import { BusinessChips, ComplianceChips, DriverBlock, DriverPickers, EditDriversDialog } from "../components/Drivers";
import LifecyclePanel from "../components/LifecyclePanel";
import { L2TestSummaryLine } from "../components/RuleTests";
import {
  Chips,
  confirmDialog,
  ErrorNote,
  GapBadge,
  Modal,
  MultiSelect,
  SelectSearch,
  ShowMore,
  StatusPill,
  useLoad,
  useShowMore,
} from "../components/ui";
import {
  fmtDate,
  isRefKind,
  num,
  pct,
  REF_KIND_ONE,
  REF_KIND_PARAM,
  REF_PARAM,
  STATUS_LABEL,
  today,
} from "../lib/format";
import { STRIDE, STRIDE_HINT, STRIDE_LABEL } from "../lib/stride";
import { t } from "../i18n";

/** STRIDE categories an L2 use case is mapped to. */
function strideOf(m: StrideMapping | undefined, l2Id: number): Stride[] {
  return STRIDE.filter((c) => m?.categories.find((x) => x.category === c)?.l2s.some((x) => x.l2_id === l2Id));
}

interface Catalogue {
  l1s: L1[];
  l2s: L2[];
  scores: Scores;
  drivers: BusinessDriver[];
  sources: ComplianceSource[];
  systems: SystemRow[];
  mapping: StrideMapping;
}

/** Filter by business driver (bd), compliance source (src), compliance driver (cd) and system
 * (sys: L2 use cases linked by the system's latest completed interview). */
interface DriverFilter {
  bd: string;
  src: string;
  cd: string;
  sys: string;
}

function matchesDrivers(l2: L2, f: DriverFilter): boolean {
  if (f.sys && !(l2.systems ?? []).some((s) => String(s.id) === f.sys)) return false;
  if (f.bd && !l2.business_drivers.includes(f.bd)) return false;
  if (f.src && !l2.compliance_drivers.some((c) => String(c.source_id) === f.src)) return false;
  if (f.cd && !l2.compliance_driver_ids.includes(Number(f.cd))) return false;
  return true;
}

/** Names of a rule's entries of one reference list (threat actors are on L2, not on rules). */
function ruleRefs(r: L3, kind: Exclude<RefKind, "threat_actor">): string[] {
  if (kind === "log_source") return r.log_sources;
  if (kind === "detection_technology") return r.detection_technologies;
  return r.scopes;
}

/** Builds the link that sets the reference filter and keeps the other parameters. */
type RefLink = (kind: RefKind, name: string) => string;

export default function UseCases() {
  const { can } = useAuth();
  const editor = can("admin", "analyst");
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState("");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<null | "editL2" | "newL2" | "newL3" | "verifyL2" | "newL1">(null);
  const [editL1, setEditL1] = useState<L1 | null>(null);
  const [driversOf, setDriversOf] = useState<L2 | null>(null);

  const cat = useLoad<Catalogue>(async () => {
    const [l1s, l2s, scores, drivers, sources, systems, mapping] = await Promise.all([
      api.l1s(),
      api.l2s(),
      api.scores(),
      api.drivers(),
      api.compliance(),
      api.systems({ archived: true }),
      api.strideMapping(),
    ]);
    return { l1s, l2s, scores, drivers, sources, systems, mapping };
  });
  const filter: DriverFilter = {
    bd: params.get("bd") ?? "",
    src: params.get("src") ?? "",
    cd: params.get("cd") ?? "",
    sys: params.get("sys") ?? "",
  };

  // Reference filter: one entry of a reference list (?ref_kind=log_source&ref=Windows%20Security).
  // Threat actors filter L2 use cases, the other kinds filter L3 rules.
  const refKindParam = params.get(REF_KIND_PARAM);
  const refName = params.get(REF_PARAM) ?? "";
  const refActive = !!(refKindParam || refName);
  const refKind = isRefKind(refKindParam) && refName ? refKindParam : null;
  const ruleKind = refKind && refKind !== "threat_actor" ? refKind : null;
  const refList = useLoad(() => (refKind ? api.refs(refKind) : Promise.resolve(null)), [refKind]);
  const refMissing =
    refActive && (!refKind || (refList.data !== null && !refList.data.some((i) => i.name === refName)));
  const refRules = useLoad<L3[] | null>(() => (ruleKind ? api.l3s() : Promise.resolve(null)), [ruleKind]);
  const ruleMatches = (r: L3) => !ruleKind || ruleRefs(r, ruleKind).includes(refName);
  const refL2s = useMemo(
    () => new Set((refRules.data ?? []).filter(ruleMatches).map((r) => r.l2_code)),
    [refRules.data, ruleKind, refName],
  );
  const matchesRef = (l2: L2) => {
    if (!refActive) return true;
    if (refMissing || !refKind) return false;
    if (refKind === "threat_actor") return l2.actors.includes(refName);
    return refL2s.has(l2.code);
  };
  const matchesFilters = (l2: L2) => matchesDrivers(l2, filter) && matchesRef(l2);
  const filtering = !!(filter.bd || filter.src || filter.cd || filter.sys || refActive);
  const view = params.get("view") === "table" ? "table" : "tree";
  /** Change some URL parameters and keep the others (filters, view, selection). */
  const setParam = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    setParams(next);
  };

  const l2Score = useMemo(() => new Map(cat.data?.scores.l2.map((s) => [s.code, s]) ?? []), [cat.data]);

  const selectedCode = useMemo(() => {
    const d = cat.data;
    if (!d) return null;
    const p = params.get("l2");
    if (p && d.l2s.some((x) => x.code === p && matchesFilters(x))) return p;
    const l1 = params.get("l1");
    return d.l2s.find((x) => (!l1 || x.l1_code === l1) && matchesFilters(x))?.code ?? null;
  }, [cat.data, params, refL2s, refMissing]);
  const selected = cat.data?.l2s.find((x) => x.code === selectedCode) ?? null;
  const rules = useLoad<L3[]>(
    () => (selectedCode ? api.l3s({ l2: selectedCode }) : Promise.resolve([])),
    [selectedCode],
  );
  const heads = useLoad(
    () => (selectedCode ? api.configHeads("l3", selectedCode + "-") : Promise.resolve({})),
    [selectedCode],
  );

  const q = query.trim().toLowerCase();
  // The search also looks into the rules (id, name, SIEM name, ATT&CK technique, SIEM rule id); they are
  // loaded once, when the first search starts.
  const searching = q.length > 0;
  const allRules = useLoad<L3[] | null>(() => (searching ? api.l3s() : Promise.resolve(null)), [searching]);
  const ruleHits = useMemo(() => {
    const hits = new Map<string, L3[]>();
    if (!q) return hits;
    for (const r of allRules.data ?? []) {
      const text = [r.code, r.name, r.siem_name ?? "", ...r.attack_techniques, ...(r.siem_rule_ids ?? [])].join(" ").toLowerCase();
      if (!text.includes(q) || !ruleMatches(r)) continue;
      hits.set(r.l2_code, [...(hits.get(r.l2_code) ?? []), r]);
    }
    return hits;
  }, [allRules.data, q, ruleKind, refName]);
  const matches = (l2: L2) =>
    (!q || l2.code.toLowerCase().includes(q) || l2.name.toLowerCase().includes(q) || ruleHits.has(l2.code)) &&
    matchesFilters(l2);

  /** Link that sets the reference filter and keeps view, drivers and selection. */
  const refLink: RefLink = (kind, name) => {
    const next = new URLSearchParams(params);
    next.set(REF_KIND_PARAM, kind);
    next.set(REF_PARAM, name);
    return `/usecases?${next}`;
  };
  const clearRef = { [REF_KIND_PARAM]: null, [REF_PARAM]: null };
  const shownRules = rules.data?.filter(ruleMatches) ?? null;
  // Table view with a rule filter lists the matching rules of all L2 use cases.
  const ruleTable = view === "table" && !!ruleKind;
  const allHeads = useLoad(
    () => (ruleTable ? api.configHeads("l3", "") : Promise.resolve({})),
    [ruleTable],
  );
  const tableRules = useMemo(() => {
    if (!ruleTable || !cat.data) return [];
    const l2s = new Map(cat.data.l2s.map((x) => [x.code, x]));
    return (refRules.data ?? []).filter((r) => {
      const l2 = l2s.get(r.l2_code);
      return ruleMatches(r) && !!l2 && matchesDrivers(l2, filter);
    });
  }, [ruleTable, cat.data, refRules.data, refName, params]);

  const refresh = () => {
    void cat.reload();
    void rules.reload();
  };

  const total = cat.data
    ? `${cat.data.l1s.length} L1 · ${cat.data.l2s.length} L2 · ${cat.data.l1s.reduce((a, x) => a + x.l3_count, 0)} ${t("L3 rules")}`
    : "…";

  return (
    <>
      <header className="page-header">
        <div>
          <h1>{t("Use cases")}</h1>
          <div className="subtitle">{total}</div>
        </div>
        {editor && (
          <details className="menu-btn">
            <summary className="btn btn-primary">{t("+ New")}</summary>
            <div className="menu-pop" role="menu">
              {(
                [
                  ["newL1", t("L1 use case")],
                  ["newL2", t("L2 use case")],
                  ["newL3", t("L3 rule")],
                ] as const
              ).map(([d, label]) => (
                <button
                  key={d}
                  type="button"
                  role="menuitem"
                  disabled={d === "newL3" && !selected}
                  title={d === "newL3" && !selected ? t("Select an L2 use case first") : undefined}
                  onClick={(e) => {
                    e.currentTarget.closest("details")?.removeAttribute("open");
                    setDialog(d);
                  }}
                >
                  {label}
                </button>
              ))}
            </div>
          </details>
        )}
      </header>

      <ErrorNote error={cat.error} />

      <section className="card uc-filters" aria-label={t("Filter use cases")}>
        <div className="view-toggle" role="group" aria-label={t("View")}>
          {(["tree", "table"] as const).map((v) => (
            <button
              key={v}
              type="button"
              className={"filter-chip" + (view === v ? " active" : "")}
              aria-pressed={view === v}
              onClick={() => setParam({ view: v === "tree" ? null : v })}
            >
              {v === "tree" ? t("Tree") : t("Table")}
            </button>
          ))}
        </div>
        <span className="grow" />
        <details className="uc-filter-more" open={filtering || undefined}>
          <summary className="btn btn-sm">
            {t("Filters")}
            {[filter.bd, filter.src, filter.cd, filter.sys].filter(Boolean).length > 0 ? ` (${[filter.bd, filter.src, filter.cd, filter.sys].filter(Boolean).length})` : ""}
          </summary>
          <div className="uc-filter-fields">
            <SelectSearch
              label={t("Business driver")}
              allLabel={t("All business drivers")}
              value={filter.bd}
              onChange={(v) => setParam({ bd: v || null, l2: null })}
              options={(cat.data?.drivers ?? []).map((d) => ({ value: d.code, label: `${d.code} · ${d.name}` }))}
            />
            <SelectSearch
              label={t("Compliance source")}
              allLabel={t("All compliance sources")}
              value={filter.src}
              onChange={(v) => setParam({ src: v || null, cd: null, l2: null })}
              options={(cat.data?.sources ?? []).map((x) => ({ value: String(x.id), label: x.name }))}
            />
            <SelectSearch
              label={t("Compliance driver")}
              allLabel={t("All compliance drivers")}
              value={filter.cd}
              onChange={(v) => setParam({ cd: v || null, l2: null })}
              options={(cat.data?.sources ?? [])
                .filter((x) => !filter.src || String(x.id) === filter.src)
                .flatMap((x) =>
                  x.drivers.map((c) => ({ value: String(c.id), label: c.ref + (c.name ? ` · ${c.name}` : ""), group: x.name })),
                )}
            />
            <SelectSearch
              label={t("System")}
              allLabel={t("All systems")}
              value={filter.sys}
              onChange={(v) => setParam({ sys: v || null, l2: null })}
              options={(cat.data?.systems ?? []).map((x) => ({
                value: String(x.id),
                label: x.name + (x.archived ? ` (${t("archived")})` : ""),
              }))}
            />
          </div>
        </details>
        {refActive && (
          <span className="ref-filter-chip">
            <span>
              {refKind ? REF_KIND_ONE[refKind] : t("Reference")}: <strong>{refName || "–"}</strong>
            </span>
            <button
              type="button"
              className="ref-filter-x"
              aria-label={t("Remove filter {name}", { name: refName })}
              onClick={() => setParam(clearRef)}
            >
              ×
            </button>
          </span>
        )}
        {filtering && (
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setParam({ bd: null, src: null, cd: null, sys: null, ...clearRef })}
          >
            {t("Clear filters")}
          </button>
        )}
      </section>

      {refMissing && (
        <div className="note-box ref-missing" role="status">
          <span>{t("This reference entry no longer exists: {name}", { name: refName || "–" })}</span>
          <button type="button" className="btn btn-sm" onClick={() => setParam(clearRef)}>
            {t("Clear filter")}
          </button>
        </div>
      )}

      {ruleTable && cat.data && !refMissing && (
        <section className="stack">
          <ErrorNote error={refRules.error} />
          {tableRules.length > 0 && (
            <RuleTable rules={tableRules} heads={allHeads.data ?? {}} refLink={refLink} />
          )}
          {refRules.data && !tableRules.length && (
            <p className="muted empty-flat">{t("No L3 rule matches the filters.")}</p>
          )}
          <p className="muted small">{t("{n} L3 rules", { n: tableRules.length })}</p>
        </section>
      )}

      {view === "table" && !ruleTable && cat.data && (
        <UseCaseTable
          cat={cat.data}
          visible={matches}
          l2Score={l2Score}
          editor={editor}
          onEditDrivers={setDriversOf}
          onOpen={(code) => setParam({ view: null, l2: code })}
        />
      )}

      {view === "tree" && (
      <div className="split">
        <section className="card tree" aria-label={t("Use case tree")}>
          <label className="sr-only" htmlFor="uc-search">
            {t("Search use cases")}
          </label>
          <input
            id="uc-search"
            className="input input-sm"
            placeholder={t("Search use cases, rules, ATT&CK IDs")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          {cat.data?.l1s.map((l1) => {
            const children = cat.data!.l2s.filter((x) => x.l1_code === l1.code && matches(x));
            const l1Hit = !!q && (l1.code.toLowerCase().includes(q) || l1.name.toLowerCase().includes(q));
            if ((q || filtering) && !children.length && !l1Hit) return null;
            const open = q || filtering || !collapsed.has(l1.code);
            return (
              <div key={l1.code} className="tree-group">
                <div className="tree-l1-row">
                <button
                  type="button"
                  className="tree-l1"
                  aria-expanded={!!open}
                  onClick={() =>
                    setCollapsed((c) => {
                      const n = new Set(c);
                      if (n.has(l1.code)) n.delete(l1.code);
                      else n.add(l1.code);
                      return n;
                    })
                  }
                >
                  <span className="caret" aria-hidden="true">
                    {open ? "▾" : "▸"}
                  </span>
                  <span className="code-tag">{l1.code}</span>
                  <span className="grow">{l1.name}</span>
                  <span className="small muted">{l1.applicable ? l1.l2_count : t("n/a")}</span>
                </button>
                {editor && (
                  <button
                    type="button"
                    className="link-btn small tree-edit"
                    aria-label={t("Edit {code}", { code: l1.code })}
                    onClick={() => setEditL1(l1)}
                  >
                    {t("Edit")}
                  </button>
                )}
                </div>
                {open &&
                  children.map((l2) => {
                    const sc = l2Score.get(l2.code);
                    const gap = !sc || sc.scored_rules === 0;
                    const hits = ruleHits.get(l2.code) ?? [];
                    return (
                      <div key={l2.code} className="tree-l2-wrap">
                      <button
                        type="button"
                        className={"tree-l2" + (l2.code === selectedCode ? " active" : "")}
                        aria-current={l2.code === selectedCode ? "true" : undefined}
                        onClick={() => setParam({ l2: l2.code })}
                      >
                        <span className="mono small muted tree-code">{l2.code}</span>
                        <span className="grow">{l2.name}</span>
                        <span className={gap ? "count-gap" : "count"} title={gap ? t("Detection gap") : t("Rules")}>
                          {l2.l3_count}
                        </span>
                      </button>
                      {hits.slice(0, 6).map((r) => (
                        <Link key={r.code} to={`/usecases/l3/${r.code}`} className="tree-rule">
                          <span className="mono small muted">{r.code}</span>
                          <span className="grow">{r.name}</span>
                        </Link>
                      ))}
                      {hits.length > 6 && (
                        <span className="tree-rule muted small">{t("and {n} more rules", { n: hits.length - 6 })}</span>
                      )}
                      </div>
                    );
                  })}
              </div>
            );
          })}
        </section>

        <section className="split-wide stack-lg" aria-labelledby="l2title">
          {cat.data && filtering && !refMissing && !cat.data.l2s.some(matches) && (
            <p className="muted">{t("No L2 use case matches the filters.")}</p>
          )}
          {selected && (
            <L2Header
              l2={selected}
              score={l2Score.get(selected.code)}
              drivers={cat.data?.drivers}
              stride={strideOf(cat.data?.mapping, selected.id)}
              editor={editor}
              onEdit={() => setDialog("editL2")}
              onEditDrivers={() => setDriversOf(selected)}
              onVerify={() => setDialog("verifyL2")}
              refLink={refLink}
            />
          )}
          <ErrorNote error={rules.error} />
          {selected && ruleKind && rules.data && rules.data.length > 0 && (
            <p className="muted small" role="status">
              {t("{a} of {b} rules shown", { a: shownRules!.length, b: rules.data.length })}
            </p>
          )}
          {selected && shownRules && shownRules.length > 0 && (
            <RuleTable rules={shownRules} heads={heads.data ?? {}} refLink={refLink} />
          )}
          {selected && rules.data && rules.data.length === 0 && (
            <div className="empty">
              <GapBadge />
              <h3>{t("No L3 rules yet")}</h3>
              <p>
                {t(
                  "This L2 use case is not scored and counts against framework completeness until at least one operational rule with all three metrics exists.",
                )}
              </p>
              {editor && (
                <button type="button" className="btn btn-primary" onClick={() => setDialog("newL3")}>
                  {t("+ Add first rule")}
                </button>
              )}
            </div>
          )}
          {/* L2 use cases only group rules: no configuration here, rules have it (issue #25) */}
          {selected && <LifecyclePanel key={selected.code} level="l2" code={selected.code} onChanged={refresh} />}
        </section>
      </div>
      )}

      {driversOf && (
        <EditDriversDialog l2={driversOf} onClose={() => setDriversOf(null)} onSaved={refresh} />
      )}
      {selected && dialog === "editL2" && (
        <EditL2Dialog l2={selected} stride={strideOf(cat.data?.mapping, selected.id)} onClose={() => setDialog(null)} onSaved={refresh} />
      )}
      {selected && dialog === "verifyL2" && (
        <VerifyDialog level="l2" code={selected.code} onClose={() => setDialog(null)} onSaved={refresh} />
      )}
      {dialog === "newL2" && cat.data && (
        <NewL2Dialog
          l1s={cat.data.l1s}
          defaultL1={selected?.l1_code}
          onClose={() => setDialog(null)}
          onCreated={(code) => {
            setDialog(null);
            void cat.reload();
            setParam({ view: null, l2: code });
          }}
        />
      )}
      {(dialog === "newL1" || editL1) && cat.data && (
        <L1Dialog
          l1={editL1}
          count={cat.data.l1s.length}
          onClose={() => {
            setDialog(null);
            setEditL1(null);
          }}
          onSaved={refresh}
        />
      )}
      {dialog === "newL3" && selected && (
        <NewL3Dialog
          l2={selected}
          onClose={() => setDialog(null)}
          onCreated={(code) => navigate(`/usecases/l3/${code}`)}
        />
      )}
    </>
  );
}

function L2Header({
  l2,
  score,
  drivers,
  stride,
  editor,
  onEdit,
  onEditDrivers,
  onVerify,
  refLink,
}: {
  l2: L2;
  score?: Scores["l2"][number];
  drivers?: BusinessDriver[];
  stride: Stride[];
  editor: boolean;
  onEdit: () => void;
  onEditDrivers: () => void;
  onVerify: () => void;
  refLink: RefLink;
}) {
  const stats = [
    { label: t("Status"), value: STATUS_LABEL[l2.lifecycle_status] },
    { label: t("Rules (scored)"), value: `${score?.rules ?? l2.l3_count} (${score?.scored_rules ?? 0})` },
    { label: t("Weight"), value: num(score?.weight ?? null) },
    { label: t("Potential"), value: num(score?.potential ?? null) },
    { label: t("Onboarded"), value: fmtDate(l2.onboarded_at) },
    { label: t("Last verified"), value: fmtDate(l2.last_verified_at) },
  ];
  return (
    <div className="card l2-head">
      <div className="l2-head-main">
        <span className="mono small muted">
          {l2.code} · L1 {l2.l1_code}
        </span>
        <h2 id="l2title" className="h-lg">
          {l2.name}
        </h2>
        {l2.description && <Markdown text={l2.description} className="lead" />}
        <div className="chips">
          {l2.actors.map((a) => (
            <Link
              key={a}
              to={refLink("threat_actor", a)}
              className="chip chip-neutral chip-link"
              title={t("Show all L2 use cases with threat actor {name}", { name: a })}
            >
              {a}
            </Link>
          ))}
          {l2.risk_level && (
            <span className="chip chip-neutral">
              {t("Risk")} {l2.risk_level}/5
            </span>
          )}
          {l2.target_implementation !== null && (
            <span className="chip chip-neutral">
              {t("Target impl.")} {pct(l2.target_implementation)}
            </span>
          )}
        </div>
        <div className="driver-block">
          <span className="small muted">{t("STRIDE")}:</span>{" "}
          <span className="chips" style={{ display: "inline-flex" }}>
            {stride.length ? (
              stride.map((c) => (
                <Link key={c} to="/stride-mapping" className="chip chip-info chip-link" title={STRIDE_HINT[c]}>
                  {STRIDE_LABEL[c]}
                </Link>
              ))
            ) : (
              <span className="small muted">{t("Not mapped to any category")}</span>
            )}
          </span>
        </div>
        <L2TestSummaryLine code={l2.code} />
        <DriverBlock business={l2.business_drivers} compliance={l2.compliance_drivers} drivers={drivers} />
        {(l2.systems ?? []).length > 0 && (
          <div className="driver-block">
            <span className="small muted">{t("Needed by systems")}:</span>{" "}
            <span className="chips" style={{ display: "inline-flex" }}>
              {(l2.systems ?? []).map((x) => (
                <Link key={x.id} to={`/systems/${x.id}`} className="chip chip-info chip-link">
                  {x.name}
                  {x.archived ? ` (${t("archived")})` : ""}
                </Link>
              ))}
            </span>
          </div>
        )}
        {editor && (
          <div className="row-actions start">
            <button type="button" className="btn btn-sm" onClick={onEdit}>
              {t("Edit use case")}
            </button>
            <button type="button" className="btn btn-sm" onClick={onEditDrivers}>
              {t("Edit drivers")}
            </button>
            <button type="button" className="btn btn-sm" onClick={onVerify}>
              {t("Verify now")}
            </button>
          </div>
        )}
      </div>
      <dl className="mini-stats">
        {stats.map((s) => (
          <div key={s.label}>
            <dt>{s.label}</dt>
            <dd>{s.value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function UseCaseTable({
  cat,
  visible,
  l2Score,
  editor,
  onEditDrivers,
  onOpen,
}: {
  cat: Catalogue;
  visible: (l2: L2) => boolean;
  l2Score: Map<string, Scores["l2"][number]>;
  editor: boolean;
  onEditDrivers: (l2: L2) => void;
  onOpen: (code: string) => void;
}) {
  const shown = cat.l2s.filter(visible);
  // in the order of the table (L1 by L1), so "show more" continues where the list stopped
  const ordered = cat.l1s.flatMap((l1) => shown.filter((x) => x.l1_code === l1.code));
  const page = useShowMore(ordered, 25);
  const onPage = new Set(page.shown.map((x) => x.code));
  return (
    <section className="card table-card" aria-label={t("Use case table")}>
      <div className="scroll-x">
        <table className="table">
          <thead>
            <tr>
              <th>{t("L2 use case")}</th>
              <th>{t("Status")}</th>
              <th className="num">{t("Rules")}</th>
              <th className="num">{t("Weight")}</th>
              <th>{t("Business drivers")}</th>
              <th>{t("Compliance drivers")}</th>
              {editor && <th className="num">{t("Actions")}</th>}
            </tr>
          </thead>
          <tbody>
            {cat.l1s.map((l1) => {
              const rows = shown.filter((x) => x.l1_code === l1.code && onPage.has(x.code));
              if (!rows.length) return null;
              return [
                <tr key={l1.code} className="l1-row">
                  <td colSpan={4}>
                    <span className="code-tag">{l1.code}</span> {l1.name}
                  </td>
                  <td title={t("Inherited from its L2 use cases")}>
                    <BusinessChips codes={l1.business_drivers} drivers={cat.drivers} />
                  </td>
                  <td title={t("Inherited from its L2 use cases")}>
                    <ComplianceChips items={l1.compliance_drivers} />
                  </td>
                  {editor && <td />}
                </tr>,
                ...rows.map((l2) => {
                  const sc = l2Score.get(l2.code);
                  return (
                    <tr key={l2.code}>
                      <td>
                        <button type="button" className="link-btn rule-link" onClick={() => onOpen(l2.code)}>
                          <span className="mono small muted">{l2.code}</span>
                          <span className="strong-500">{l2.name}</span>
                        </button>
                      </td>
                      <td>
                        <StatusPill status={l2.lifecycle_status} />
                      </td>
                      <td className="num">{l2.l3_count}</td>
                      <td className="num strong">
                        {sc?.weight != null ? num(sc.weight) : <GapBadge>{t("gap")}</GapBadge>}
                      </td>
                      <td>
                        <BusinessChips codes={l2.business_drivers} drivers={cat.drivers} />
                      </td>
                      <td>
                        <ComplianceChips items={l2.compliance_drivers} />
                      </td>
                      {editor && (
                        <td className="num">
                          <button type="button" className="btn btn-sm" onClick={() => onEditDrivers(l2)}>
                            {t("Edit drivers")}
                          </button>
                        </td>
                      )}
                    </tr>
                  );
                }),
              ];
            })}
          </tbody>
        </table>
      </div>
      <ShowMore {...page} />
      {!shown.length && <p className="muted empty-flat">{t("No L2 use case matches the filters.")}</p>}
      <p className="muted small" style={{ padding: "0 16px 12px" }}>
        {t("{n} L2 use cases. L3 rules and L1 use cases inherit the drivers of their L2.", { n: shown.length })}
      </p>
    </section>
  );
}

function RuleTable({
  rules,
  heads,
  refLink,
}: {
  rules: L3[];
  heads: Record<string, ConfigCommit>;
  refLink: RefLink;
}) {
  return (
    <div className="card table-card">
      <table className="table">
        <thead>
          <tr>
            <th>{t("Rule")}</th>
            <th>{t("Status")}</th>
            <th className="num" title={t("Effectiveness / Implementation / Coverage")}>
              {t("Eff / Impl / Cov")}
            </th>
            <th className="num">{t("Weight")}</th>
            <th>{t("Data sources")}</th>
            <th>{t("Last verified")}</th>
            <th>{t("Config")}</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.code}>
              <td>
                <Link to={`/usecases/l3/${r.code}`} className="rule-link">
                  <span className="mono small muted">
                    {r.code}
                    {r.attack_techniques.length > 0 && ` · ${r.attack_techniques.join(", ")}`}
                  </span>
                  <span className="strong-500">{r.name}</span>
                </Link>
              </td>
              <td>
                <StatusPill status={r.lifecycle_status} />
              </td>
              <td className="num metric-trio">
                {pct(r.effectiveness)}
                <span className="sep" aria-hidden="true">/</span>
                {pct(r.implementation)}
                <span className="sep" aria-hidden="true">/</span>
                {pct(r.coverage)}
              </td>
              <td className="num strong">
                {r.assessed ? num(r.weight) : <span className="muted">{t("not assessed")}</span>}
              </td>
              <td>
                <Chips
                  items={r.log_sources}
                  href={(s) => refLink("log_source", s)}
                  title={(s) => t("Show all rules with log source {name}", { name: s })}
                />
              </td>
              <td>
                <VerifiedCell rule={r} />
              </td>
              <td className="mono small">
                {heads[r.code] ? (
                  <span title={heads[r.code].message}>
                    r{heads[r.code].rev}
                    {heads[r.code].tags.length > 0 && (
                      <span className="muted"> · {heads[r.code].tags[heads[r.code].tags.length - 1].name}</span>
                    )}
                  </span>
                ) : (
                  <span className="muted">–</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function VerifiedCell({ rule }: { rule: L3 }) {
  const scoredState = rule.lifecycle_status === "operational" || rule.lifecycle_status === "maintenance";
  const issues = rule.issues_at ? (
    <span className="badge-gap" title={t("The last check on {date} found issues", { date: fmtDate(rule.issues_at) })}>
      {t("Issues")}
    </span>
  ) : null;
  if (!rule.last_verified_at)
    return scoredState ? (
      <span className="chips">
        <span className="badge-gap">{t("Never")}</span>
        {issues}
      </span>
    ) : (
      (issues ?? <span className="muted">–</span>)
    );
  return (
    <span className="chips">
      <span
        className={rule.verification_overdue ? "badge-gap" : ""}
        title={t("Due {date}", { date: fmtDate(rule.verification_due) })}
      >
        {fmtDate(rule.last_verified_at)}
        {rule.verification_overdue && t(" · overdue")}
      </span>
      {issues}
    </span>
  );
}

// ------------------------------------------------------------------ dialogs

function EditL2Dialog({ l2, stride, onClose, onSaved }: { l2: L2; stride: Stride[]; onClose: () => void; onSaved: () => void }) {
  const lists = useLoad(async () => {
    const [actors, drivers, compliance] = await Promise.all([
      api.refs("threat_actor"),
      api.drivers(),
      api.compliance(),
    ]);
    return { actors, drivers, compliance };
  });
  const [form, setForm] = useState({
    name: l2.name,
    description: l2.description,
    risk_level: l2.risk_level?.toString() ?? "",
    target_implementation: l2.target_implementation === null ? "" : Math.round(l2.target_implementation * 100) + "",
    onboarded_at: l2.onboarded_at ?? "",
    actors: l2.actors,
    business_drivers: l2.business_drivers,
    compliance_driver_ids: l2.compliance_driver_ids.map(String),
  });
  const [cats, setCats] = useState<Stride[]>(stride);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const admin = useAuth().can("admin");
  const set = (patch: Partial<typeof form>) => setForm((f) => ({ ...f, ...patch }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.updateL2(l2.code, {
        name: form.name,
        description: form.description,
        risk_level: form.risk_level ? Number(form.risk_level) : null,
        target_implementation: form.target_implementation === "" ? null : Number(form.target_implementation) / 100,
        onboarded_at: form.onboarded_at || null,
        actors: form.actors,
        business_drivers: form.business_drivers,
        compliance_driver_ids: form.compliance_driver_ids.map(Number),
        expected_updated_at: l2.updated_at,
      });
      // the mapping belongs to the admin; set only the categories that changed
      if (admin && (cats.length !== stride.length || cats.some((c) => !stride.includes(c)))) {
        const fresh = await api.strideMapping();
        for (const c of STRIDE) {
          if (cats.includes(c) === stride.includes(c)) continue;
          const ids = fresh.categories.find((x) => x.category === c)?.l2s.map((x) => x.l2_id) ?? [];
          await api.setStrideMapping(c, cats.includes(c) ? [...ids, l2.id] : ids.filter((i) => i !== l2.id));
        }
      }
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    const ok = await confirmDialog(
      t("Delete the use case {code}? Its verifications, status changes and configuration history are deleted with it. This cannot be undone.", {
        code: l2.code,
      }),
      { title: t("Delete use case"), confirmLabel: t("Delete"), danger: true },
    );
    if (!ok) return;
    setBusy(true);
    try {
      try {
        await api.deleteL2(l2.code);
      } catch (err) {
        const systems = err instanceof ApiError && err.status === 409 ? (err.data as { systems?: string[] })?.systems : null;
        if (!systems?.length) throw err;
        const sure = await confirmDialog(
          t("{code} is linked to {n} systems through their interviews. Deleting it removes these links, and their coverage changes.", {
            code: l2.code,
            n: systems.length,
          }),
          {
            title: t("Use case is linked to systems"),
            confirmLabel: t("Delete and remove links"),
            danger: true,
            body: (
              <ul className="confirm-list">
                {systems.map((x) => (
                  <li key={x}>{x}</li>
                ))}
              </ul>
            ),
          },
        );
        if (!sure) return;
        await api.deleteL2(l2.code, true);
      }
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const d = lists.data;
  return (
    <Modal title={t("Edit {code}", { code: l2.code })} open onClose={onClose} wide>
      <form className="stack" onSubmit={submit}>
        <ErrorNote error={error ?? lists.error} />
        <label className="field">
          {t("Name")}
          <input className="input" required value={form.name} onChange={(e) => set({ name: e.target.value })} />
        </label>
        <MarkdownField
          label={t("Description")}
          value={form.description}
          onChange={(v) => set({ description: v })}
        />
        <div className="form-grid">
          <label className="field">
            {t("Risk level (1–5)")}
            <select className="input" value={form.risk_level} onChange={(e) => set({ risk_level: e.target.value })}>
              <option value="">{t("Not set")}</option>
              {[1, 2, 3, 4, 5].map((n) => (
                <option key={n}>{n}</option>
              ))}
            </select>
          </label>
          <label className="field">
            {t("Target implementation (%)")}
            <input
              className="input"
              type="number"
              min={0}
              max={100}
              value={form.target_implementation}
              onChange={(e) => set({ target_implementation: e.target.value })}
            />
          </label>
          <label className="field">
            {t("Onboarded on")}
            <input
              className="input"
              type="date"
              value={form.onboarded_at}
              onChange={(e) => set({ onboarded_at: e.target.value })}
            />
          </label>
        </div>
        {d && (
          <div className="form-grid">
            <MultiSelect
              label={t("Threat actors")}
              options={d.actors.map((a) => ({ value: a.name, label: a.name }))}
              value={form.actors}
              onChange={(v) => set({ actors: v })}
            />
            <DriverPickers
              drivers={d.drivers}
              sources={d.compliance}
              business={form.business_drivers}
              compliance={form.compliance_driver_ids}
              onChange={set}
            />
          </div>
        )}
        <fieldset className="fieldset stride-pick">
          <legend>{t("STRIDE categories")}</legend>
          <div className="stride-pick-list">
            {STRIDE.map((c) => (
              <label key={c} className="check" title={STRIDE_HINT[c]}>
                <input
                  type="checkbox"
                  disabled={!admin}
                  checked={cats.includes(c)}
                  onChange={(e) => setCats(e.target.checked ? [...cats, c] : cats.filter((x) => x !== c))}
                />{" "}
                {STRIDE_LABEL[c]}
              </label>
            ))}
          </div>
          <span className="small muted">
            {admin
              ? t("Interviews propose this use case for the checked threats. One use case can belong to several categories.")
              : t("Only admins can change the STRIDE mapping.")}
          </span>
        </fieldset>
        <div className="row-actions">
          {admin && (
            <button
              type="button"
              className="btn btn-danger push-left"
              disabled={busy || l2.l3_count > 0}
              title={l2.l3_count > 0 ? t("Delete or move its L3 rules first") : undefined}
              onClick={() => void remove()}
            >
              {t("Delete use case")}
            </button>
          )}
          <button type="button" className="btn" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {t("Save")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Create or edit an L1 use case (a threat category). "Applicable" decides whether it counts. */
function L1Dialog({
  l1,
  count,
  onClose,
  onSaved,
}: {
  l1: L1 | null;
  count: number;
  onClose: () => void;
  onSaved: () => void;
}) {
  const admin = useAuth().can("admin");
  const [form, setForm] = useState({
    code: l1?.code ?? "",
    name: l1?.name ?? "",
    threat_category: l1?.threat_category ?? "",
    purpose: l1?.purpose ?? "",
    stakeholders: l1?.stakeholders ?? "",
    description: l1?.description ?? "",
    applicable: l1?.applicable ?? true,
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (patch: Partial<typeof form>) => setForm((f) => ({ ...f, ...patch }));

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    const { code, ...rest } = form;
    void run(() => (l1 ? api.updateL1(l1.code, rest) : api.createL1({ code, ...rest, sort_order: (count + 1) * 10 })));
  }

  async function remove() {
    if (!l1) return;
    const ok = await confirmDialog(t("Delete the L1 use case {code}? This cannot be undone.", { code: l1.code }), {
      title: t("Delete L1 use case"),
      confirmLabel: t("Delete"),
      danger: true,
    });
    if (ok) void run(() => api.deleteL1(l1.code));
  }

  return (
    <Modal title={l1 ? t("Edit {code}", { code: l1.code }) : t("New L1 use case")} open onClose={onClose} wide>
      <form className="stack" onSubmit={submit}>
        <ErrorNote error={error} />
        <div className="form-grid">
          {!l1 && (
            <label className="field">
              {t("Identifier (two letters)")}
              <input
                className="input mono"
                required
                pattern="[A-Z]{2}"
                maxLength={2}
                placeholder="XX"
                value={form.code}
                onChange={(e) => set({ code: e.target.value.toUpperCase() })}
              />
            </label>
          )}
          <label className="field">
            {t("Name")}
            <input className="input" required maxLength={255} value={form.name} onChange={(e) => set({ name: e.target.value })} />
          </label>
          <label className="field">
            {t("Threat category")}
            <input
              className="input"
              maxLength={255}
              value={form.threat_category}
              onChange={(e) => set({ threat_category: e.target.value })}
            />
          </label>
        </div>
        <label className="check">
          <input type="checkbox" checked={form.applicable} onChange={(e) => set({ applicable: e.target.checked })} />
          {t("Applicable to this organisation")}
        </label>
        {!form.applicable && (
          <p className="form-notice">
            {t("A use case that is not applicable is left out of every score, with all its L2 use cases and rules.")}
          </p>
        )}
        <label className="field">
          {t("Purpose")}
          <textarea className="input textarea" rows={2} value={form.purpose} onChange={(e) => set({ purpose: e.target.value })} />
        </label>
        <label className="field">
          {t("Stakeholders")}
          <input className="input" value={form.stakeholders} onChange={(e) => set({ stakeholders: e.target.value })} />
        </label>
        <MarkdownField
          label={t("Description")}
          value={form.description}
          onChange={(v) => set({ description: v })}
        />
        <div className="row-actions">
          {l1 && admin && (
            <button
              type="button"
              className="btn btn-danger push-left"
              disabled={busy || l1.l2_count > 0}
              title={l1.l2_count > 0 ? t("Delete or move its L2 use cases first") : undefined}
              onClick={() => void remove()}
            >
              {t("Delete")}
            </button>
          )}
          <button type="button" className="btn" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? t("Saving…") : t("Save")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

export function VerifyDialog({
  level,
  code,
  onClose,
  onSaved,
}: {
  level: "l2" | "l3";
  code: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [result, setResult] = useState<"ok" | "issues">("ok");
  const [note, setNote] = useState("");
  const [when, setWhen] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.verify(level, code, { result, note, ...(when ? { verified_at: when } : {}) });
      onSaved();
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={t("Verify {code}", { code })} open onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <p className="muted small" style={{ margin: 0 }}>
          {t("Record that the detection was tested, for example with a purple team exercise or replayed logs.")}
        </p>
        <ErrorNote error={error} />
        <fieldset className="radio-row">
          <legend>{t("Result")}</legend>
          <label>
            <input type="radio" checked={result === "ok"} onChange={() => setResult("ok")} /> {t("Works as expected")}
          </label>
          <label>
            <input type="radio" checked={result === "issues"} onChange={() => setResult("issues")} />{" "}
            {t("Issues found")}
          </label>
        </fieldset>
        <label className="field">
          {t("Note")}
          <textarea className="input textarea" rows={3} value={note} onChange={(e) => setNote(e.target.value)} />
        </label>
        <label className="field">
          {t("Date (leave empty for today)")}
          <input className="input" type="date" value={when} onChange={(e) => setWhen(e.target.value)} />
        </label>
        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {t("Save verification")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function NewL2Dialog({
  l1s,
  defaultL1,
  onClose,
  onCreated,
}: {
  l1s: L1[];
  defaultL1?: string;
  onClose: () => void;
  onCreated: (code: string) => void;
}) {
  const [l1, setL1] = useState(defaultL1 ?? l1s[0]?.code ?? "");
  const [suffix, setSuffix] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      const code = `${l1}-${suffix.toUpperCase()}`;
      await api.createL2({ code, name });
      onCreated(code);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <Modal title={t("New L2 use case")} open onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <ErrorNote error={error} />
        <div className="form-grid">
          <label className="field">
            {t("L1 use case")}
            <select className="input" value={l1} onChange={(e) => setL1(e.target.value)}>
              {l1s.map((x) => (
                <option key={x.code} value={x.code}>
                  {x.code} {x.name}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            {t("ID suffix (3 letters or digits)")}
            <input
              className="input mono"
              required
              pattern="[A-Za-z0-9]{3}"
              maxLength={3}
              value={suffix}
              onChange={(e) => setSuffix(e.target.value)}
              placeholder={t("e.g. LAT")}
            />
          </label>
        </div>
        <label className="field">
          {t("Name")}
          <input className="input" required value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button type="submit" className="btn btn-primary">
            {t("Create")} {l1}-{suffix.toUpperCase() || "___"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function NewL3Dialog({ l2, onClose, onCreated }: { l2: L2; onClose: () => void; onCreated: (code: string) => void }) {
  const next = useLoad(() => api.nextL3Code(l2.code), [l2.code]);
  const [code, setCode] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [onboarded, setOnboarded] = useState(today()); // issue #27: defaults to today
  const [error, setError] = useState<string | null>(null);
  const value = code ?? next.data?.code ?? "";

  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      await api.createL3({ code: value, name, lifecycle_status: "onboarding", onboarded_at: onboarded || null });
      onCreated(value);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <Modal title={t("New rule in {code}", { code: l2.code })} open onClose={onClose}>
      <form className="stack" onSubmit={submit}>
        <ErrorNote error={error ?? next.error} />
        <label className="field">
          {t("Rule ID")}
          <input
            className="input mono"
            required
            value={value}
            pattern="[A-Za-z]{2}-[A-Za-z0-9]{3}-([A-Za-z0-9]+-)*[0-9]{2,3}"
            maxLength={64}
            aria-describedby="l3-code-hint"
            onChange={(e) => setCode(e.target.value.toUpperCase())}
          />
          <span id="l3-code-hint" className="small muted" style={{ fontWeight: 400 }}>
            {t("Format {a}; extra identifiers may go before the number, e.g. {b}.", {
              a: `${l2.code}-NN`,
              b: `${l2.code}-WIN-AD-01`,
            })}
          </span>
        </label>
        <label className="field">
          {t("Name")}
          <input
            className="input"
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("e.g. Detect credential dumping attempt")}
          />
        </label>
        <label className="field">
          {t("Onboarded on")}
          <input
            type="date"
            className="input"
            value={onboarded}
            max={today()}
            onChange={(e) => setOnboarded(e.target.value)}
          />
        </label>
        <p className="muted small" style={{ margin: 0 }}>
          {t("The rule starts in onboarding. Set metrics, data sources and status on the next page.")}
        </p>
        <div className="row-actions">
          <button type="button" className="btn" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button type="submit" className="btn btn-primary" disabled={!value}>
            {t("Create rule")}
          </button>
        </div>
      </form>
    </Modal>
  );
}
