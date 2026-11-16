# Root-Cause Clustering Design

## 1. Design Constraints

1. **Metadata-only inference.** Clustering reads only `metadata.json` (`corpus`,
   `reason`, `frames`, `coverage`, `occurrences`, `input`, `symptom` headline for
   reporting). It never re-executes testcases or scrapes raw artifact files.
2. **Soft crash-reason prior (cross-reason merging).** The same underlying bug
   can surface under different `reason` strings across fuzzer builds (for
   example, `SEGV` under `afl-ijon` vs. `use-of-uninitialized-value` under
   `msan`, or `undefined-behavior` vs. post-parse invariant `ABRT`). Therefore
   `reason` must be a bounded soft feature, never a hard partition.
3. **Single-bug and short-campaign invariance.** As bugs are fixed, short
   fuzzing runs often produce only one underlying bug splintered across several
   minimal buckets (e.g., an invariant check triggered on 2–30 different AST
   node types or an integer overflow reached from different callers). Clustering
   must use a fixed calibrated similarity threshold `T` rather than relative
   elbow/eigengap selection that forces multiple clusters when `k_true = 1`.
4. **Generalization across independent campaigns.** Every normalization,
   boilerplate filter, and threshold is jointly validated across two
   independent 58-bucket calibration runs (`tmp/fuzz/triage.run1/metadata.json`,
   17,247 occurrences, and `tmp/fuzz/triage.run2/metadata.json`, 18,344
   occurrences), verified out-of-sample on a third 56-bucket campaign
   (`tmp/fuzz/triage/metadata.json`, 17,621 occurrences), plus 1-, 2-, and
   3-bug subsamples.

## 2. Ground Truth Across Calibration & Validation Campaigns

Three fuzz campaigns of 10 minutes duration were run. Triage directories from these
runs was used to calibrate the clustering algorithm.

All three campaigns share the same reference corpus (`corpus_count = 541`,
`edge_df = 5109` active corpus edges, `edge_functions = 10423` symbol-mapped
edges) and exhibit the same 6 distinct root causes across 56–58 reproducible buckets:

| Bug | Signature / Signal | Run 1 | Run 2 | Run 3 |
| --- | --- | ---: | ---: | ---: |
| `HeredocEOF` (`pm_parser_err_heredoc_term`) | Edge `9441` hit across 25–34 AST/diagnostic invariants (`ABRT`, `kind=length_underflow`) | 34 (13,962) | 32 (12,739) | 26 (14,053) |
| `AssocNot` (`PM_ASSOC_NODE` / `parse_not`) | `ABRT/baebb56b3435c50c` (`"{not "`) | 1 (2,239) | 1 (4,456) | 1 (2,403) |
| `InterpSym` (`PM_INTERPOLATED_SYMBOL_NODE`) | `ABRT/c2f3671322ccc501` (`"%I \#{}\#{"`) | 1 (682) | 1 (478) | 1 (723) |
| `GlobalVar` (`invalid_variable_global*`) | `ABRT/e5cdede64a528f8c` + `ABRT/800e2d77ff495ce3` | 2 (36) | 2 (71) | 2 (32) |
| `UB_indent` (`parser_warn_indentation_mismatch`) | `undefined-behavior` at `src/prism.c:15213` | 16 (255) | 16 (472) | 20 (293) |
| `UB_linecol` (`pm_line_offset_list_line_column`) | `undefined-behavior` at `src/line_offset_list.c:85,96` | 4 (73) | 6 (128) | 6 (117) |

Notably, `ABRT` post-parse invariant checks abort inside `fuzz_invariant_fail`
after `pm_parse` returns, so their `frames` contain only `harness`/`external`
frames and generated AST visitors (`pm_visit_node`, `pm_visit_child_nodes`).
Their root cause must therefore be separated primarily via coverage edges.

## 3. Feature Extraction

### 3.1 Coverage Edges: Weighted Jaccard with Laplace-Smoothed IDF

Let $N = \text{corpus\_count}$ and let $\text{df}(e)$ be the number of corpus
inputs executing edge $e$. With Laplace pseudo-count smoothing `IDF_SMOOTHING`
($s = 5.0$):

$$\text{idf}(e) = \ln \frac{N + s}{\text{df}(e) + s}$$

Each mapped edge $e$ with $\text{idf}(e) > 0$ receives weight
$w_e = m(\text{fn}(e)) \cdot \text{idf}(e)$, where $m(\text{fn}(e))$ is the
function-role multiplier from Section 3.2. To represent linear Jaccard mass
inside a sparse Euclidean vector dot product, we store $v_e = \sqrt{w_e}$
(and $v_e = \sqrt{\text{idf}(e)}$ in the `unmapped_fallback` path when
`edge_functions` is empty). Coverage similarity between buckets $a$ and $b$
is **Weighted Jaccard (Tanimoto)** over the active edge weights:

$$S_{\text{cov}}(a, b) = \frac{v_a \cdot v_b}{\|v_a\|^2 + \|v_b\|^2 - v_a \cdot v_b} = \frac{\sum_{e \in A \cap B} w_e}{\sum_{e \in A \cup B} w_e}$$

Why Weighted Jaccard with $v_e = \sqrt{w_e}$ instead of the earlier $1/\sqrt{k_f}$
cosine-overlap geometric mean:

1. **No $1/\sqrt{k_f}$ penalty against multi-edge parser functions.** Dividing by
   $\sqrt{k_f}$ (number of hit edges in function $f$) crushed multi-branch
   state machines like `parser_lex` and `parse_heredoc` relative to single-edge
   helpers.
2. **Linear IDF rather than $\text{IDF}^2$.** Storing $v_e = \text{idf}(e)$ and
   taking a dot product squared $\text{idf}(e)$ ($\text{IDF}^2 \approx 67\times$
   skew between $\text{df}=0$ and $\text{df}=250$), allowing single incidental
   $\text{df}=0$ edges to dominate. With $v_e = \sqrt{w_e}$, edge mass in both
   the numerator and denominator is linear in $\text{idf}(e)$.
3. **Laplace smoothing $s = 5.0$.** Prevents small $\text{df}=0 \to 1$ corpus
   fluctuations from creating unstable spikes ($\ln(546/5) \approx 4.69$ vs.
   $\ln(546/6) \approx 4.51$).
4. **Penalizing unmatched extra execution paths (`Tanimoto` vs. `Cosine` /
   `overlap`).** Small error-recovery inputs whose path is nearly a subset of a
   larger compound input (e.g., `AssocNot/baeb` at 144 mapped edges vs.
   `HeredocEOF` inside `{ ... }` such as `b39b` or `5cd2` at 259–280 edges)
   had inflated `sqrt(cosine * overlap)` (`b39b~baeb = 0.5220` in Run 2 baseline,
   causing a premature merge). Weighted Jaccard puts unmatched edges in the
   denominator in full, dropping `b39b~baeb` to `0.272201`, safely below
   `2551~b39b = 0.309399` and `cluster-01` internal linkage.

### 3.2 Function-Role Multipliers

`function_weight_multiplier` assigns $m(\text{fn})$ cleanly from role membership and corpus edge count $C(\text{fn})$:

- **`BOILERPLATE_FUNCTIONS` and `BOILERPLATE_PREFIXES` ($m = 0.0$):** Fuzz harness
  drivers, invariant checkers, and generated visitors (`fuzz_*`, `check_*`,
  `pm_visit_*`, plus explicit harness/string helpers such as `harness_parse`,
  `harness`, `LLVMFuzzerTestOneInput`, `pm_token_str`, `context_human`, and
  `VISITOR_FUNCTIONS`). Prefix matching ensures newer harness checks such as
  `fuzz_check_error_diag` or `fuzz_span_violation_kind` are filtered
  automatically without stale allowlists.
- **`SETUP_FUNCTIONS` ($m = 0.0$):** Pre-parse option initialization and
  encoding-name lookup (`pm_parser_init`, `pm_parser_init_shebang`,
  `pm_encoding_find`, `pm_strncasecmp`). The 4-byte fuzzer option header selects
  encodings rarely present in the seed corpus (such as `ASCII-8BIT`), so
  unrelated crashes sharing that fuzz option hit the same $\text{df} \le 1$ init
  edges (`2551~e5cd` in Run 2 reached `0.4199` under baseline; excluding setup
  edges drops `2551~e5cd` to `0.179404`).
- **`ENCODING_HELPER_FUNCTIONS` ($m = 0.25$):** Per-character encoding helpers
  invoked throughout lexing (`pm_encoding_char_width`,
  `pm_encoding_cesu_8_char_width`, `pm_encoding_utf_8_char_width`,
  `pm_encoding_property_char`). Damping to `0.25` prevents rare non-UTF-8
  encoding flags from aliasing unrelated bugs while keeping signal if an actual
  parser bug involves encoding width dispatch.
- **`RECOVERY_FUNCTIONS` ($m = 0.10$):** Generic error-recovery helpers shared
  across unrelated syntax-error crashes (`context_recoverable`,
  `pm_error_recovery_node_new`, `pm_error_recovery_node_create`,
  `pm_error_recovery_node_create_unexpected`, `pm_parse_err_is_fatal`,
  `pm_diagnostic_list_append`).
- **Base weight for all other Prism functions:** $m_{\text{base}} = 1.0$.
- **Dispatcher damping & function edge cap:** High-fanout parser/lexer dispatch
  loops (`DISPATCHER_FUNCTIONS`: `parser_lex`, `parse_expression`, `pm_parse`)
  are further scaled by `DISPATCHER_WEIGHT = 0.5`, and any function with
  $C(\text{fn}) > \text{FUNCTION\_EDGE\_CAP} = 150.0$ mapped corpus edges is
  scaled by $\sqrt{150.0 / C(\text{fn})}$. Unlike per-bucket $1/\sqrt{k_f}$
  normalization, corpus-level square-root scaling prevents monolithic dispatch
  loops from overwhelming small targeted bug functions while keeping bucket
  feature weights corpus-consistent.

### 3.3 Call Stack Frames

`extract_frame_vector` keeps only frames with `scope == "prism"`, non-empty
`func`, and `!boilerplate_function?(func)` (excluding all `VISITOR_FUNCTIONS`,
`pm_visit_*`, `fuzz_*`, and `check_*` frames). Frames are indexed from the
crashing leaf ($d = 0$) as `func@file` (omitting line numbers so multi-site
overflows in the same leaf helper, e.g., `src/line_offset_list.c:85` and `:96`,
align at $d = 0$) with geometric decay $\text{FRAME\_DECAY}^d = 0.5^d$.
Non-empty frame vectors are compared via cosine similarity:

$$S_{\text{frame}}(a, b) = \frac{f_a \cdot f_b}{\|f_a\| \, \|f_b\|}$$

## 4. Oracle Separation, Pairwise Evidence & Reason Weight

Before computing pairwise similarity, `oracle_family` partitions buckets by
verification oracle (`verify_profile` or `symptom.invariant.namespace`):

- `"diff_parse_y"` (`diff_parse_y` parser/CRuby parity checks),
- `"stream_diff"` (`msan_slow` / `stream_diff` streaming parity checks),
- `"crash_or_inv"` (crash sanitizers and post-parse AST/location invariants).

Buckets from different oracle families receive `similarity = 0.0` and are never
merged in `best_upgma_merge` regardless of `threshold`. This preserves soft
cross-reason merging inside `"crash_or_inv"` (e.g., `SEGV` vs. MSan
`use-of-uninitialized-value` or `ABRT`) while preventing shared `ABRT` post-parse
exit scaffolding from mixing sanitizer/invariant bugs with `diff_parse_y` or
`stream_diff` mismatches.

Within compatible oracle families, evidence combines coverage, stack frames, and
structured `diff_parse_y` symptoms using `FRAME_BLEND_WEIGHT` ($\alpha = 0.75$)
and `FRAME_MISMATCH_PENALTY` ($\rho = 0.50$):

$$\text{evidence}(a, b) = \begin{cases}
\alpha\, S_{\text{frame}}(a, b) + (1 - \alpha)\, S_{\text{cov}}(a, b) & \text{if both have Prism frames and coverage} \\
S_{\text{frame}}(a, b) & \text{if both have Prism frames and either lacks coverage} \\
S_{\text{diff}}(S_{\text{cov}}(a, b), a, b) & \text{if neither has Prism frames} \\
\rho\, S_{\text{cov}}(a, b) & \text{if exactly one has Prism frames}
\end{cases}$$

When neither bucket has Prism frames and both carry `diff_parse_y` structured
fields (`symptom.invariant.fields`), `diff_symptom_similarity` applies a
conflict-aware adjustment:

- If non-empty `sub` (`prism_ok_cruby_err`, `prism_err_cruby_ok`, `operator`) or
  `kind` conflicts, evidence is damped by `DIFF_CONFLICT_SCALE = 0.35`.
- Otherwise, across `{prism, cruby, node, scope}` (ignoring `"ok"` diagnostics):
  - if all populated fields agree and at least one agreed value is non-generic
    (i.e., not in `GENERIC_DIFF_ERRORS`: `expect_eol_after_statement`,
    `unexpected_token_ignore`, `unexpected_token_close_context`,
    `regexp_parse_error`, `SyntaxError:other`), evidence is boosted via
    $\min(1.0, (1 - 0.15)\,\text{ev} + 0.15)$ (`DIFF_MATCH_BOOST = 0.15`);
  - if any populated field disagrees, evidence is damped by `0.35`;
  - otherwise `evidence` stays unchanged at $S_{\text{cov}}(a, b)$.

Total similarity adds the soft `reason` indicator $r(a, b) \in \{0, 1\}$ with
`DEFAULT_REASON_WEIGHT` ($w_r = 0.10$):

$$S(a, b) = (1 - w_r)\,\text{evidence}(a, b) + w_r\, r(a, b)$$

### Non-Guesswork Derivation of $w_r = 0.10$

Two explicit inequalities bound $w_r$:

1. **Suppressing unrelated same-reason merges (`reason` alone cannot merge).**
   Across Run 1 and Run 2, the highest inter-cluster average `evidence` between
   distinct bugs of the same `reason` (`HeredocEOF` vs. `AssocNot`) is
   $\approx 0.117$ (`similarity = 0.205095` at $w_r = 0.10$), while unrelated
   `undefined-behavior` bugs (`UB_indent` vs. `UB_linecol`) have
   `evidence` $\approx 0.025$ (`similarity = 0.122145`). To keep unrelated
   same-reason pairs safely below threshold $T = 0.225$:

   $$(1 - w_r)\, s_{\text{noise}} + w_r < T \implies w_r < \frac{T - s_{\text{noise}}}{1 - s_{\text{noise}}}$$

   For $T = 0.225$ and $s_{\text{noise}} = 0.12$, this requires
   $w_r < 0.1193$. Choosing $w_r = 0.10$ keeps same-reason zero-evidence pairs
   at $0.10$ and $s_{\text{noise}} = 0.117$ at $0.205 < 0.225$.

2. **Allowing cross-reason same-bug merges (`r = 0`).**
   When the same bug surfaces under two different fuzzers/reasons (`r = 0`), it
   merges iff:

   $$(1 - w_r)\,\text{evidence}(a, b) \ge T \iff \text{evidence}(a, b) \ge \frac{T}{1 - w_r}$$

   With $w_r = 0.10$ and $T = 0.225$, any pair with $\text{evidence} \ge 0.250$
   merges regardless of `reason`. For instance, two crashes from different
   reasons sharing the same top Prism frame ($S_{\text{frame}} = 1.0$) achieve
   $\text{evidence} \ge 0.75$ and score $\ge 0.675 \gg 0.225$; even sharing only
   common frame structure ($S_{\text{frame}} = 0.40$) or strong shared coverage
   ($S_{\text{cov}} = 0.30$) yields $0.90 \cdot (0.75 \cdot 0.40 + 0.25 \cdot 0.30) = 0.3375 > 0.225$.

## 5. Linkage and Fixed Threshold Calibration

We use **UPGMA** (unweighted pair-group method with arithmetic mean / average
linkage), breaking ties deterministically by canonical cluster bucket ID, and
cut the dendrogram at fixed threshold `DEFAULT_THRESHOLD = 0.225`.

### Calibration Across Runs 1–2 and Validation on Run 3

Evaluated directly by [`FuzzClustering.cluster_metadata`](cluster.rb):

- **Run 1 (`tmp/fuzz/triage.run1/metadata.json`, 58 buckets, 17,247 occ):**
  - Full: **6 pure clusters** (`34, 1, 1, 16, 4, 2`)
  - Last within-bug merge: `0.277123`
  - First cross-bug merge (`max_inter`): `0.198929`
  - Separation interval: `(0.198929, 0.277123]` (width `+0.078194`)
- **Run 2 (`tmp/fuzz/triage.run2/metadata.json`, 58 buckets, 18,344 occ):**
  - Full: **6 pure clusters** (`32, 1, 1, 2, 16, 6`)
  - Last within-bug merge: `0.248938` (`HeredocEOF` cluster absorbing `[2551, b39b]`, which themselves merge at `0.309399`)
  - First cross-bug merge (`max_inter`): `0.205095`
  - Separation interval: `(0.205095, 0.248938]` (width `+0.043843`)
- **Run 3 out-of-sample (`tmp/fuzz/triage/metadata.json`, 56 buckets, 17,621 occ):**
  - Full: **6 pure clusters** (`26, 1, 1, 20, 6, 2`)
  - Last within-bug merge: `0.412921`
  - First cross-bug merge (`max_inter`): `0.198715`
  - Separation interval: `(0.198715, 0.412921]` (width `+0.214206`)
- **Joint calibration interval across Runs 1–2:** `(0.205095, 0.248938]`, exact
  midpoint **`0.227017`**, rounded to **`T = 0.225`** (which also cuts Run 3
  cleanly across its `+0.214206` gap).
- **Reason-restricted & single-bug campaign checks at `T = 0.225`:**
  - `ABRT`-only: `k = 4` pure clusters on Run 1 (`0.198929..0.277123`) and
    Run 2 (`0.205095..0.248938`).
  - `undefined-behavior`-only: `k = 2` pure clusters on Run 1
    (`0.114863..0.625010`) and Run 2 (`0.122145..0.644564`).
  - Random single-bug subsamples (2–12 buckets drawn from multi-bucket bugs):
    **275/275 (100%)** collapse cleanly to 1 cluster on Run 1, **275/275 (100%)**
    on Run 2, and **275/275 (100%)** on Run 3 (**825/825 total**).

### Multi-Oracle 24-Hour Validation (`210` Buckets, `50,139` Occurrences)

After adding prefix boilerplate filtering, dispatcher damping + function edge
cap, `oracle_family` separation, and conflict-aware `diff_parse_y` symptom
scoring at the unchanged threshold `T = 0.225`:

- **Run 1 (`tmp/fuzz/triage.run1/metadata.json`, 58 buckets):** **6 pure
  clusters** (`V-measure = 1.000`, `ARI = 1.000`, `min_merge = 0.239372`,
  `max_inter = 0.186246`).
- **Run 2 (`tmp/fuzz/triage.run2/metadata.json`, 58 buckets):** **6 pure
  clusters** (`V-measure = 1.000`, `ARI = 1.000`, `min_merge = 0.225181`,
  `max_inter = 0.186533`).
- **24-hour multi-oracle campaign (`tmp/fuzz/triage/metadata.json`, 210
  buckets, 50,139 occurrences; 119 labeled buckets):**
  - Baseline (`E0`): `21` clusters, `5` oracle-mixed clusters, `Purity = 0.6975`,
    `Inverse Purity = 0.9412`, `V-measure = 0.8518`, `ARI = 0.7418`.
  - Updated `cluster.rb`: **`47` clusters**, **`0` oracle-mixed clusters**,
    `min_merge = 0.227594`, `max_inter = 0.221973`, **`Purity = 0.9580`**,
    **`Inverse Purity = 0.9412`**, **`V-measure = 0.9659`**, **`ARI = 0.9313`**.

## 6. CLI and Output Format

```bash
ruby test/fuzz/triage/cluster.rb [--metadata PATH] [-o PATH|-] [--threshold FLOAT] [--reason-weight FLOAT] [--include-unreproducible] [--quiet]
```

Each cluster selects a deterministic representative by `(-occurrences, min_size_bytes, bucket_id)` and emits schema v1 JSON to `tmp/fuzz/triage/clusters.json` (or stdout with `-o -`).
