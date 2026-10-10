/*
 * pass_k8s.c — Pipeline pass for Kubernetes manifests, Helm charts and dependency manifests.
 *
 * For each discovered YAML file that is a generic k8s manifest (apiVersion: detected)
 *   → emit one Resource node per file (first document only — multi-document YAML is not yet
 * supported). Kustomizations are not handled here: their entries are IMPORTS of the
 * file itself, resolved by the import resolver (resolve_kustomize_entry).
 *
 * Depends on: pass_infrascan.c (cbm_is_k8s_manifest, cbm_infra_qn),
 *             extraction layer (cbm.h), graph_buffer, pipeline internals.
 */
#include "foundation/constants.h"
#include "pipeline/pipeline.h"
#include <stdint.h>
#include "pipeline/pipeline_internal.h"
#include "graph_buffer/graph_buffer.h"
#include "discover/discover.h"
#include "foundation/log.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/limits.h"
#include "cbm.h"
#include "helpers.h"               /* cbm_kind_in_set_free_cache */
#include "foundation/slab_alloc.h" /* cbm_slab_destroy_thread */
#include "foundation/platform.h"   /* cbm_default_worker_count */
#include "pipeline/worker_pool.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Internal helpers ────────────────────────────────────────────── */

/* Read entire file into heap-allocated buffer. Returns NULL on error.
 * Caller must free(). Sets *out_len to byte count. */
static char *k8s_read_file(const char *path, int *out_len) {
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        return NULL;
    }

    (void)fseek(f, 0, SEEK_END);
    long size = ftell(f);
    (void)fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > cbm_max_file_bytes()) { /* generous, env-configurable cap (B4) */
        (void)fclose(f);
        return NULL;
    }

    /* +pad: tree-sitter lexer lookahead reads past EOF; keep it in-bounds */
    enum { CBM_TS_LOOKAHEAD_PAD = 16 };
    char *buf = cbm_alloc(CBM_MEM_CLASS_OTHER, (size_t)size + CBM_TS_LOOKAHEAD_PAD);
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }

    size_t nread = fread(buf, SKIP_ONE, size, f);
    (void)fclose(f);
    if (nread > (size_t)size) {
        nread = (size_t)size;
    }
    memset(buf + nread, 0, CBM_TS_LOOKAHEAD_PAD);
    *out_len = (int)nread;
    return buf;
}

/* Format int to string for logging. Thread-safe via TLS. */
static const char *itoa_k8s(int val) {
    enum { RING_BUF_COUNT = 4, RING_BUF_MASK = 3 };
    static CBM_TLS char bufs[RING_BUF_COUNT][CBM_SZ_32];
    static CBM_TLS int idx = 0;
    int i = idx;
    idx = (idx + SKIP_ONE) & RING_BUF_MASK;
    snprintf(bufs[i], sizeof(bufs[i]), "%d", val);
    return bufs[i];
}

/* Extract the basename of a path (pointer into the string; no allocation). */
static const char *k8s_basename(const char *path) {
    const char *p = strrchr(path, '/');
    return p ? p + SKIP_ONE : path;
}

/* ── K8s cross-manifest label-selector matching ──────────────────────
 * A Service routes traffic to the Pods whose labels carry EVERY pair of the
 * Service's spec.selector, in the Service's own namespace -- the way k8s
 * resolves Service → Endpoints. Per manifest we record the Resource node, its
 * namespace and the label pairs that take part: a Service's spec.selector, a
 * workload's pod-template labels, a bare Pod's metadata.labels. After all
 * manifests are read, an inverted index from "key=value" to workloads turns
 * each Service into a scan of the workloads carrying its rarest pair rather
 * than of every workload; each match becomes an INFRA_MAPS edge
 * (Service → workload). */
enum { K8S_LABEL_LEN = 128, K8S_GROW_MIN = 64 };

typedef enum {
    K8S_REC_OTHER = 0,
    K8S_REC_SERVICE,  /* pairs = spec.selector */
    K8S_REC_WORKLOAD, /* pairs = pod-template labels */
    K8S_REC_POD,      /* pairs = metadata.labels */
} k8s_rec_kind_t;

typedef struct {
    int64_t node_id;
    char name[K8S_LABEL_LEN];
    char ns[K8S_LABEL_LEN]; /* metadata.namespace; "" when unset */
    k8s_rec_kind_t kind;
    int pair_off; /* this record's pairs: pairs[pair_off .. pair_off + pair_n) */
    int pair_n;
} k8s_record_t;

typedef struct {
    k8s_record_t *items;
    int count;
    int cap;
    char **pairs; /* "key=value", heap-owned */
    int pair_count;
    int pair_cap;
} k8s_record_array_t;

/* Count leading-space indentation of a line (tabs are invalid YAML indent). */
static int k8s_indent(const char *line) {
    int n = 0;
    while (line[n] == ' ') {
        n++;
    }
    return n;
}

/* Split `key: value` (already de-indented). Returns 1 if a key was found; fills
 * key/val (val empty when the key opens a nested block). */
static int k8s_split_kv(const char *t, char *key, size_t key_sz, char *val, size_t val_sz) {
    key[0] = '\0';
    val[0] = '\0';
    if (t[0] == '#' || t[0] == '-' || t[0] == '\0') {
        return 0;
    }
    const char *colon = strchr(t, ':');
    if (!colon) {
        return 0;
    }
    size_t klen = (size_t)(colon - t);
    if (klen == 0 || klen >= key_sz) {
        return 0;
    }
    memcpy(key, t, klen);
    key[klen] = '\0';
    const char *v = colon + 1;
    while (*v == ' ' || *v == '\t') {
        v++;
    }
    size_t vn = 0;
    while (v[vn] && v[vn] != '\r' && v[vn] != '\n' && v[vn] != '#' && vn + 1 < val_sz) {
        val[vn] = v[vn];
        vn++;
    }
    /* trim trailing space */
    while (vn > 0 && (val[vn - 1] == ' ' || val[vn - 1] == '\t')) {
        vn--;
    }
    val[vn] = '\0';
    /* strip surrounding quotes */
    if (vn >= 2 && (val[0] == '"' || val[0] == '\'') && val[vn - 1] == val[0]) {
        memmove(val, val + 1, vn - 2);
        val[vn - 2] = '\0';
    }
    return 1;
}

/* Which label block a leaf `key: value` sits in, by its parent path. */
typedef enum {
    K8S_PAIR_NONE = 0,
    K8S_PAIR_SELECTOR,       /* spec.selector (a Service's selector is a flat map) */
    K8S_PAIR_TEMPLATE_LABEL, /* spec.template.metadata.labels, also under a CronJob's jobTemplate */
    K8S_PAIR_META_LABEL,     /* metadata.labels */
} k8s_pair_block_t;

static k8s_pair_block_t k8s_pair_block(const char *parent_path) {
    if (strcmp(parent_path, "spec.selector") == 0) {
        return K8S_PAIR_SELECTOR;
    }
    if (strcmp(parent_path, "spec.template.metadata.labels") == 0 ||
        strcmp(parent_path, "spec.jobTemplate.spec.template.metadata.labels") == 0) {
        return K8S_PAIR_TEMPLATE_LABEL;
    }
    if (strcmp(parent_path, "metadata.labels") == 0) {
        return K8S_PAIR_META_LABEL;
    }
    return K8S_PAIR_NONE;
}

static k8s_rec_kind_t k8s_rec_kind(const char *kind) {
    static const char *const workloads[] = {
        "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController",
        "Job",        "CronJob",     NULL};
    if (strcmp(kind, "Service") == 0) {
        return K8S_REC_SERVICE;
    }
    if (strcmp(kind, "Pod") == 0) {
        return K8S_REC_POD;
    }
    for (int i = 0; workloads[i]; i++) {
        if (strcmp(kind, workloads[i]) == 0) {
            return K8S_REC_WORKLOAD;
        }
    }
    return K8S_REC_OTHER;
}

/* The block whose pairs a record of this kind contributes. */
static k8s_pair_block_t k8s_kind_block(k8s_rec_kind_t kind) {
    switch (kind) {
    case K8S_REC_SERVICE:
        return K8S_PAIR_SELECTOR;
    case K8S_REC_WORKLOAD:
        return K8S_PAIR_TEMPLATE_LABEL;
    case K8S_REC_POD:
        return K8S_PAIR_META_LABEL;
    case K8S_REC_OTHER:
    default:
        return K8S_PAIR_NONE;
    }
}

/* One scanned `key: value` with the block it sits in. */
typedef struct {
    k8s_pair_block_t block;
    char *kv; /* "key=value", heap-owned until moved into the record array */
} k8s_scanned_pair_t;

typedef struct {
    k8s_scanned_pair_t *items;
    int count;
    int cap;
} k8s_scanned_t;

static char *k8s_join_kv(const char *key, const char *val) {
    size_t kl = strlen(key);
    size_t vl = strlen(val);
    char *kv = cbm_alloc(CBM_MEM_CLASS_OTHER, kl + vl + 2);
    if (!kv) {
        return NULL;
    }
    memcpy(kv, key, kl);
    kv[kl] = '=';
    memcpy(kv + kl + 1, val, vl + 1);
    return kv;
}

static void k8s_scanned_push(k8s_scanned_t *s, k8s_pair_block_t block, const char *key,
                             const char *val) {
    if (s->count == s->cap) {
        int cap = s->cap ? s->cap * 2 : K8S_GROW_MIN;
        k8s_scanned_pair_t *grown =
            cbm_realloc(CBM_MEM_CLASS_OTHER, s->items, (size_t)cap * sizeof(*grown));
        if (!grown) {
            return;
        }
        s->items = grown;
        s->cap = cap;
    }
    char *kv = k8s_join_kv(key, val);
    if (kv) {
        s->items[s->count++] = (k8s_scanned_pair_t){.block = block, .kv = kv};
    }
}

/* Dotted path of the open block keys, e.g. "spec.template.metadata.labels". */
static void k8s_parent_path(char *out, size_t out_sz, const char (*keys)[64], int depth) {
    out[0] = '\0';
    size_t w = 0;
    for (int i = 0; i < depth && w + 1 < out_sz; i++) {
        int n = snprintf(out + w, out_sz - w, "%s%s", i ? "." : "", keys[i]);
        if (n < 0) {
            break;
        }
        w += (size_t)n < out_sz - w ? (size_t)n : out_sz - w - 1;
    }
}

/* Scan a single-document k8s manifest's text for its name, namespace, kind and
 * label pairs into `rec` / `out`. A small indentation path-stack gives every
 * leaf its parent path, which tells spec.selector from the pod template's
 * labels and from the object's own metadata.labels. */
static void k8s_scan_labels(const char *source, k8s_record_t *rec, k8s_scanned_t *out) {
    enum { K8S_PATH_DEPTH = 12 };
    int indents[K8S_PATH_DEPTH];
    char keys[K8S_PATH_DEPTH][64];
    int depth = 0;
    bool got_name = false;
    bool seen_key = false;

    const char *p = source;
    while (p && *p) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[CBM_SZ_512];
        size_t cp = len < sizeof(line) - 1 ? len : sizeof(line) - 1;
        memcpy(line, p, cp);
        line[cp] = '\0';

        /* End of first YAML document — stop (one Resource per file). */
        const char *trimmed = line;
        while (*trimmed == ' ') {
            trimmed++;
        }
        /* A `---` before any key opens the first document; it does not end it. */
        if (strncmp(trimmed, "---", 3) == 0 && line == trimmed) {
            if (seen_key) {
                break;
            }
            if (!eol) {
                break;
            }
            p = eol + 1;
            continue;
        }

        if (trimmed[0] && trimmed[0] != '#') {
            seen_key = true;
            int ind = k8s_indent(line);
            while (depth > 0 && indents[depth - 1] >= ind) {
                depth--;
            }
            char key[64];
            char val[K8S_LABEL_LEN];
            if (k8s_split_kv(trimmed, key, sizeof(key), val, sizeof(val))) {
                if (val[0] == '\0') {
                    /* Block-opening key: push onto the path stack. */
                    if (depth < K8S_PATH_DEPTH) {
                        indents[depth] = ind;
                        snprintf(keys[depth], sizeof(keys[depth]), "%s", key);
                        depth++;
                    }
                } else if (ind == 0 && strcmp(key, "kind") == 0) {
                    rec->kind = k8s_rec_kind(val);
                } else if (depth == 1 && strcmp(keys[0], "metadata") == 0) {
                    if (!got_name && strcmp(key, "name") == 0) {
                        snprintf(rec->name, sizeof(rec->name), "%s", val);
                        got_name = true;
                    } else if (strcmp(key, "namespace") == 0) {
                        snprintf(rec->ns, sizeof(rec->ns), "%s", val);
                    }
                } else {
                    char parent[CBM_SZ_512];
                    k8s_parent_path(parent, sizeof(parent), (const char (*)[64])keys, depth);
                    k8s_pair_block_t block = k8s_pair_block(parent);
                    if (block != K8S_PAIR_NONE) {
                        k8s_scanned_push(out, block, key, val);
                    }
                }
            }
        }

        if (!eol) {
            break;
        }
        p = eol + 1;
    }
}

static bool k8s_records_reserve(k8s_record_array_t *recs, int pair_extra) {
    if (recs->count == recs->cap) {
        int cap = recs->cap ? recs->cap * 2 : K8S_GROW_MIN;
        k8s_record_t *grown =
            cbm_realloc(CBM_MEM_CLASS_OTHER, recs->items, (size_t)cap * sizeof(*grown));
        if (!grown) {
            return false;
        }
        recs->items = grown;
        recs->cap = cap;
    }
    if (recs->pair_count + pair_extra > recs->pair_cap) {
        int cap = recs->pair_cap ? recs->pair_cap : K8S_GROW_MIN;
        while (cap < recs->pair_count + pair_extra) {
            cap *= 2;
        }
        char **grown = cbm_realloc(CBM_MEM_CLASS_OTHER, recs->pairs, (size_t)cap * sizeof(*grown));
        if (!grown) {
            return false;
        }
        recs->pairs = grown;
        recs->pair_cap = cap;
    }
    return true;
}

/* Record the manifest behind Resource `node_id`: scan its text, keep the
 * pairs its kind contributes, drop the rest. */
static void k8s_record_manifest(k8s_record_array_t *recs, int64_t node_id, const char *source) {
    k8s_record_t rec = {.node_id = node_id};
    k8s_scanned_t scanned = {0};
    k8s_scan_labels(source, &rec, &scanned);
    k8s_pair_block_t keep = k8s_kind_block(rec.kind);
    int kept = 0;
    for (int i = 0; i < scanned.count; i++) {
        kept += scanned.items[i].block == keep;
    }
    if (rec.kind != K8S_REC_OTHER && k8s_records_reserve(recs, kept)) {
        rec.pair_off = recs->pair_count;
        for (int i = 0; i < scanned.count; i++) {
            if (scanned.items[i].block == keep) {
                recs->pairs[recs->pair_count++] = scanned.items[i].kv;
                scanned.items[i].kv = NULL;
            }
        }
        rec.pair_n = recs->pair_count - rec.pair_off;
        recs->items[recs->count++] = rec;
    }
    for (int i = 0; i < scanned.count; i++) {
        cbm_free(CBM_MEM_CLASS_OTHER, scanned.items[i].kv);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, scanned.items);
}

static void k8s_records_free(k8s_record_array_t *recs) {
    for (int i = 0; i < recs->pair_count; i++) {
        cbm_free(CBM_MEM_CLASS_OTHER, recs->pairs[i]);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, recs->pairs);
    cbm_free(CBM_MEM_CLASS_OTHER, recs->items);
    *recs = (k8s_record_array_t){0};
}

/* Workloads (record indices, ascending) that carry one "key=value" pair. */
typedef struct {
    int *items;
    int count;
    int cap;
} k8s_posting_t;

static void k8s_posting_free(const char *key, void *value, void *userdata) {
    (void)key;
    (void)userdata;
    k8s_posting_t *posting = value;
    cbm_free(CBM_MEM_CLASS_OTHER, posting->items);
    cbm_free(CBM_MEM_CLASS_OTHER, posting);
}

static bool k8s_posting_add(CBMHashTable *index, const char *kv, int rec_idx) {
    k8s_posting_t *posting = cbm_ht_get(index, kv);
    if (!posting) {
        posting = cbm_calloc(CBM_MEM_CLASS_OTHER, sizeof(*posting));
        if (!posting) {
            return false;
        }
        cbm_ht_set(index, kv, posting);
    }
    if (posting->count && posting->items[posting->count - 1] == rec_idx) {
        return true; /* the same pair twice in one workload */
    }
    if (posting->count == posting->cap) {
        int cap = posting->cap ? posting->cap * 2 : K8S_GROW_MIN;
        int *grown = cbm_realloc(CBM_MEM_CLASS_OTHER, posting->items, (size_t)cap * sizeof(*grown));
        if (!grown) {
            return false;
        }
        posting->items = grown;
        posting->cap = cap;
    }
    posting->items[posting->count++] = rec_idx;
    return true;
}

static bool k8s_has_pair(const k8s_record_array_t *recs, const k8s_record_t *rec, const char *kv) {
    for (int i = 0; i < rec->pair_n; i++) {
        if (strcmp(recs->pairs[rec->pair_off + i], kv) == 0) {
            return true;
        }
    }
    return false;
}

/* Two set namespaces must agree; an unset one is the deploy-time namespace. */
static bool k8s_same_namespace(const k8s_record_t *a, const k8s_record_t *b) {
    return !a->ns[0] || !b->ns[0] || strcmp(a->ns, b->ns) == 0;
}

/* Connect each Service to the workloads its selector targets via an INFRA_MAPS
 * edge (Service Resource → workload Resource). */
static void k8s_link_selectors(cbm_pipeline_ctx_t *ctx, const k8s_record_array_t *recs) {
    CBMHashTable *index = cbm_ht_create(0);
    if (!index) {
        return;
    }
    for (int i = 0; i < recs->count; i++) {
        const k8s_record_t *wl = &recs->items[i];
        if (wl->kind == K8S_REC_WORKLOAD || wl->kind == K8S_REC_POD) {
            for (int p = 0; p < wl->pair_n; p++) {
                (void)k8s_posting_add(index, recs->pairs[wl->pair_off + p], i);
            }
        }
    }
    int edges = 0;
    for (int i = 0; i < recs->count; i++) {
        const k8s_record_t *svc = &recs->items[i];
        if (svc->kind != K8S_REC_SERVICE || svc->pair_n == 0) {
            continue;
        }
        /* Candidates: the workloads carrying the Service's rarest pair. */
        const k8s_posting_t *rarest = NULL;
        for (int p = 0; p < svc->pair_n; p++) {
            const k8s_posting_t *posting = cbm_ht_get(index, recs->pairs[svc->pair_off + p]);
            if (!posting) {
                rarest = NULL;
                break;
            }
            if (!rarest || posting->count < rarest->count) {
                rarest = posting;
            }
        }
        for (int c = 0; rarest && c < rarest->count; c++) {
            const k8s_record_t *wl = &recs->items[rarest->items[c]];
            bool all = k8s_same_namespace(svc, wl);
            for (int p = 0; all && p < svc->pair_n; p++) {
                all = k8s_has_pair(recs, wl, recs->pairs[svc->pair_off + p]);
            }
            if (all) {
                char props[CBM_SZ_256];
                snprintf(props, sizeof(props),
                         "{\"kind\":\"selector\",\"service\":\"%s\",\"workload\":\"%s\"}",
                         svc->name, wl->name);
                cbm_gbuf_insert_edge(ctx->gbuf, svc->node_id, wl->node_id, "INFRA_MAPS", props);
                edges++;
            }
        }
    }
    cbm_ht_foreach(index, k8s_posting_free, NULL);
    cbm_ht_free(index);
    if (edges > 0) {
        cbm_log_info("pass.k8s.selectors", "linked", itoa_k8s(edges));
    }
}

/* ── K8s manifest handler ────────────────────────────────────────── */

/* source/src_len are the already-read file bytes (caller retains ownership and
 * must free after this call returns). The first Resource's manifest is
 * recorded in `recs` for cross-manifest selector matching. */
static void handle_k8s_manifest(cbm_pipeline_ctx_t *ctx, const char *rel_path, const char *source,
                                const CBMFileResult *res, k8s_record_array_t *recs) {
    int resource_count = 0;
    int64_t first_node_id = 0;

    if (!res) {
        return;
    }

    /* Compute file node QN for DEFINES edges */
    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel_path, "__file__");
    const cbm_gbuf_node_t *file_node = file_qn ? cbm_gbuf_find_by_qn(ctx->gbuf, file_qn) : NULL;
    free(file_qn);

    for (int d = 0; d < res->defs.count; d++) {
        CBMDefinition *def = &res->defs.items[d];
        if (!def->label || strcmp(def->label, "Resource") != 0) {
            continue;
        }
        if (!def->name || !def->qualified_name) {
            continue;
        }

        int64_t node_id =
            cbm_gbuf_upsert_node(ctx->gbuf, "Resource", def->name, def->qualified_name, rel_path,
                                 (int)def->start_line, (int)def->end_line, "{\"source\":\"k8s\"}");

        /* DEFINES edge: File → Resource */
        if (file_node && node_id > 0) {
            cbm_gbuf_insert_edge(ctx->gbuf, file_node->id, node_id, "DEFINES", "{}");
        }

        /* Capture the first Resource for cross-manifest selector matching. */
        if (first_node_id <= 0 && node_id > 0) {
            first_node_id = node_id;
        }

        resource_count++;
    }

    /* Record selector / pod-label pairs for later Service → workload linking. */
    if (first_node_id > 0 && source) {
        k8s_record_manifest(recs, first_node_id, source);
    }

    cbm_log_info("pass.k8s.manifest", "file", rel_path, "resources", itoa_k8s(resource_count));
}

/* ── Helm chart handler ──────────────────────────────────────────── */

static bool is_helm_chart_file(const char *base) {
    return strcmp(base, "Chart.yaml") == 0 || strcmp(base, "Chart.yml") == 0;
}

/* Emit a Chart node for a Chart.yaml and a DEPENDS_ON edge to a (shared,
 * deduplicated) Chart node per declared dependency (#338). */
static void handle_helm_chart(cbm_pipeline_ctx_t *ctx, const char *rel_path, const char *source) {
    cbm_helm_chart_t hc;
    if (cbm_parse_helm_chart(source, &hc) != 0) {
        return;
    }

    const char *cname = hc.chart_name[0] ? hc.chart_name : k8s_basename(rel_path);
    char *chart_qn = cbm_infra_qn(ctx->project_name, rel_path, "helm-chart", NULL);
    if (!chart_qn) {
        return;
    }
    int64_t chart_id = cbm_gbuf_upsert_node(ctx->gbuf, "Chart", cname, chart_qn, rel_path, SKIP_ONE,
                                            0, "{\"source\":\"helm\"}");
    free(chart_qn);

    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel_path, "__file__");
    const cbm_gbuf_node_t *file_node = file_qn ? cbm_gbuf_find_by_qn(ctx->gbuf, file_qn) : NULL;
    if (file_node && chart_id > 0) {
        cbm_gbuf_insert_edge(ctx->gbuf, file_node->id, chart_id, "DEFINES", "{}");
    }
    free(file_qn);

    int dep_edges = 0;
    for (int i = 0; i < hc.dep_count && chart_id > 0; i++) {
        /* Stable per-project QN so multiple charts depending on the same chart
         * link to one shared dependency node. */
        char dep_qn[CBM_SZ_512];
        snprintf(dep_qn, sizeof(dep_qn), "%s.__helm_dep__.%s", ctx->project_name, hc.deps[i]);
        int64_t dep_id =
            cbm_gbuf_upsert_node(ctx->gbuf, "Chart", hc.deps[i], dep_qn, rel_path, SKIP_ONE, 0,
                                 "{\"source\":\"helm\",\"external\":true}");
        if (dep_id > 0) {
            cbm_gbuf_insert_edge(ctx->gbuf, chart_id, dep_id, "DEPENDS_ON", "{}");
            dep_edges++;
        }
    }
    cbm_log_info("pass.k8s.helm", "file", rel_path, "deps", itoa_k8s(dep_edges));
}

/* ── Dependency-manifest handler (go.mod / requirements.txt) ──────── */

static bool is_gomod_file(const char *base) {
    return strcmp(base, "go.mod") == 0;
}

static bool is_requirements_file(const char *base) {
    return strcmp(base, "requirements.txt") == 0;
}

/* Emit a DEPENDS_ON edge from the manifest file node to a (shared, per-project)
 * external Package node.  Mirrors the Helm Chart.yaml DEPENDS_ON shape. */
static int emit_dep_edge(cbm_pipeline_ctx_t *ctx, const cbm_gbuf_node_t *src, const char *rel_path,
                         const char *ecosystem, const char *name) {
    if (!name || !name[0]) {
        return 0;
    }
    char dep_qn[CBM_SZ_512];
    snprintf(dep_qn, sizeof(dep_qn), "%s.__%s_dep__.%s", ctx->project_name, ecosystem, name);
    char dep_props[CBM_SZ_256];
    snprintf(dep_props, sizeof(dep_props), "{\"source\":\"%s\",\"external\":true}", ecosystem);
    int64_t dep_id =
        cbm_gbuf_upsert_node(ctx->gbuf, "Package", name, dep_qn, rel_path, SKIP_ONE, 0, dep_props);
    if (dep_id > 0 && dep_id != src->id) {
        cbm_gbuf_insert_edge(ctx->gbuf, src->id, dep_id, "DEPENDS_ON", "{}");
        return 1;
    }
    return 0;
}

/* Copy the first whitespace-delimited token of `line` into `out`. */
static void first_token(const char *line, char *out, size_t out_sz) {
    out[0] = '\0';
    while (*line == ' ' || *line == '\t') {
        line++;
    }
    size_t n = 0;
    while (line[n] && line[n] != ' ' && line[n] != '\t' && line[n] != '\r' && line[n] != '\n' &&
           n + 1 < out_sz) {
        out[n] = line[n];
        n++;
    }
    out[n] = '\0';
}

/* Parse go.mod `require` directives (single-line and block forms) and emit a
 * DEPENDS_ON edge per dependency.  go.mod requires are not surfaced as imports
 * by the extraction layer, so we parse the manifest text directly here. */
static int parse_gomod_deps(cbm_pipeline_ctx_t *ctx, const cbm_gbuf_node_t *src,
                            const char *rel_path, const char *source) {
    int edges = 0;
    bool in_block = false;
    const char *p = source;
    while (p && *p) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[CBM_SZ_512];
        size_t cp = len < sizeof(line) - 1 ? len : sizeof(line) - 1;
        memcpy(line, p, cp);
        line[cp] = '\0';
        const char *t = line;
        while (*t == ' ' || *t == '\t') {
            t++;
        }
        if (in_block) {
            if (t[0] == ')') {
                in_block = false;
            } else if (t[0] && t[0] != '/') {
                char name[CBM_SZ_256];
                first_token(t, name, sizeof(name));
                edges += emit_dep_edge(ctx, src, rel_path, "gomod", name);
            }
        } else if (strncmp(t, "require", 7) == 0 && (t[7] == ' ' || t[7] == '\t' || t[7] == '(')) {
            const char *rest = t + 7;
            while (*rest == ' ' || *rest == '\t') {
                rest++;
            }
            if (*rest == '(') {
                in_block = true;
            } else if (*rest) {
                char name[CBM_SZ_256];
                first_token(rest, name, sizeof(name));
                edges += emit_dep_edge(ctx, src, rel_path, "gomod", name);
            }
        }
        if (!eol) {
            break;
        }
        p = eol + 1;
    }
    return edges;
}

/* Parse requirements.txt entries (one package spec per line) and emit a
 * DEPENDS_ON edge per dependency.  The package name is the leading token up to
 * the first version/extras/comment delimiter. */
static int parse_requirements_deps(cbm_pipeline_ctx_t *ctx, const cbm_gbuf_node_t *src,
                                   const char *rel_path, const char *source) {
    int edges = 0;
    const char *p = source;
    while (p && *p) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[CBM_SZ_512];
        size_t cp = len < sizeof(line) - 1 ? len : sizeof(line) - 1;
        memcpy(line, p, cp);
        line[cp] = '\0';
        const char *t = line;
        while (*t == ' ' || *t == '\t') {
            t++;
        }
        /* Skip blanks, comments, options (-r, --hash), and URLs. */
        if (t[0] && t[0] != '#' && t[0] != '-' && strstr(t, "://") == NULL) {
            char name[CBM_SZ_256];
            size_t n = 0;
            while (t[n] && t[n] != '=' && t[n] != '<' && t[n] != '>' && t[n] != '!' &&
                   t[n] != '~' && t[n] != '[' && t[n] != ';' && t[n] != ' ' && t[n] != '\t' &&
                   t[n] != '\r' && n + 1 < sizeof(name)) {
                name[n] = t[n];
                n++;
            }
            name[n] = '\0';
            edges += emit_dep_edge(ctx, src, rel_path, "pypi", name);
        }
        if (!eol) {
            break;
        }
        p = eol + 1;
    }
    return edges;
}

static void handle_dep_manifest(cbm_pipeline_ctx_t *ctx, const char *rel_path, const char *source,
                                const char *ecosystem) {
    if (!source) {
        return;
    }
    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel_path, "__file__");
    const cbm_gbuf_node_t *src = file_qn ? cbm_gbuf_find_by_qn(ctx->gbuf, file_qn) : NULL;
    free(file_qn);
    if (!src) {
        return;
    }
    int dep_edges = strcmp(ecosystem, "gomod") == 0
                        ? parse_gomod_deps(ctx, src, rel_path, source)
                        : parse_requirements_deps(ctx, src, rel_path, source);
    cbm_log_info("pass.k8s.depmanifest", "file", rel_path, "deps", itoa_k8s(dep_edges));
}

/* ── Pass entry point ────────────────────────────────────────────── */

/* What one file contributes, prepared off the graph: reading, classifying and
 * extracting are per-file work, so they run in parallel; everything that
 * touches the graph buffer then runs on this thread in file order, exactly as
 * the sequential loop did. Sequentially the pass re-read and re-parsed every
 * YAML manifest on one thread -- 1.1 s of the Go corpus (6,275 manifests;
 * profile + waste sanitizer, 2026-09-17). */
typedef enum { K8S_SKIP = 0, K8S_DEP, K8S_HELM, K8S_MANIFEST } k8s_kind_t;

typedef struct {
    k8s_kind_t kind;
    char *source; /* DEP, HELM, MANIFEST */
    int src_len;
    CBMFileResult *res; /* MANIFEST */
} k8s_prep_t;

typedef struct {
    cbm_pipeline_ctx_t *ctx;
    const cbm_file_info_t *files;
    k8s_prep_t *prep; /* indexed from `begin` */
    int begin;
    int end;
    _Atomic int next;
} k8s_prep_job_t;

enum { K8S_CHUNK = 1024 };

static void k8s_prep_file(const k8s_prep_job_t *job, int i, k8s_prep_t *out) {
    cbm_pipeline_ctx_t *ctx = job->ctx;
    const char *path = job->files[i].path;
    const char *rel = job->files[i].rel_path;
    CBMLanguage lang = job->files[i].language;
    const char *base = k8s_basename(rel);

    if (is_gomod_file(base) || lang == CBM_LANG_GOMOD || is_requirements_file(base)) {
        out->source = k8s_read_file(path, &out->src_len);
        out->kind = out->source ? K8S_DEP : K8S_SKIP;
    } else if (lang == CBM_LANG_YAML || lang == CBM_LANG_K8S) {
        /* Read source once to classify (and reuse for uncached extraction). */
        out->source = k8s_read_file(path, &out->src_len);
        if (!out->source) {
            return;
        }
        if (is_helm_chart_file(base)) {
            out->kind = K8S_HELM;
        } else if (cbm_is_k8s_manifest(base, out->source)) {
            /* Always re-extract with CBM_LANG_K8S regardless of any cached
             * result: cached results were produced during the parallel YAML
             * pass and contain no "Resource" definitions. */
            out->kind = K8S_MANIFEST;
            out->res = cbm_extract_file(out->source, out->src_len, CBM_LANG_K8S, ctx->project_name,
                                        rel, CBM_EXTRACT_BUDGET, NULL, NULL);
        } else {
            cbm_free(CBM_MEM_CLASS_OTHER, out->source);
            out->source = NULL;
        }
    }
}

static void k8s_prep_worker(int worker_id, void *arg) {
    (void)worker_id;
    k8s_prep_job_t *job = (k8s_prep_job_t *)arg;
    cbm_work_arena_keep_begin(); /* one scratch arena for this worker's files */
    while (true) {
        int i = atomic_fetch_add_explicit(&job->next, SKIP_ONE, memory_order_relaxed);
        if (i >= job->end) {
            break;
        }
        k8s_prep_file(job, i, &job->prep[i - job->begin]);
    }
    /* Per-thread extraction state, torn down like extract_worker's. */
    cbm_destroy_thread_parser();
    cbm_work_arena_release();
    cbm_slab_destroy_thread();
    cbm_kind_in_set_free_cache();
}

int cbm_pipeline_pass_k8s(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count) {
    cbm_log_info("pass.start", "pass", "k8s", "files", itoa_k8s(file_count));

    cbm_init();

    int manifest_count = 0;
    int helm_count = 0;

    /* Collect per-manifest selector/label records for cross-manifest matching. */
    k8s_record_array_t recs = {0};

    k8s_prep_t *prep = cbm_calloc(CBM_MEM_CLASS_OTHER, K8S_CHUNK * sizeof(*prep));
    if (!prep) {
        return CBM_NOT_FOUND;
    }
    int workers = cbm_default_worker_count(false);

    for (int begin = 0; begin < file_count; begin += K8S_CHUNK) {
        int end = begin + K8S_CHUNK < file_count ? begin + K8S_CHUNK : file_count;
        if (cbm_pipeline_check_cancel(ctx)) {
            cbm_free(CBM_MEM_CLASS_OTHER, prep);
            k8s_records_free(&recs);
            return CBM_NOT_FOUND;
        }
        memset(prep, 0, (size_t)K8S_CHUNK * sizeof(*prep));
        k8s_prep_job_t job = {.ctx = ctx, .files = files, .prep = prep, .begin = begin, .end = end};
        atomic_init(&job.next, begin);
        cbm_parallel_for(
            workers, k8s_prep_worker, &job,
            (cbm_parallel_for_opts_t){.max_workers = workers, .force_pthreads = false});

        bool cancelled = false;
        for (int i = begin; i < end; i++) {
            k8s_prep_t *p = &prep[i - begin];
            if (!cancelled && cbm_pipeline_check_cancel(ctx)) {
                cancelled = true;
            }
            if (!cancelled) {
                const char *rel = files[i].rel_path;
                const char *base = k8s_basename(rel);
                switch (p->kind) {
                case K8S_DEP:
                    handle_dep_manifest(ctx, rel, p->source,
                                        is_requirements_file(base) ? "pypi" : "gomod");
                    break;
                case K8S_HELM:
                    handle_helm_chart(ctx, rel, p->source);
                    helm_count++;
                    break;
                case K8S_MANIFEST:
                    handle_k8s_manifest(ctx, rel, p->source, p->res, &recs);
                    manifest_count++;
                    break;
                case K8S_SKIP:
                default:
                    break;
                }
            }
            cbm_free(CBM_MEM_CLASS_OTHER, p->source);
            if (p->res) {
                cbm_free_result(p->res);
            }
        }
        if (cancelled) {
            cbm_free(CBM_MEM_CLASS_OTHER, prep);
            k8s_records_free(&recs);
            return CBM_NOT_FOUND;
        }
    }
    cbm_free(CBM_MEM_CLASS_OTHER, prep);

    /* Connect Services to the workloads their selectors target (INFRA_MAPS). */
    k8s_link_selectors(ctx, &recs);
    k8s_records_free(&recs);

    cbm_log_info("pass.done", "pass", "k8s", "manifests", itoa_k8s(manifest_count));
    (void)helm_count;
    return 0;
}
