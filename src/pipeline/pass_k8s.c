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
#include "foundation/str_util.h"   /* cbm_json_escape */
#include "pipeline/worker_pool.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define K8S_SLEN(s) (sizeof(s) - 1)

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

/* `key: { a: b, c: d }` — a flow-style map is the same label map written on
 * one line. One the line buffer cut short (no closing brace) is skipped
 * whole: a selector missing pairs would select too much. */
static void k8s_scan_flow_map(k8s_scanned_t *out, const char (*keys)[64], int depth,
                              const char *key, const char *val) {
    size_t n = strlen(val);
    if (n < PAIR_LEN || val[0] != '{' || val[n - SKIP_ONE] != '}') {
        return;
    }
    char path[CBM_SZ_512];
    k8s_parent_path(path, sizeof(path), keys, depth);
    size_t w = strlen(path);
    snprintf(path + w, sizeof(path) - w, "%s%s", w ? "." : "", key);
    k8s_pair_block_t block = k8s_pair_block(path);
    if (block == K8S_PAIR_NONE) {
        return;
    }
    char inner[CBM_SZ_512];
    snprintf(inner, sizeof(inner), "%.*s", (int)(n - PAIR_LEN), val + SKIP_ONE);
    for (char *item = inner; item;) {
        char *comma = strchr(item, ',');
        if (comma) {
            *comma = '\0';
        }
        while (*item == ' ') {
            item++;
        }
        char k[64];
        char v[K8S_LABEL_LEN];
        if (k8s_split_kv(item, k, sizeof(k), v, sizeof(v)) && v[0]) {
            size_t kl = strlen(k);
            while (kl > 0 && k[kl - SKIP_ONE] == ' ') {
                k[--kl] = '\0';
            }
            k8s_scanned_push(out, block, k, v);
        }
        item = comma ? comma + SKIP_ONE : NULL;
    }
}

/* Scan ONE manifest document's text for its name, namespace, kind and
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

        /* End of the document — stop (the caller hands over one document). */
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
            char val[CBM_SZ_512]; /* a whole flow map fits: the line is the limit */
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
                } else if (val[0] == '{') {
                    k8s_scan_flow_map(out, (const char (*)[64])keys, depth, key, val);
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

/* Record the document at lines [start_line, end_line] (1-based, inclusive) of
 * a multi-document manifest: every object's selector or pod labels come from
 * its own document. */
static void k8s_record_document(k8s_record_array_t *recs, int64_t node_id, const char *source,
                                int start_line, int end_line) {
    const char *begin = source;
    for (int line = 1; begin && line < start_line; line++) {
        begin = strchr(begin, '\n');
        begin = begin ? begin + SKIP_ONE : NULL;
    }
    if (!begin) {
        return;
    }
    const char *end = begin;
    for (int line = start_line; *end && line <= end_line; line++) {
        const char *eol = strchr(end, '\n');
        end = eol ? eol + SKIP_ONE : end + strlen(end);
    }
    size_t n = (size_t)(end - begin);
    char *doc = cbm_alloc(CBM_MEM_CLASS_OTHER, n + SKIP_ONE);
    if (!doc) {
        return;
    }
    memcpy(doc, begin, n);
    doc[n] = '\0';
    k8s_record_manifest(recs, node_id, doc);
    cbm_free(CBM_MEM_CLASS_OTHER, doc);
}

/* Built-in kinds that live outside any namespace (IDENTITY.md). A CRD's own
 * scope (spec.scope) is the curated / generated table's job. */
static bool k8s_cluster_scoped(const char *kind) {
    static const char *const kinds[] = {"Namespace",
                                        "Node",
                                        "PersistentVolume",
                                        "ClusterRole",
                                        "ClusterRoleBinding",
                                        "CustomResourceDefinition",
                                        "StorageClass",
                                        "PriorityClass",
                                        "ValidatingWebhookConfiguration",
                                        "MutatingWebhookConfiguration",
                                        "APIService",
                                        "CSIDriver",
                                        "CSINode",
                                        "IngressClass",
                                        "RuntimeClass",
                                        "VolumeAttachment",
                                        "ValidatingAdmissionPolicy",
                                        "ValidatingAdmissionPolicyBinding",
                                        "ClusterIssuer"};
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        if (strcmp(kind, kinds[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* A Resource's properties from its identity key, the part of its QN after
 * "::": `<group>/<Kind>/<declared namespace or ->/<name>` (IDENTITY.md).
 * `obj_key` is the logical identity: the namespace it lives in, `_` for a
 * cluster-scoped kind, `?` when the deploy decides; `effective_ns` (when
 * not NULL) is the namespace a kustomize build gives it. NULL for a QN
 * without a well-formed key (the caller keeps the plain source tag). */
static char *k8s_resource_props(const char *qn, const char *effective_ns) {
    enum { K8S_KEY_PARTS = 4, K8S_ESC = 6 * K8S_LABEL_LEN };
    const char *key = qn ? strstr(qn, "::") : NULL;
    if (!key) {
        return NULL;
    }
    key += K8S_SLEN("::");
    char part[K8S_KEY_PARTS][K8S_LABEL_LEN];
    int parts = 0;
    for (const char *p = key; parts < K8S_KEY_PARTS; parts++) {
        const char *slash = parts < K8S_KEY_PARTS - SKIP_ONE ? strchr(p, '/') : NULL;
        size_t len = slash ? (size_t)(slash - p) : strlen(p);
        if (len == 0 || len >= K8S_LABEL_LEN || (!slash && parts < K8S_KEY_PARTS - SKIP_ONE)) {
            return NULL;
        }
        memcpy(part[parts], p, len);
        part[parts][len] = '\0';
        p = slash ? slash + SKIP_ONE : p + len;
    }
    const char *group = part[0];
    const char *kind = part[1];
    const char *ns = strcmp(part[2], "-") == 0 ? "" : part[2];
    const char *name = part[3];
    const char *effective = k8s_cluster_scoped(kind) ? "_"
                            : effective_ns           ? effective_ns
                            : ns[0]                  ? ns
                                                     : "?";
    char esc[K8S_KEY_PARTS + SKIP_ONE][K8S_ESC];
    cbm_json_escape(esc[0], K8S_ESC, group);
    cbm_json_escape(esc[1], K8S_ESC, kind);
    cbm_json_escape(esc[2], K8S_ESC, ns);
    cbm_json_escape(esc[3], K8S_ESC, name);
    cbm_json_escape(esc[4], K8S_ESC, effective);
    size_t n = K8S_KEY_PARTS * K8S_ESC + K8S_ESC + CBM_SZ_256;
    char *props = cbm_alloc(CBM_MEM_CLASS_OTHER, n);
    if (!props) {
        return NULL;
    }
    int w =
        snprintf(props, n, "{\"source\":\"k8s\",\"group\":\"%s\",\"kind\":\"%s\"", esc[0], esc[1]);
    if (ns[0]) {
        w += snprintf(props + w, n - (size_t)w, ",\"namespace\":\"%s\"", esc[2]);
    }
    snprintf(props + w, n - (size_t)w, ",\"obj_key\":\"%s/%s/%s/%s\"}", esc[0], esc[1], esc[4],
             esc[3]);
    return props;
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

/* ── Bundles: what is deployed together (IDENTITY.md) ────────────── */

/* A Service selects pods of its own deployment, never a same-labelled copy
 * elsewhere in the repository. A bundle is a kustomize build root (a
 * kustomization no other one includes) with every manifest its entries
 * reach; outside kustomize, the Helm chart a file sits in, else its
 * directory. A base several overlays include belongs to each of them. */

typedef struct {
    char *path; /* the kustomization file */
    char *ns;   /* its `namespace:`, NULL when unset */
    int *kids;  /* kustomizations its entries name (indices) */
    int kid_n;
    int kid_cap;
    const char **files; /* manifests its entries name (graph-owned paths) */
    int file_n;
    int file_cap;
    bool referenced; /* included by another kustomization */
} k8s_kust_t;

typedef struct {
    k8s_kust_t *items;
    int count;
    int cap;
} k8s_kusts_t;

/* One bundle a manifest belongs to, with the namespace the bundle gives
 * its objects (NULL: their own). `bundle` is an interned name, compared by
 * pointer. */
typedef struct {
    const char *bundle;
    const char *ns;
} k8s_member_t;

typedef struct {
    k8s_member_t *items;
    int count;
    int cap;
} k8s_members_t;

typedef struct {
    CBMHashTable *names;   /* bundle name -> itself (owned key) */
    CBMHashTable *members; /* manifest path -> k8s_members_t* */
    CBMHashTable *charts;  /* Helm chart directory -> itself (owned key) */
} k8s_bundles_t;

static bool k8s_grow(void **items, int *cap, int count, size_t elem) {
    if (count < *cap) {
        return true;
    }
    int ncap = *cap ? *cap * PAIR_LEN : K8S_GROW_MIN;
    void *grown = cbm_realloc(CBM_MEM_CLASS_OTHER, *items, (size_t)ncap * elem);
    if (!grown) {
        return false;
    }
    *items = grown;
    *cap = ncap;
    return true;
}

/* The top-level `namespace:` of a kustomization, NULL when it sets none. */
static char *k8s_kustomize_namespace(const char *source) {
    for (const char *p = source; p && *p;) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if (strncmp(p, "namespace:", K8S_SLEN("namespace:")) == 0) {
            char line[CBM_SZ_512];
            snprintf(line, sizeof(line), "%.*s", (int)len, p);
            char key[64];
            char val[K8S_LABEL_LEN];
            if (k8s_split_kv(line, key, sizeof(key), val, sizeof(val)) && val[0]) {
                return cbm_mem_strdup(CBM_MEM_CLASS_OTHER, val);
            }
            return NULL;
        }
        p = eol ? eol + SKIP_ONE : NULL;
    }
    return NULL;
}

static void k8s_kusts_push(k8s_kusts_t *ks, const char *path, char *ns) {
    if (!k8s_grow((void **)&ks->items, &ks->cap, ks->count, sizeof(*ks->items))) {
        cbm_free(CBM_MEM_CLASS_OTHER, ns);
        return;
    }
    ks->items[ks->count++] =
        (k8s_kust_t){.path = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, path), .ns = ns};
}

static void k8s_kusts_free(k8s_kusts_t *ks) {
    for (int i = 0; i < ks->count; i++) {
        cbm_free(CBM_MEM_CLASS_OTHER, ks->items[i].path);
        cbm_free(CBM_MEM_CLASS_OTHER, ks->items[i].ns);
        cbm_free(CBM_MEM_CLASS_OTHER, ks->items[i].kids);
        cbm_free(CBM_MEM_CLASS_OTHER, (void *)ks->items[i].files);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, ks->items);
    *ks = (k8s_kusts_t){0};
}

static int k8s_cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static int k8s_cmp_int(const void *a, const void *b) {
    int x = *(const int *)a;
    int y = *(const int *)b;
    return (x > y) - (x < y);
}

static int k8s_cmp_kust(const void *a, const void *b) {
    return strcmp(((const k8s_kust_t *)a)->path, ((const k8s_kust_t *)b)->path);
}

/* index + 1 of the kustomization at `path`, 0 when none. */
static int k8s_kust_at(CBMHashTable *by_path, const char *path) {
    return (int)(intptr_t)cbm_ht_get(by_path, path);
}

/* The kustomization file inside directory `dir`, as kustomize looks for it. */
static int k8s_kust_in_dir(CBMHashTable *by_path, const char *dir) {
    static const char *const names[] = {"kustomization.yaml", "kustomization.yml", "Kustomization"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[CBM_SZ_1K];
        snprintf(path, sizeof(path), "%s%s%s", dir, dir[0] ? "/" : "", names[i]);
        int k = k8s_kust_at(by_path, path);
        if (k) {
            return k;
        }
    }
    return 0;
}

/* Wire each kustomization to what its entries name, from the IMPORTS edges
 * the kustomize resolver drew: a directory means the kustomization in it,
 * a file another kustomization or a manifest. */
static void k8s_kusts_wire(cbm_pipeline_ctx_t *ctx, k8s_kusts_t *ks, CBMHashTable *by_path) {
    const cbm_gbuf_edge_t **edges = NULL;
    int count = 0;
    if (cbm_gbuf_find_edges_by_type(ctx->gbuf, "IMPORTS", &edges, &count) != 0) {
        return;
    }
    for (int i = 0; i < count; i++) {
        const cbm_gbuf_node_t *src = cbm_gbuf_find_by_id(ctx->gbuf, edges[i]->source_id);
        int k = src && src->file_path ? k8s_kust_at(by_path, src->file_path) : 0;
        const cbm_gbuf_node_t *tgt = k ? cbm_gbuf_find_by_id(ctx->gbuf, edges[i]->target_id) : NULL;
        if (!tgt || !tgt->file_path) {
            continue;
        }
        k8s_kust_t *kust = &ks->items[k - SKIP_ONE];
        int kid = tgt->label && strcmp(tgt->label, "Folder") == 0
                      ? k8s_kust_in_dir(by_path, tgt->file_path)
                      : k8s_kust_at(by_path, tgt->file_path);
        if (kid && kid != k) {
            if (k8s_grow((void **)&kust->kids, &kust->kid_cap, kust->kid_n, sizeof(int))) {
                kust->kids[kust->kid_n++] = kid - SKIP_ONE;
                ks->items[kid - SKIP_ONE].referenced = true;
            }
        } else if (!kid && strcmp(tgt->label ? tgt->label : "", "Folder") != 0) {
            if (k8s_grow((void **)&kust->files, &kust->file_cap, kust->file_n,
                         sizeof(*kust->files))) {
                kust->files[kust->file_n++] = tgt->file_path;
            }
        }
    }
    for (int i = 0; i < ks->count; i++) {
        qsort(ks->items[i].files, (size_t)ks->items[i].file_n, sizeof(*ks->items[i].files),
              k8s_cmp_str);
        qsort(ks->items[i].kids, (size_t)ks->items[i].kid_n, sizeof(int), k8s_cmp_int);
    }
}

static const char *k8s_bundle_name(k8s_bundles_t *b, const char *kind, const char *where) {
    char name[CBM_SZ_1K];
    snprintf(name, sizeof(name), "%s:%s", kind, where);
    const char *known = cbm_ht_get_key(b->names, name);
    if (known) {
        return known;
    }
    char *owned = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, name);
    if (owned) {
        cbm_ht_set(b->names, owned, owned);
    }
    return owned;
}

static void k8s_member_add(k8s_bundles_t *b, const char *file, const char *bundle, const char *ns) {
    k8s_members_t *m = cbm_ht_get(b->members, file);
    if (!m) {
        m = cbm_calloc(CBM_MEM_CLASS_OTHER, sizeof(*m));
        if (!m) {
            return;
        }
        cbm_ht_set(b->members, file, m);
    }
    for (int i = 0; i < m->count; i++) {
        if (m->items[i].bundle == bundle) {
            return; /* reached twice from one root: the first path's namespace */
        }
    }
    if (k8s_grow((void **)&m->items, &m->cap, m->count, sizeof(*m->items))) {
        m->items[m->count++] = (k8s_member_t){bundle, ns};
    }
}

/* Every build root's manifests, each with the namespace the outermost
 * kustomization on its path sets (kustomize applies the root's namespace
 * transformer last, so it wins). */
static void k8s_bundles_from_kusts(k8s_bundles_t *b, k8s_kusts_t *ks) {
    typedef struct {
        int kust;
        const char *ns;
    } frame_t;
    int *seen =
        cbm_calloc(CBM_MEM_CLASS_OTHER, (size_t)(ks->count ? ks->count : SKIP_ONE) * sizeof(int));
    frame_t *stack = NULL;
    int depth = 0;
    int cap = 0;
    for (int r = 0; seen && r < ks->count; r++) {
        if (ks->items[r].referenced) {
            continue;
        }
        const char *bundle = k8s_bundle_name(b, "kustomize", ks->items[r].path);
        if (!bundle || !k8s_grow((void **)&stack, &cap, depth, sizeof(*stack))) {
            continue;
        }
        stack[depth++] = (frame_t){r, ks->items[r].ns};
        while (depth > 0) {
            frame_t f = stack[--depth];
            if (seen[f.kust] == r + SKIP_ONE) {
                continue;
            }
            seen[f.kust] = r + SKIP_ONE;
            const k8s_kust_t *k = &ks->items[f.kust];
            for (int i = 0; i < k->file_n; i++) {
                k8s_member_add(b, k->files[i], bundle, f.ns);
            }
            for (int i = k->kid_n - SKIP_ONE; i >= 0; i--) {
                if (k8s_grow((void **)&stack, &cap, depth, sizeof(*stack))) {
                    int kid = k->kids[i];
                    stack[depth++] = (frame_t){kid, f.ns ? f.ns : ks->items[kid].ns};
                }
            }
        }
    }
    cbm_free(CBM_MEM_CLASS_OTHER, stack);
    cbm_free(CBM_MEM_CLASS_OTHER, seen);
}

static void k8s_dirname(const char *path, char *out, size_t out_sz) {
    const char *slash = strrchr(path, '/');
    snprintf(out, out_sz, "%.*s", slash ? (int)(slash - path) : 0, path);
}

/* The bundles of the manifest at `file`: its kustomize build roots; else
 * the Helm chart it sits in; else its directory. */
static const k8s_members_t *k8s_bundles_of(k8s_bundles_t *b, const char *file,
                                           k8s_members_t *single) {
    const k8s_members_t *m = cbm_ht_get(b->members, file);
    if (m && m->count > 0) {
        return m;
    }
    char dir[CBM_SZ_1K];
    k8s_dirname(file, dir, sizeof(dir));
    char up[CBM_SZ_1K];
    snprintf(up, sizeof(up), "%s", dir);
    const char *bundle = NULL;
    while (!bundle) {
        if (cbm_ht_get(b->charts, up)) {
            bundle = k8s_bundle_name(b, "chart", up);
            break;
        }
        if (!up[0]) {
            break;
        }
        char parent[CBM_SZ_1K];
        k8s_dirname(up, parent, sizeof(parent));
        snprintf(up, sizeof(up), "%s", parent);
    }
    if (!bundle) {
        bundle = k8s_bundle_name(b, "dir", dir);
    }
    single->items[0] = (k8s_member_t){bundle, NULL};
    single->count = bundle ? SKIP_ONE : 0;
    return single;
}

static void k8s_free_owned_key(const char *key, void *value, void *ud) {
    (void)value;
    (void)ud;
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)key);
}

static void k8s_free_members(const char *key, void *value, void *ud) {
    (void)key;
    (void)ud;
    k8s_members_t *m = value;
    cbm_free(CBM_MEM_CLASS_OTHER, m->items);
    cbm_free(CBM_MEM_CLASS_OTHER, m);
}

static void k8s_bundles_free(k8s_bundles_t *b) {
    if (b->members) {
        cbm_ht_foreach(b->members, k8s_free_members, NULL);
        cbm_ht_free(b->members);
    }
    if (b->names) {
        cbm_ht_foreach(b->names, k8s_free_owned_key, NULL);
        cbm_ht_free(b->names);
    }
    if (b->charts) {
        cbm_ht_foreach(b->charts, k8s_free_owned_key, NULL);
        cbm_ht_free(b->charts);
    }
    *b = (k8s_bundles_t){0};
}

/* A Helm chart's directory bundles the plain manifests below it. */
static void k8s_chart_dir_add(k8s_bundles_t *b, const char *chart_yaml) {
    char dir[CBM_SZ_1K];
    k8s_dirname(chart_yaml, dir, sizeof(dir));
    if (b->charts && !cbm_ht_get(b->charts, dir)) {
        char *owned = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, dir);
        if (owned) {
            cbm_ht_set(b->charts, owned, owned);
        }
    }
}

/* Build the kustomize bundles (call once every manifest and kustomization is
 * known and the IMPORTS edges exist). */
static void k8s_bundles_build(cbm_pipeline_ctx_t *ctx, k8s_kusts_t *ks, k8s_bundles_t *b) {
    b->names = cbm_ht_create(0);
    b->members = cbm_ht_create(0);
    if (!b->charts) {
        b->charts = cbm_ht_create(0);
    }
    if (!b->names || !b->members || !b->charts) {
        return;
    }
    qsort(ks->items, (size_t)ks->count, sizeof(*ks->items), k8s_cmp_kust);
    CBMHashTable *by_path = cbm_ht_create(0);
    if (!by_path) {
        return;
    }
    for (int i = 0; i < ks->count; i++) {
        cbm_ht_set(by_path, ks->items[i].path, (void *)(intptr_t)(i + SKIP_ONE));
    }
    k8s_kusts_wire(ctx, ks, by_path);
    cbm_ht_free(by_path);
    k8s_bundles_from_kusts(b, ks);
}

/* A Service and a workload meet when they share a bundle whose namespaces
 * agree: two set namespaces must be equal; an unset one is the deploy's. */
static bool k8s_share_bundle(k8s_bundles_t *b, const cbm_pipeline_ctx_t *ctx,
                             const k8s_record_t *svc, const k8s_record_t *wl) {
    const cbm_gbuf_node_t *sn = cbm_gbuf_find_by_id(ctx->gbuf, svc->node_id);
    const cbm_gbuf_node_t *wn = cbm_gbuf_find_by_id(ctx->gbuf, wl->node_id);
    if (!sn || !wn || !sn->file_path || !wn->file_path) {
        return false;
    }
    k8s_member_t one_s[SKIP_ONE];
    k8s_member_t one_w[SKIP_ONE];
    k8s_members_t single_s = {.items = one_s, .cap = SKIP_ONE};
    k8s_members_t single_w = {.items = one_w, .cap = SKIP_ONE};
    const k8s_members_t *ms = k8s_bundles_of(b, sn->file_path, &single_s);
    const k8s_members_t *mw = k8s_bundles_of(b, wn->file_path, &single_w);
    for (int i = 0; i < ms->count; i++) {
        for (int j = 0; j < mw->count; j++) {
            if (ms->items[i].bundle != mw->items[j].bundle) {
                continue;
            }
            const char *ns_s = ms->items[i].ns ? ms->items[i].ns : svc->ns;
            const char *ns_w = mw->items[j].ns ? mw->items[j].ns : wl->ns;
            if (!ns_s[0] || !ns_w[0] || strcmp(ns_s, ns_w) == 0) {
                return true;
            }
        }
    }
    return false;
}

/* The declared namespace inside a Resource QN's key ("" when `-`). */
static void k8s_declared_ns(const char *qn, char *out, size_t out_sz) {
    out[0] = '\0';
    const char *key = qn ? strstr(qn, "::") : NULL;
    const char *p = key ? key + K8S_SLEN("::") : NULL;
    for (int part = 0; p && part < PAIR_LEN; part++) {
        p = strchr(p, '/');
        p = p ? p + SKIP_ONE : NULL;
    }
    const char *end = p ? strchr(p, '/') : NULL;
    if (end && !(end - p == SKIP_ONE && p[0] == '-')) {
        snprintf(out, out_sz, "%.*s", (int)(end - p), p);
    }
}

/* Objects a kustomize build deploys live in the namespace it gives them:
 * when every bundle of the file agrees on one, that is the namespace of
 * the object's logical key; bundles that disagree leave it to the deploy. */
static void k8s_apply_effective_namespaces(cbm_pipeline_ctx_t *ctx, k8s_bundles_t *b) {
    const cbm_gbuf_node_t **nodes = NULL;
    int count = 0;
    if (!b->members || cbm_gbuf_find_by_label(ctx->gbuf, "Resource", &nodes, &count) != 0) {
        return;
    }
    for (int i = 0; i < count; i++) {
        const cbm_gbuf_node_t *n = nodes[i];
        const k8s_members_t *m = n->file_path ? cbm_ht_get(b->members, n->file_path) : NULL;
        if (!m || m->count == 0) {
            continue;
        }
        char declared[K8S_LABEL_LEN];
        k8s_declared_ns(n->qualified_name, declared, sizeof(declared));
        const char *eff = NULL;
        bool agree = true;
        bool any_set = false;
        for (int j = 0; j < m->count; j++) {
            const char *v = m->items[j].ns ? m->items[j].ns : declared;
            any_set = any_set || m->items[j].ns;
            if (!v[0] || (eff && strcmp(eff, v) != 0)) {
                agree = false;
            }
            eff = eff ? eff : v;
        }
        if (!any_set) {
            continue; /* no build sets a namespace: the declared one stands */
        }
        char *props = k8s_resource_props(n->qualified_name, agree ? eff : "?");
        if (props) {
            (void)cbm_gbuf_node_set_properties_json((cbm_gbuf_node_t *)n, props);
            cbm_free(CBM_MEM_CLASS_OTHER, props);
        }
    }
}

/* ── Object references (PHASE1.md) ───────────────────────────────── */

/* A reference fact of a manifest, kept past its file's extraction. */
typedef struct {
    int64_t src;      /* the referencing Resource */
    char *kind;       /* target kind */
    char *ns;         /* explicit target namespace, NULL = the source's */
    char *name;       /* target metadata.name */
    const char *via;  /* static: the extractor's table */
    const char *edge; /* static: "USAGE" or "INFRA_MAPS" */
} k8s_ref_t;

/* A CRD and the group/kind it declares. */
typedef struct {
    int64_t node;
    char *group;
    char *kind;
} k8s_crd_t;

typedef struct {
    k8s_ref_t *refs;
    int ref_n;
    int ref_cap;
    k8s_crd_t *crds;
    int crd_n;
    int crd_cap;
} k8s_facts_t;

static void k8s_facts_free(k8s_facts_t *f) {
    for (int i = 0; i < f->ref_n; i++) {
        cbm_free(CBM_MEM_CLASS_OTHER, f->refs[i].kind);
        cbm_free(CBM_MEM_CLASS_OTHER, f->refs[i].ns);
        cbm_free(CBM_MEM_CLASS_OTHER, f->refs[i].name);
    }
    for (int i = 0; i < f->crd_n; i++) {
        cbm_free(CBM_MEM_CLASS_OTHER, f->crds[i].group);
        cbm_free(CBM_MEM_CLASS_OTHER, f->crds[i].kind);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, f->refs);
    cbm_free(CBM_MEM_CLASS_OTHER, f->crds);
    *f = (k8s_facts_t){0};
}

/* Keep a file's facts, its def indices mapped to the Resource nodes. */
static void k8s_facts_keep(k8s_facts_t *f, const CBMFileResult *res, const int64_t *node_of) {
    for (int i = 0; i < res->k8s_facts.count; i++) {
        const CBMK8sFact *x = &res->k8s_facts.items[i];
        if (x->def_index < 0 || x->def_index >= res->defs.count || node_of[x->def_index] <= 0) {
            continue;
        }
        int64_t node = node_of[x->def_index];
        if (x->fact == CBM_K8S_FACT_CRD) {
            if (k8s_grow((void **)&f->crds, &f->crd_cap, f->crd_n, sizeof(*f->crds))) {
                f->crds[f->crd_n++] =
                    (k8s_crd_t){node, cbm_mem_strdup(CBM_MEM_CLASS_OTHER, x->name),
                                cbm_mem_strdup(CBM_MEM_CLASS_OTHER, x->kind)};
            }
        } else if (k8s_grow((void **)&f->refs, &f->ref_cap, f->ref_n, sizeof(*f->refs))) {
            f->refs[f->ref_n++] =
                (k8s_ref_t){.src = node,
                            .kind = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, x->kind),
                            .ns = x->ns ? cbm_mem_strdup(CBM_MEM_CLASS_OTHER, x->ns) : NULL,
                            .name = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, x->name),
                            .via = x->via,
                            .edge = x->edge};
        }
    }
}

/* Does the target at `tgt` answer `ref` from `src`: one bundle, and the
 * namespace the reference asks for (explicit, else the source's own there)
 * agrees with the target's there? A cluster-scoped kind has no namespace. */
static bool k8s_ref_meets(k8s_bundles_t *b, const k8s_ref_t *ref, const cbm_gbuf_node_t *src,
                          const cbm_gbuf_node_t *tgt) {
    k8s_member_t one_s[SKIP_ONE];
    k8s_member_t one_t[SKIP_ONE];
    k8s_members_t single_s = {.items = one_s, .cap = SKIP_ONE};
    k8s_members_t single_t = {.items = one_t, .cap = SKIP_ONE};
    const k8s_members_t *ms = k8s_bundles_of(b, src->file_path, &single_s);
    const k8s_members_t *mt = k8s_bundles_of(b, tgt->file_path, &single_t);
    char src_ns[K8S_LABEL_LEN];
    char tgt_ns[K8S_LABEL_LEN];
    k8s_declared_ns(src->qualified_name, src_ns, sizeof(src_ns));
    k8s_declared_ns(tgt->qualified_name, tgt_ns, sizeof(tgt_ns));
    bool cluster = k8s_cluster_scoped(ref->kind);
    for (int i = 0; i < ms->count; i++) {
        for (int j = 0; j < mt->count; j++) {
            if (ms->items[i].bundle != mt->items[j].bundle) {
                continue;
            }
            const char *want = ref->ns ? ref->ns : ms->items[i].ns ? ms->items[i].ns : src_ns;
            const char *have = mt->items[j].ns ? mt->items[j].ns : tgt_ns;
            if (cluster || !want[0] || !have[0] || strcmp(want, have) == 0) {
                return true;
            }
        }
    }
    return false;
}

/* Draw every reference to the object(s) it names inside its bundle;
 * an unresolved reference draws nothing. */
static void k8s_resolve_refs(cbm_pipeline_ctx_t *ctx, k8s_bundles_t *b, const k8s_facts_t *f) {
    int edges = 0;
    int unresolved = 0;
    for (int i = 0; i < f->ref_n; i++) {
        const k8s_ref_t *ref = &f->refs[i];
        const cbm_gbuf_node_t *src = cbm_gbuf_find_by_id(ctx->gbuf, ref->src);
        char name[CBM_SZ_1K];
        snprintf(name, sizeof(name), "%s/%s", ref->kind, ref->name);
        const cbm_gbuf_node_t **cands = NULL;
        int n = 0;
        if (!src || !src->file_path || cbm_gbuf_find_by_name(ctx->gbuf, name, &cands, &n) != 0) {
            n = 0;
        }
        char props[CBM_SZ_256];
        snprintf(props, sizeof(props), "{\"%s\":\"%s\"}",
                 strcmp(ref->edge, "INFRA_MAPS") == 0 ? "kind" : "ref", ref->via);
        /* A name is one object per kind and namespace, so two declarations
         * of it in one bundle are alternatives (versioned manifests side by
         * side): the declaration in the reference's own file, when there is
         * one, is the one it means. */
        bool own_file = false;
        for (int c = 0; c < n && !own_file; c++) {
            const cbm_gbuf_node_t *t = cands[c];
            own_file = t != src && t->label && strcmp(t->label, "Resource") == 0 && t->file_path &&
                       strcmp(t->file_path, src->file_path) == 0 && k8s_ref_meets(b, ref, src, t);
        }
        int hits = 0;
        for (int c = 0; c < n; c++) {
            const cbm_gbuf_node_t *t = cands[c];
            if (t == src || !t->label || strcmp(t->label, "Resource") != 0 || !t->file_path ||
                (own_file && strcmp(t->file_path, src->file_path) != 0) ||
                !k8s_ref_meets(b, ref, src, t)) {
                continue;
            }
            cbm_gbuf_insert_edge(ctx->gbuf, src->id, t->id, ref->edge, props);
            hits++;
        }
        edges += hits;
        unresolved += hits == 0;
    }
    if (f->ref_n > 0) {
        cbm_log_info("pass.k8s.refs", "refs", itoa_k8s(f->ref_n), "edges", itoa_k8s(edges),
                     "unresolved", itoa_k8s(unresolved));
    }
}

/* A CRD's group/kind, for grouping the CRDs of one type. */
typedef struct {
    char key[CBM_SZ_512];
    int crd;
} k8s_crd_key_t;

static int k8s_cmp_crd_key(const void *a, const void *b) {
    const k8s_crd_key_t *x = a;
    const k8s_crd_key_t *y = b;
    int c = strcmp(x->key, y->key);
    return c ? c : (x->crd > y->crd) - (x->crd < y->crd);
}

/* Do the files at `a` and `b` share a bundle? */
static bool k8s_same_bundle(k8s_bundles_t *b, const char *a, const char *c) {
    k8s_member_t one_a[SKIP_ONE];
    k8s_member_t one_c[SKIP_ONE];
    k8s_members_t single_a = {.items = one_a, .cap = SKIP_ONE};
    k8s_members_t single_c = {.items = one_c, .cap = SKIP_ONE};
    const k8s_members_t *ma = k8s_bundles_of(b, a, &single_a);
    const k8s_members_t *mc = k8s_bundles_of(b, c, &single_c);
    for (int i = 0; i < ma->count; i++) {
        for (int j = 0; j < mc->count; j++) {
            if (ma->items[i].bundle == mc->items[j].bundle) {
                return true;
            }
        }
    }
    return false;
}

/* A custom resource is an instance of the CRD declaring its group and
 * kind. A CRD vendored in several places: the copy deployed with the
 * resource (one bundle) is the one; with no copy beside it, the resource
 * stands for all of them. */
static void k8s_link_crds(cbm_pipeline_ctx_t *ctx, k8s_bundles_t *b, const k8s_facts_t *f) {
    if (f->crd_n == 0) {
        return;
    }
    /* group/kind -> the run of its CRDs in `order` (sorted by group/kind), so
     * each resource visits only the CRDs of its own type. */
    k8s_crd_key_t *order = cbm_calloc(CBM_MEM_CLASS_OTHER, (size_t)f->crd_n * sizeof(*order));
    CBMHashTable *by_type = cbm_ht_create(0);
    if (!order || !by_type) {
        cbm_free(CBM_MEM_CLASS_OTHER, order);
        if (by_type) {
            cbm_ht_free(by_type);
        }
        return;
    }
    for (int i = 0; i < f->crd_n; i++) {
        snprintf(order[i].key, sizeof(order[i].key), "%s/%s", f->crds[i].group, f->crds[i].kind);
        order[i].crd = i;
    }
    qsort(order, (size_t)f->crd_n, sizeof(*order), k8s_cmp_crd_key);
    for (int i = f->crd_n - SKIP_ONE; i >= 0; i--) {
        cbm_ht_set(by_type, order[i].key, (void *)(intptr_t)(i + SKIP_ONE)); /* first of run */
    }
    const cbm_gbuf_node_t **nodes = NULL;
    int count = 0;
    int edges = 0;
    if (cbm_gbuf_find_by_label(ctx->gbuf, "Resource", &nodes, &count) == 0) {
        for (int i = 0; i < count; i++) {
            const char *key =
                nodes[i]->qualified_name ? strstr(nodes[i]->qualified_name, "::") : NULL;
            if (!key || !nodes[i]->file_path) {
                continue;
            }
            key += K8S_SLEN("::");
            const char *kind_end = strchr(key, '/');
            kind_end = kind_end ? strchr(kind_end + SKIP_ONE, '/') : NULL;
            if (!kind_end) {
                continue;
            }
            char type[CBM_SZ_512];
            snprintf(type, sizeof(type), "%.*s", (int)(kind_end - key), key);
            int first = (int)(intptr_t)cbm_ht_get(by_type, type) - SKIP_ONE;
            if (first < 0) {
                continue;
            }
            int end = first;
            while (end < f->crd_n && strcmp(order[end].key, type) == 0) {
                end++;
            }
            bool beside = false;
            for (int r = first; r < end && !beside; r++) {
                const cbm_gbuf_node_t *crd =
                    cbm_gbuf_find_by_id(ctx->gbuf, f->crds[order[r].crd].node);
                beside = crd && crd->file_path &&
                         k8s_same_bundle(b, nodes[i]->file_path, crd->file_path);
            }
            for (int r = first; r < end; r++) {
                int64_t crd_id = f->crds[order[r].crd].node;
                const cbm_gbuf_node_t *crd = cbm_gbuf_find_by_id(ctx->gbuf, crd_id);
                if (crd_id == nodes[i]->id ||
                    (beside && (!crd || !crd->file_path ||
                                !k8s_same_bundle(b, nodes[i]->file_path, crd->file_path)))) {
                    continue;
                }
                cbm_gbuf_insert_edge(ctx->gbuf, nodes[i]->id, crd_id, "USAGE", "{\"ref\":\"crd\"}");
                edges++;
            }
        }
    }
    cbm_ht_free(by_type);
    cbm_free(CBM_MEM_CLASS_OTHER, order);
    if (edges > 0) {
        cbm_log_info("pass.k8s.crds", "instances", itoa_k8s(edges));
    }
}

/* Connect each Service to the workloads its selector targets via an INFRA_MAPS
 * edge (Service Resource → workload Resource), inside a shared bundle. */
static void k8s_link_selectors(cbm_pipeline_ctx_t *ctx, const k8s_record_array_t *recs,
                               k8s_bundles_t *bundles) {
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
            bool all = k8s_share_bundle(bundles, ctx, svc, wl);
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
 * must free after this call returns). Every Resource's own document is
 * recorded in `recs` for cross-manifest selector matching. */
static void handle_k8s_manifest(cbm_pipeline_ctx_t *ctx, const char *rel_path, const char *source,
                                const CBMFileResult *res, k8s_record_array_t *recs,
                                k8s_facts_t *facts) {
    int resource_count = 0;

    if (!res) {
        return;
    }

    /* Compute file node QN for DEFINES edges */
    char *file_qn = cbm_pipeline_fqn_compute(ctx->project_name, rel_path, "__file__");
    const cbm_gbuf_node_t *file_node = file_qn ? cbm_gbuf_find_by_qn(ctx->gbuf, file_qn) : NULL;
    free(file_qn);

    int64_t *node_of =
        cbm_calloc(CBM_MEM_CLASS_OTHER,
                   (size_t)(res->defs.count ? res->defs.count : SKIP_ONE) * sizeof(int64_t));
    for (int d = 0; d < res->defs.count; d++) {
        CBMDefinition *def = &res->defs.items[d];
        if (!def->label || strcmp(def->label, "Resource") != 0) {
            continue;
        }
        if (!def->name || !def->qualified_name) {
            continue;
        }

        char *props = k8s_resource_props(def->qualified_name, NULL);
        int64_t node_id = cbm_gbuf_upsert_node(
            ctx->gbuf, "Resource", def->name, def->qualified_name, rel_path, (int)def->start_line,
            (int)def->end_line, props ? props : "{\"source\":\"k8s\"}");
        cbm_free(CBM_MEM_CLASS_OTHER, props);

        /* DEFINES edge: File → Resource */
        if (file_node && node_id > 0) {
            cbm_gbuf_insert_edge(ctx->gbuf, file_node->id, node_id, "DEFINES", "{}");
        }

        /* Record its selector / pod-label pairs for Service → workload linking. */
        if (node_id > 0 && source) {
            k8s_record_document(recs, node_id, source, (int)def->start_line, (int)def->end_line);
        }
        if (node_of) {
            node_of[d] = node_id;
        }

        resource_count++;
    }
    if (node_of) {
        k8s_facts_keep(facts, res, node_of);
        cbm_free(CBM_MEM_CLASS_OTHER, node_of);
    }

    cbm_log_info("pass.k8s.manifest", "file", rel_path, "resources", itoa_k8s(resource_count));
}

/* ── Helm chart handler ──────────────────────────────────────────── */

static bool is_helm_chart_file(const char *base) {
    return strcmp(base, "Chart.yaml") == 0 || strcmp(base, "Chart.yml") == 0;
}

/* A chart's `file://` dependency: the chart in that directory of this
 * repository. Linked once every Chart.yaml has been read, so a dependency
 * indexed after its dependent still resolves. One that names no chart of this
 * repository (an absolute build-container path, a directory without a chart)
 * stays a declared dependency on the external node, like a remote one. */
typedef struct {
    int64_t chart_id;
    char name[CBM_HELM_NAME_MAX]; /* dependency name, for the external fallback */
    char *chart_rel;              /* the depending Chart.yaml */
    char *target_qn;              /* QN of the depended-on Chart node; NULL = unresolvable */
    char *props;                  /* edge properties */
} k8s_local_dep_t;

typedef struct {
    k8s_local_dep_t *items;
    int count;
    int cap;
} k8s_local_deps_t;

static bool k8s_is_file_repository(const char *repository) {
    return strncmp(repository, "file://", K8S_SLEN("file://")) == 0;
}

static char *k8s_dep_props(const char *repository) {
    char escaped[CBM_HELM_REPO_MAX * 2];
    cbm_json_escape(escaped, (int)sizeof(escaped), repository);
    size_t n = strlen(escaped) + sizeof("{\"repository\":\"\"}");
    char *props = cbm_alloc(CBM_MEM_CLASS_OTHER, n);
    if (props) {
        snprintf(props, n, "{\"repository\":\"%s\"}", escaped);
    }
    return props;
}

/* DEPENDS_ON from `chart_id` to the shared external Chart node of `name`
 * (one per name and project, so charts depending on the same chart meet). */
static bool k8s_external_dep(cbm_pipeline_ctx_t *ctx, int64_t chart_id, const char *name,
                             const char *chart_rel, const char *props) {
    char dep_qn[CBM_SZ_512];
    snprintf(dep_qn, sizeof(dep_qn), "%s.__helm_dep__.%s", ctx->project_name, name);
    int64_t dep_id = cbm_gbuf_upsert_node(ctx->gbuf, "Chart", name, dep_qn, chart_rel, SKIP_ONE, 0,
                                          "{\"source\":\"helm\",\"external\":true}");
    if (dep_id <= 0) {
        return false;
    }
    cbm_gbuf_insert_edge(ctx->gbuf, chart_id, dep_id, "DEPENDS_ON", props ? props : "{}");
    return true;
}

/* QN of the chart a relative `file://` directory names, core-owned; NULL for
 * an absolute path (it names the build host, not this repo). */
static char *k8s_local_chart_qn(const char *project, const char *chart_rel, const char *dir) {
    if (!dir[0] || dir[0] == '/') {
        return NULL;
    }
    char rel[CBM_HELM_REPO_MAX + K8S_SLEN("./") + K8S_SLEN("/Chart.yaml")];
    snprintf(rel, sizeof(rel), "%s%s/Chart.yaml", strncmp(dir, "../", 3) == 0 ? "" : "./", dir);
    /* fqn.c hands out libc-allocated strings: copy into the core, release them. */
    char *path = cbm_pipeline_resolve_relative_import(chart_rel, rel);
    char *qn = path ? cbm_infra_qn(project, path, "helm-chart", NULL) : NULL;
    free(path);
    char *owned = qn ? cbm_mem_strdup(CBM_MEM_CLASS_OTHER, qn) : NULL;
    free(qn);
    return owned;
}

static void k8s_local_deps_push(k8s_local_deps_t *deps, int64_t chart_id, const char *chart_rel,
                                const char *project, const cbm_helm_dep_t *dep) {
    if (deps->count == deps->cap) {
        int cap = deps->cap ? deps->cap * 2 : K8S_GROW_MIN;
        k8s_local_dep_t *grown =
            cbm_realloc(CBM_MEM_CLASS_OTHER, deps->items, (size_t)cap * sizeof(*grown));
        if (!grown) {
            return;
        }
        deps->items = grown;
        deps->cap = cap;
    }
    k8s_local_dep_t *d = &deps->items[deps->count++];
    *d = (k8s_local_dep_t){.chart_id = chart_id};
    d->target_qn = k8s_local_chart_qn(project, chart_rel, dep->repository + K8S_SLEN("file://"));
    snprintf(d->name, sizeof(d->name), "%s", dep->name);
    d->chart_rel = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, chart_rel);
    d->props = k8s_dep_props(dep->repository);
}

static void k8s_local_deps_free(k8s_local_deps_t *deps) {
    for (int i = 0; i < deps->count; i++) {
        cbm_free(CBM_MEM_CLASS_OTHER, deps->items[i].target_qn);
        cbm_free(CBM_MEM_CLASS_OTHER, deps->items[i].chart_rel);
        cbm_free(CBM_MEM_CLASS_OTHER, deps->items[i].props);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, deps->items);
    *deps = (k8s_local_deps_t){0};
}

static void k8s_link_local_deps(cbm_pipeline_ctx_t *ctx, k8s_local_deps_t *deps) {
    for (int i = 0; i < deps->count; i++) {
        const k8s_local_dep_t *d = &deps->items[i];
        const cbm_gbuf_node_t *target =
            d->target_qn ? cbm_gbuf_find_by_qn(ctx->gbuf, d->target_qn) : NULL;
        if (target && target->label && strcmp(target->label, "Chart") == 0 &&
            target->id != d->chart_id) {
            cbm_gbuf_insert_edge(ctx->gbuf, d->chart_id, target->id, "DEPENDS_ON", d->props);
        } else if (d->chart_rel) {
            (void)k8s_external_dep(ctx, d->chart_id, d->name, d->chart_rel, d->props);
        }
    }
    k8s_local_deps_free(deps);
}

/* Emit a Chart node for a Chart.yaml and a DEPENDS_ON edge per declared
 * dependency (#338): to the chart in this repository for a resolvable
 * `file://` dependency (once all charts are read), otherwise to a shared
 * external Chart node per dependency name, the repository on the edge. */
static void handle_helm_chart(cbm_pipeline_ctx_t *ctx, const char *rel_path, const char *source,
                              k8s_local_deps_t *local_deps) {
    cbm_helm_chart_t hc;
    if (cbm_parse_helm_chart(source, &hc) != 0) {
        cbm_helm_chart_free(&hc);
        return;
    }

    const char *cname = hc.chart_name[0] ? hc.chart_name : k8s_basename(rel_path);
    char *chart_qn = cbm_infra_qn(ctx->project_name, rel_path, "helm-chart", NULL);
    if (!chart_qn) {
        cbm_helm_chart_free(&hc);
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
        const cbm_helm_dep_t *dep = &hc.deps[i];
        if (k8s_is_file_repository(dep->repository)) {
            k8s_local_deps_push(local_deps, chart_id, rel_path, ctx->project_name, dep);
            continue;
        }
        char *props = dep->repository[0] ? k8s_dep_props(dep->repository) : NULL;
        dep_edges += k8s_external_dep(ctx, chart_id, dep->name, rel_path, props);
        cbm_free(CBM_MEM_CLASS_OTHER, props);
    }
    cbm_helm_chart_free(&hc);
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
typedef enum { K8S_SKIP = 0, K8S_DEP, K8S_HELM, K8S_MANIFEST, K8S_KUSTOMIZE } k8s_kind_t;

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
    } else if (lang == CBM_LANG_KUSTOMIZE) {
        /* Its `namespace:` is the namespace of the objects it builds. */
        out->source = k8s_read_file(path, &out->src_len);
        out->kind = out->source ? K8S_KUSTOMIZE : K8S_SKIP;
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
    k8s_local_deps_t local_deps = {0};
    k8s_kusts_t kusts = {0};
    k8s_bundles_t bundles = {.charts = cbm_ht_create(0)};
    k8s_facts_t facts = {0};

    k8s_prep_t *prep = cbm_calloc(CBM_MEM_CLASS_OTHER, K8S_CHUNK * sizeof(*prep));
    if (!prep) {
        k8s_bundles_free(&bundles);
        return CBM_NOT_FOUND;
    }
    int workers = cbm_default_worker_count(false);

    for (int begin = 0; begin < file_count; begin += K8S_CHUNK) {
        int end = begin + K8S_CHUNK < file_count ? begin + K8S_CHUNK : file_count;
        if (cbm_pipeline_check_cancel(ctx)) {
            cbm_free(CBM_MEM_CLASS_OTHER, prep);
            k8s_records_free(&recs);
            k8s_local_deps_free(&local_deps);
            k8s_kusts_free(&kusts);
            k8s_bundles_free(&bundles);
            k8s_facts_free(&facts);
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
                    handle_helm_chart(ctx, rel, p->source, &local_deps);
                    k8s_chart_dir_add(&bundles, rel);
                    helm_count++;
                    break;
                case K8S_KUSTOMIZE:
                    k8s_kusts_push(&kusts, rel, k8s_kustomize_namespace(p->source));
                    break;
                case K8S_MANIFEST:
                    handle_k8s_manifest(ctx, rel, p->source, p->res, &recs, &facts);
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
            k8s_local_deps_free(&local_deps);
            k8s_kusts_free(&kusts);
            k8s_bundles_free(&bundles);
            k8s_facts_free(&facts);
            return CBM_NOT_FOUND;
        }
    }
    cbm_free(CBM_MEM_CLASS_OTHER, prep);

    /* Connect Services to the workloads their selectors target (INFRA_MAPS),
     * inside the bundles that deploy them together. */
    k8s_bundles_build(ctx, &kusts, &bundles);
    k8s_apply_effective_namespaces(ctx, &bundles);
    k8s_link_selectors(ctx, &recs, &bundles);
    k8s_resolve_refs(ctx, &bundles, &facts);
    k8s_link_crds(ctx, &bundles, &facts);
    k8s_facts_free(&facts);
    k8s_records_free(&recs);
    k8s_bundles_free(&bundles);
    k8s_kusts_free(&kusts);
    /* Link `file://` chart dependencies now that every Chart.yaml is read. */
    k8s_link_local_deps(ctx, &local_deps);

    cbm_log_info("pass.done", "pass", "k8s", "manifests", itoa_k8s(manifest_count));
    (void)helm_count;
    return 0;
}
