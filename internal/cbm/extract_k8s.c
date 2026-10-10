// extract_k8s.c — K8s manifest and Kustomize file extractor.
//
// For CBM_LANG_KUSTOMIZE: walks top-level block_mapping_pair nodes whose key
// matches "resources", "bases", "patches", "components", or
// "patchesStrategicMerge", then emits one CBMImport per block_sequence item.
//
// For CBM_LANG_K8S: reads apiVersion, kind, metadata.name and
// metadata.namespace of EVERY document and emits one CBMDefinition per object:
// label "Resource", name "Kind/metadata-name", QN
// "<file-base>::<group>/<Kind>/<declared namespace or ->/<name>" (identity
// spec: the file base keeps the extension, so it is unique per file).

#include "cbm.h"
#include "arena.h"
#include "helpers.h"
#include "tree_sitter/api.h"
#include "foundation/constants.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Local constants. */
enum {
    K8S_BUF_SIZE = 256,
};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// The value inside a flow_node: its first named child that is not an anchor
// (`&name`), a tag (`!!str`) or a comment, all of which precede the value.
static TSNode flow_node_value(TSNode node) {
    uint32_t n = ts_node_named_child_count(node);
    for (uint32_t i = 0; i < n; i++) {
        TSNode child = ts_node_named_child(node, i);
        const char *type = ts_node_type(child);
        if (strcmp(type, "anchor") != 0 && strcmp(type, "tag") != 0 &&
            strcmp(type, "comment") != 0) {
            return child;
        }
    }
    TSNode null_node = {0};
    return null_node;
}

// Return the raw source text for a scalar node (plain, single-quoted, or
// double-quoted). Surrounding quote characters are stripped for quoted forms.
// Handles flow_node wrappers transparently by descending into the value they
// wrap (the tree-sitter YAML grammar often wraps scalars in flow_node).
// Returns NULL for non-scalar node types.
static const char *get_scalar_text(CBMArena *a, TSNode node, const char *source) {
    enum { MAX_UNWRAP = 4 };
    for (int depth = 0; depth < MAX_UNWRAP; depth++) {
        const char *type = ts_node_type(node);
        if (strcmp(type, "flow_node") == 0) {
            TSNode inner = flow_node_value(node);
            if (ts_node_is_null(inner)) {
                return NULL;
            }
            node = inner;
            continue;
        }
        if (strcmp(type, "plain_scalar") == 0) {
            return cbm_node_text(a, node, source);
        }
        if (strcmp(type, "double_quote_scalar") == 0 || strcmp(type, "single_quote_scalar") == 0) {
            const char *raw = cbm_node_text(a, node, source);
            if (!raw) {
                return NULL;
            }
            size_t len = strlen(raw);
            if (len >= PAIR_LEN) {
                return cbm_arena_strndup(a, raw + SKIP_ONE, len - PAIR_LEN);
            }
            return raw;
        }
        break;
    }
    return NULL;
}

// Return true if the key text of a block_mapping_pair matches one of the
// Kustomize resource-list field names.
static int is_kustomize_list_key(const char *key) {
    return (strcmp(key, "resources") == 0 || strcmp(key, "bases") == 0 ||
            strcmp(key, "patches") == 0 || strcmp(key, "components") == 0 ||
            strcmp(key, "patchesStrategicMerge") == 0 || strcmp(key, "crds") == 0);
}

// ---------------------------------------------------------------------------
// Kustomize extraction
// ---------------------------------------------------------------------------

// Walk a block_sequence node and emit one CBMImport per block_sequence_item
// scalar child, using key_name as the local_name.
static void emit_kustomize_sequence(CBMExtractCtx *ctx, TSNode seq_node, const char *key_name) {
    CBMArena *a = ctx->arena;
    uint32_t n = ts_node_child_count(seq_node);
    for (uint32_t i = 0; i < n; i++) {
        TSNode item = ts_node_child(seq_node, i);
        if (strcmp(ts_node_type(item), "block_sequence_item") != 0) {
            continue;
        }
        // block_sequence_item has one named child: the value
        uint32_t ic = ts_node_child_count(item);
        for (uint32_t j = 0; j < ic; j++) {
            TSNode val = ts_node_child(item, j);
            const char *scalar = get_scalar_text(a, val, ctx->source);
            if (!scalar) {
                continue;
            }
            CBMImport imp = {
                .local_name = cbm_arena_strdup(a, key_name),
                .module_path = cbm_arena_strdup(a, scalar),
            };
            cbm_imports_push(&ctx->result->imports, a, imp);
        }
    }
}

// First named child that is not a comment. A comment between `---` and the
// mapping (the `# yaml-language-server: $schema=...` line editors add) is the
// document's first named child; the content follows it.
static TSNode first_content_child(TSNode node) {
    uint32_t n = ts_node_named_child_count(node);
    for (uint32_t i = 0; i < n; i++) {
        TSNode child = ts_node_named_child(node, i);
        if (strcmp(ts_node_type(child), "comment") != 0) {
            return child;
        }
    }
    TSNode null_node = {0};
    return null_node;
}

// Unwrap a YAML node through optional block_node wrapper to get block_mapping.
// Returns null node if not a block_mapping.
static TSNode unwrap_block_mapping(TSNode doc_child) {
    TSNode mapping = first_content_child(doc_child);
    if (ts_node_is_null(mapping)) {
        return mapping;
    }
    if (strcmp(ts_node_type(mapping), "block_node") == 0) {
        mapping = first_content_child(mapping);
    }
    if (ts_node_is_null(mapping) || strcmp(ts_node_type(mapping), "block_mapping") != 0) {
        TSNode null_node = {0};
        return null_node;
    }
    return mapping;
}

// Unwrap a block_mapping_pair value through optional block_node. Comments are
// skipped on both levels: one trailing the key line (`metadata: # note`) is a
// named child of the pair ahead of its value, and a commented-out first entry
// (`resources:` / `  # - a.yaml` / `  - b.yaml`) is the block_node's first
// named child, ahead of the sequence.
static TSNode unwrap_pair_value(TSNode pair) {
    TSNode val_node = {0};
    uint32_t n = ts_node_named_child_count(pair);
    for (uint32_t i = SKIP_ONE; i < n; i++) {
        TSNode child = ts_node_named_child(pair, i);
        if (strcmp(ts_node_type(child), "comment") != 0) {
            val_node = child;
            break;
        }
    }
    if (!ts_node_is_null(val_node) && strcmp(ts_node_type(val_node), "block_node") == 0) {
        val_node = first_content_child(val_node);
    }
    return val_node;
}

// Process a single block_mapping_pair for kustomize list keys.
static void process_kustomize_pair(CBMExtractCtx *ctx, TSNode pair) {
    if (strcmp(ts_node_type(pair), "block_mapping_pair") != 0) {
        return;
    }
    TSNode key_node = ts_node_named_child(pair, 0);
    if (ts_node_is_null(key_node)) {
        return;
    }
    const char *key_text = get_scalar_text(ctx->arena, key_node, ctx->source);
    if (!key_text || !is_kustomize_list_key(key_text)) {
        return;
    }

    TSNode val_node = unwrap_pair_value(pair);
    if (ts_node_is_null(val_node) || strcmp(ts_node_type(val_node), "block_sequence") != 0) {
        return;
    }
    emit_kustomize_sequence(ctx, val_node, key_text);
}

// Emit a "Class" def named after the document's `kind` scalar. A kustomization
// file has no metadata.name, so the def name is the bare kind ("Kustomization").
// Mirrors the K8s manifest kind-def so Kustomize resources are also discoverable.
static void emit_kustomize_kind_def(CBMExtractCtx *ctx, TSNode mapping) {
    CBMArena *a = ctx->arena;
    uint32_t pair_n = ts_node_child_count(mapping);
    for (uint32_t pi = 0; pi < pair_n; pi++) {
        TSNode pair = ts_node_child(mapping, pi);
        if (strcmp(ts_node_type(pair), "block_mapping_pair") != 0) {
            continue;
        }
        TSNode key_node = ts_node_named_child(pair, 0);
        if (ts_node_is_null(key_node)) {
            continue;
        }
        const char *key = get_scalar_text(a, key_node, ctx->source);
        if (!key || strcmp(key, "kind") != 0) {
            continue;
        }
        TSNode val_node = unwrap_pair_value(pair);
        if (ts_node_is_null(val_node)) {
            continue;
        }
        const char *kind = get_scalar_text(a, val_node, ctx->source);
        if (!kind || !kind[0]) {
            continue;
        }
        CBMDefinition def = {0};
        def.name = cbm_arena_strdup(a, kind);
        def.qualified_name = cbm_arena_sprintf(a, "%s.%s", ctx->module_qn, kind);
        def.label = cbm_arena_strdup(a, "Resource");
        def.file_path = ctx->rel_path;
        def.start_line = ts_node_start_point(mapping).row + TS_LINE_OFFSET;
        def.end_line = ts_node_end_point(mapping).row + TS_LINE_OFFSET;
        cbm_defs_push(&ctx->result->defs, a, def);
        return;
    }
}

static void extract_kustomize(CBMExtractCtx *ctx) {
    TSNode root = ctx->root;
    uint32_t root_n = ts_node_child_count(root);
    for (uint32_t si = 0; si < root_n; si++) {
        TSNode stream_child = ts_node_child(root, si);
        if (strcmp(ts_node_type(stream_child), "document") != 0) {
            continue;
        }
        TSNode mapping = unwrap_block_mapping(stream_child);
        if (ts_node_is_null(mapping)) {
            continue;
        }

        emit_kustomize_kind_def(ctx, mapping);

        uint32_t pair_n = ts_node_child_count(mapping);
        for (uint32_t pi = 0; pi < pair_n; pi++) {
            process_kustomize_pair(ctx, ts_node_child(mapping, pi));
        }
    }
}

// ---------------------------------------------------------------------------
// K8s manifest extraction
// ---------------------------------------------------------------------------

// The identity scalars of one manifest document.
typedef struct {
    char api_version[K8S_BUF_SIZE];
    char kind[K8S_BUF_SIZE];
    char name[K8S_BUF_SIZE];
    char ns[K8S_BUF_SIZE];
} k8s_doc_id_t;

// Read metadata.name and metadata.namespace from a metadata block_mapping.
static void extract_metadata(CBMArena *a, TSNode meta_mapping, const char *source,
                             k8s_doc_id_t *id) {
    if (ts_node_is_null(meta_mapping) || strcmp(ts_node_type(meta_mapping), "block_mapping") != 0) {
        return;
    }
    uint32_t mn = ts_node_child_count(meta_mapping);
    for (uint32_t mi = 0; mi < mn; mi++) {
        TSNode mpair = ts_node_child(meta_mapping, mi);
        if (strcmp(ts_node_type(mpair), "block_mapping_pair") != 0) {
            continue;
        }
        TSNode mkey = ts_node_named_child(mpair, 0);
        if (ts_node_is_null(mkey)) {
            continue;
        }
        const char *mkey_text = get_scalar_text(a, mkey, source);
        bool is_name = mkey_text && strcmp(mkey_text, "name") == 0;
        bool is_ns = mkey_text && strcmp(mkey_text, "namespace") == 0;
        if (!is_name && !is_ns) {
            continue;
        }
        TSNode mval = unwrap_pair_value(mpair);
        const char *text = ts_node_is_null(mval) ? NULL : get_scalar_text(a, mval, source);
        if (text) {
            snprintf(is_name ? id->name : id->ns, K8S_BUF_SIZE, "%s", text);
        }
    }
}

// Read apiVersion, kind and metadata from a document's top-level mapping.
static void extract_k8s_scalars(CBMExtractCtx *ctx, TSNode mapping, k8s_doc_id_t *id) {
    CBMArena *a = ctx->arena;
    uint32_t n = ts_node_child_count(mapping);
    for (uint32_t i = 0; i < n; i++) {
        TSNode pair = ts_node_child(mapping, i);
        if (strcmp(ts_node_type(pair), "block_mapping_pair") != 0) {
            continue;
        }
        TSNode key_node = ts_node_named_child(pair, 0);
        if (ts_node_is_null(key_node)) {
            continue;
        }
        const char *key = get_scalar_text(a, key_node, ctx->source);
        if (!key) {
            continue;
        }
        TSNode val_node = unwrap_pair_value(pair);
        if (ts_node_is_null(val_node)) {
            continue;
        }
        if (strcmp(key, "metadata") == 0) {
            extract_metadata(a, val_node, ctx->source, id);
            continue;
        }
        char *dst = strcmp(key, "kind") == 0         ? id->kind
                    : strcmp(key, "apiVersion") == 0 ? id->api_version
                                                     : NULL;
        const char *v = dst ? get_scalar_text(a, val_node, ctx->source) : NULL;
        if (v) {
            snprintf(dst, K8S_BUF_SIZE, "%s", v);
        }
    }
}

// ---------------------------------------------------------------------------
// Object references (PHASE1.md): facts the K8s pass resolves per bundle
// ---------------------------------------------------------------------------

// A reference held by a scalar at a path, relative to the pod spec, to a
// container, or (kinds) to the whole object.
typedef struct {
    const char *path;
    const char *kind;
    const char *via;
} k8s_leaf_ref_t;

typedef struct {
    const char *kinds; // "|A|B|" of the source kinds
    const char *path;
    const char *kind;
    const char *via;
    const char *edge;
} k8s_object_ref_t;

// A reference held by a mapping's kind/name/namespace fields.
typedef struct {
    const char *kinds;   // "|A|B|" of the source kinds
    const char *path;    // the mapping's path
    const char *kind;    // the target kind; NULL = the mapping's own `kind` field
    const char *allowed; // with kind NULL: "|A|" of the kinds that are objects
    const char *dflt;    // with kind NULL: the kind when the field is absent
    const char *via;
    const char *edge;
} k8s_mapping_ref_t;

static const k8s_leaf_ref_t k8s_pod_refs[] = {
    {"serviceAccountName", "ServiceAccount", "serviceAccountName"},
    {"serviceAccount", "ServiceAccount", "serviceAccountName"},
    {"priorityClassName", "PriorityClass", "priorityClassName"},
    {"imagePullSecrets[].name", "Secret", "imagePullSecrets"},
    {"volumes[].configMap.name", "ConfigMap", "volume"},
    {"volumes[].secret.secretName", "Secret", "volume"},
    {"volumes[].persistentVolumeClaim.claimName", "PersistentVolumeClaim", "volume"},
    {"volumes[].projected.sources[].configMap.name", "ConfigMap", "volume"},
    {"volumes[].projected.sources[].secret.name", "Secret", "volume"},
};

static const k8s_leaf_ref_t k8s_container_refs[] = {
    {"env[].valueFrom.configMapKeyRef.name", "ConfigMap", "env"},
    {"env[].valueFrom.secretKeyRef.name", "Secret", "env"},
    {"envFrom[].configMapRef.name", "ConfigMap", "envFrom"},
    {"envFrom[].secretRef.name", "Secret", "envFrom"},
};

static const k8s_object_ref_t k8s_object_refs[] = {
    {"|Ingress|", "spec.rules[].http.paths[].backend.service.name", "Service", "ingress",
     "INFRA_MAPS"},
    {"|Ingress|", "spec.defaultBackend.service.name", "Service", "ingress", "INFRA_MAPS"},
    {"|Ingress|", "spec.tls[].secretName", "Secret", "tls", "USAGE"},
    {"|Ingress|", "spec.ingressClassName", "IngressClass", "ingressClassName", "USAGE"},
    {"|StatefulSet|", "spec.serviceName", "Service", "serviceName", "USAGE"},
    {"|PersistentVolumeClaim|", "spec.storageClassName", "StorageClass", "storageClassName",
     "USAGE"},
};

static const k8s_mapping_ref_t k8s_mapping_refs[] = {
    {"|RoleBinding|ClusterRoleBinding|", "roleRef", NULL, "|Role|ClusterRole|", NULL, "roleRef",
     "USAGE"},
    {"|RoleBinding|ClusterRoleBinding|", "subjects[]", NULL, "|ServiceAccount|", NULL, "subject",
     "USAGE"},
    {"|HorizontalPodAutoscaler|", "spec.scaleTargetRef", NULL, NULL, NULL, "scaleTarget", "USAGE"},
    {"|ValidatingWebhookConfiguration|MutatingWebhookConfiguration|",
     "webhooks[].clientConfig.service", "Service", NULL, NULL, "webhook", "INFRA_MAPS"},
    {"|APIService|", "spec.service", "Service", NULL, NULL, "apiservice", "INFRA_MAPS"},
    {"|HTTPRoute|GRPCRoute|TCPRoute|TLSRoute|UDPRoute|", "spec.rules[].backendRefs[]", NULL, NULL,
     "Service", "route", "INFRA_MAPS"},
    {"|HTTPRoute|GRPCRoute|TCPRoute|TLSRoute|UDPRoute|", "spec.parentRefs[]", NULL, NULL, "Gateway",
     "parentRef", "USAGE"},
};

// Is `kind` one of the "|A|B|" list?
static bool k8s_kind_in(const char *list, const char *kind) {
    if (!list || !kind[0]) {
        return false;
    }
    size_t n = strlen(kind);
    for (const char *p = strstr(list, kind); p; p = strstr(p + SKIP_ONE, kind)) {
        if (p[-SKIP_ONE] == '|' && p[n] == '|') {
            return true;
        }
    }
    return false;
}

// Where a kind keeps its pod spec, "" for none.
static const char *k8s_pod_prefix(const char *kind) {
    if (strcmp(kind, "Pod") == 0) {
        return "spec";
    }
    if (strcmp(kind, "CronJob") == 0) {
        return "spec.jobTemplate.spec.template.spec";
    }
    if (k8s_kind_in("|Deployment|StatefulSet|DaemonSet|ReplicaSet|ReplicationController|Job|",
                    kind)) {
        return "spec.template.spec";
    }
    return "";
}

typedef struct {
    CBMExtractCtx *ctx;
    const char *kind; // the document's kind
    int def_index;
    char crd_group[K8S_BUF_SIZE];
    char crd_kind[K8S_BUF_SIZE];
} k8s_walk_t;

static void k8s_emit_ref(k8s_walk_t *w, const char *kind, const char *ns, const char *name,
                         const char *via, const char *edge) {
    if (!kind || !kind[0] || !name || !name[0] || strstr(name, "{{") || strstr(kind, "{{")) {
        return;
    }
    CBMArena *a = w->ctx->arena;
    CBMK8sFact f = {.fact = CBM_K8S_FACT_REF,
                    .def_index = w->def_index,
                    .kind = cbm_arena_strdup(a, kind),
                    .ns = ns && ns[0] && !strstr(ns, "{{") ? cbm_arena_strdup(a, ns) : NULL,
                    .name = cbm_arena_strdup(a, name),
                    .via = via,
                    .edge = edge};
    cbm_k8sfact_push(&w->ctx->result->k8s_facts, a, f);
}

// A scalar at `path`: a leaf reference, or a CRD's group / kind.
static void k8s_leaf(k8s_walk_t *w, const char *path, const char *value) {
    const char *pod = k8s_pod_prefix(w->kind);
    size_t pl = strlen(pod);
    if (pl && strncmp(path, pod, pl) == 0 && path[pl] == '.') {
        const char *rel = path + pl + SKIP_ONE;
        for (size_t i = 0; i < sizeof(k8s_pod_refs) / sizeof(k8s_pod_refs[0]); i++) {
            if (strcmp(rel, k8s_pod_refs[i].path) == 0) {
                k8s_emit_ref(w, k8s_pod_refs[i].kind, NULL, value, k8s_pod_refs[i].via, "USAGE");
            }
        }
        static const char *const holders[] = {"containers[].", "initContainers[].",
                                              "ephemeralContainers[]."};
        for (size_t h = 0; h < sizeof(holders) / sizeof(holders[0]); h++) {
            size_t hl = strlen(holders[h]);
            if (strncmp(rel, holders[h], hl) != 0) {
                continue;
            }
            for (size_t i = 0; i < sizeof(k8s_container_refs) / sizeof(k8s_container_refs[0]);
                 i++) {
                if (strcmp(rel + hl, k8s_container_refs[i].path) == 0) {
                    k8s_emit_ref(w, k8s_container_refs[i].kind, NULL, value,
                                 k8s_container_refs[i].via, "USAGE");
                }
            }
        }
    }
    for (size_t i = 0; i < sizeof(k8s_object_refs) / sizeof(k8s_object_refs[0]); i++) {
        const k8s_object_ref_t *r = &k8s_object_refs[i];
        if (k8s_kind_in(r->kinds, w->kind) && strcmp(path, r->path) == 0) {
            k8s_emit_ref(w, r->kind, NULL, value, r->via, r->edge);
        }
    }
    if (strcmp(w->kind, "CustomResourceDefinition") == 0) {
        if (strcmp(path, "spec.group") == 0) {
            snprintf(w->crd_group, sizeof(w->crd_group), "%s", value);
        } else if (strcmp(path, "spec.names.kind") == 0) {
            snprintf(w->crd_kind, sizeof(w->crd_kind), "%s", value);
        }
    }
}

// Through block_node / flow_node wrappers to the content node.
static TSNode k8s_unwrap(TSNode node) {
    for (int i = 0; i < PAIR_LEN && !ts_node_is_null(node); i++) {
        const char *t = ts_node_type(node);
        if (strcmp(t, "block_node") == 0) {
            node = first_content_child(node);
        } else if (strcmp(t, "flow_node") == 0) {
            node = flow_node_value(node);
        } else {
            break;
        }
    }
    return node;
}

static bool k8s_is_mapping(TSNode n) {
    const char *t = ts_node_type(n);
    return strcmp(t, "block_mapping") == 0 || strcmp(t, "flow_mapping") == 0;
}

static bool k8s_is_pair(TSNode n) {
    const char *t = ts_node_type(n);
    return strcmp(t, "block_mapping_pair") == 0 || strcmp(t, "flow_pair") == 0;
}

// The scalar value of `field` in a mapping, or NULL.
static const char *k8s_field(k8s_walk_t *w, TSNode mapping, const char *field) {
    uint32_t n = ts_node_named_child_count(mapping);
    for (uint32_t i = 0; i < n; i++) {
        TSNode pair = ts_node_named_child(mapping, i);
        if (!k8s_is_pair(pair)) {
            continue;
        }
        TSNode key = ts_node_named_child(pair, 0);
        const char *k =
            ts_node_is_null(key) ? NULL : get_scalar_text(w->ctx->arena, key, w->ctx->source);
        if (k && strcmp(k, field) == 0) {
            TSNode v = unwrap_pair_value(pair);
            return ts_node_is_null(v) ? NULL : get_scalar_text(w->ctx->arena, v, w->ctx->source);
        }
    }
    return NULL;
}

// A mapping at `path` that holds a reference in its kind/name/namespace.
static void k8s_mapping(k8s_walk_t *w, const char *path, TSNode mapping) {
    for (size_t i = 0; i < sizeof(k8s_mapping_refs) / sizeof(k8s_mapping_refs[0]); i++) {
        const k8s_mapping_ref_t *r = &k8s_mapping_refs[i];
        if (!k8s_kind_in(r->kinds, w->kind) || strcmp(path, r->path) != 0) {
            continue;
        }
        const char *kind = r->kind;
        if (!kind) {
            kind = k8s_field(w, mapping, "kind");
            kind = kind ? kind : r->dflt;
            if (!kind || (r->allowed && !k8s_kind_in(r->allowed, kind))) {
                continue;
            }
        }
        k8s_emit_ref(w, kind, k8s_field(w, mapping, "namespace"), k8s_field(w, mapping, "name"),
                     r->via, r->edge);
    }
}

// Walk `node` (reached at `path`) for references.
static void k8s_walk(k8s_walk_t *w, TSNode node, char *path, size_t len, size_t cap) {
    node = k8s_unwrap(node);
    if (ts_node_is_null(node)) {
        return;
    }
    const char *type = ts_node_type(node);
    if (k8s_is_mapping(node)) {
        k8s_mapping(w, path, node);
        uint32_t n = ts_node_named_child_count(node);
        for (uint32_t i = 0; i < n; i++) {
            TSNode pair = ts_node_named_child(node, i);
            if (!k8s_is_pair(pair)) {
                continue;
            }
            TSNode key = ts_node_named_child(pair, 0);
            const char *k =
                ts_node_is_null(key) ? NULL : get_scalar_text(w->ctx->arena, key, w->ctx->source);
            int add = k ? snprintf(path + len, cap - len, "%s%s", len ? "." : "", k) : -1;
            if (add <= 0 || len + (size_t)add >= cap) {
                path[len] = '\0'; // a path too long for any reference path: not one
                continue;
            }
            TSNode value = unwrap_pair_value(pair);
            TSNode inner = k8s_unwrap(value);
            const char *scalar = ts_node_is_null(inner)
                                     ? NULL
                                     : get_scalar_text(w->ctx->arena, inner, w->ctx->source);
            if (scalar) {
                k8s_leaf(w, path, scalar);
            } else if (!ts_node_is_null(value)) {
                k8s_walk(w, value, path, len + (size_t)add, cap);
            }
            path[len] = '\0';
        }
        return;
    }
    if (strcmp(type, "block_sequence") == 0 || strcmp(type, "flow_sequence") == 0) {
        int add = snprintf(path + len, cap - len, "[]");
        if (add <= 0 || len + (size_t)add >= cap) {
            path[len] = '\0';
            return;
        }
        uint32_t n = ts_node_named_child_count(node);
        for (uint32_t i = 0; i < n; i++) {
            TSNode item = ts_node_named_child(node, i);
            if (strcmp(ts_node_type(item), "block_sequence_item") == 0) {
                item = first_content_child(item);
            }
            if (!ts_node_is_null(item) && strcmp(ts_node_type(item), "comment") != 0) {
                k8s_walk(w, item, path, len + (size_t)add, cap);
            }
        }
        path[len] = '\0';
    }
}

// The references and CRD declaration of document def `def_index`.
static void k8s_emit_facts(CBMExtractCtx *ctx, TSNode mapping, const char *kind, int def_index) {
    k8s_walk_t w = {.ctx = ctx, .kind = kind, .def_index = def_index};
    char path[CBM_SZ_512] = "";
    k8s_walk(&w, mapping, path, 0, sizeof(path));
    if (w.crd_group[0] && w.crd_kind[0]) {
        CBMK8sFact f = {.fact = CBM_K8S_FACT_CRD,
                        .def_index = def_index,
                        .kind = cbm_arena_strdup(ctx->arena, w.crd_kind),
                        .name = cbm_arena_strdup(ctx->arena, w.crd_group)};
        cbm_k8sfact_push(&ctx->result->k8s_facts, ctx->arena, f);
    }
}

// "<project>.<rel_path segments>" with the extension kept: the File node's QN
// without ".__file__" (IDENTITY.md). Unique per file, unlike the module QN,
// which drops the extension (`a.yaml` / `a.yml`, `x/` / `x.yaml`).
static const char *k8s_file_base(CBMArena *a, const char *project, const char *rel_path) {
    project = project ? project : "";
    rel_path = rel_path ? rel_path : "";
    size_t plen = strlen(project);
    char *buf = cbm_arena_alloc(a, plen + strlen(rel_path) + PAIR_LEN);
    if (!buf) {
        return NULL;
    }
    char *o = buf;
    memcpy(o, project, plen);
    o += plen;
    bool seg_start = true;
    for (const char *p = rel_path; *p; p++) {
        char c = *p == '\\' ? '/' : *p;
        if (c == '/') {
            seg_start = true;
            continue;
        }
        if (seg_start) {
            *o++ = '.';
            seg_start = false;
        }
        *o++ = c;
    }
    *o = '\0';
    return buf;
}

// The API group of an apiVersion: the part before '/', "core" for the core
// group ("v1"), "?" when the document names none. The version is not part of
// an object's identity.
static void k8s_api_group(const char *api_version, char *out, size_t out_sz) {
    const char *slash = strchr(api_version, '/');
    if (slash) {
        snprintf(out, out_sz, "%.*s", (int)(slash - api_version), api_version);
    } else {
        snprintf(out, out_sz, "%s", api_version[0] ? "core" : "?");
    }
}

// One Resource def per document: `Kind/name`, QN
// `<file-base>::<group>/<Kind>/<declared namespace or ->/<name>` (IDENTITY.md).
static void extract_k8s_manifest(CBMExtractCtx *ctx) {
    CBMArena *a = ctx->arena;
    const char *base = k8s_file_base(a, ctx->project, ctx->rel_path);
    if (!base) {
        return;
    }

    TSNode root = ctx->root;
    uint32_t root_n = ts_node_child_count(root);
    for (uint32_t si = 0; si < root_n; si++) {
        TSNode stream_child = ts_node_child(root, si);
        if (strcmp(ts_node_type(stream_child), "document") != 0) {
            continue;
        }

        TSNode mapping = unwrap_block_mapping(stream_child);
        if (ts_node_is_null(mapping)) {
            continue;
        }

        k8s_doc_id_t id;
        memset(&id, 0, sizeof(id));
        extract_k8s_scalars(ctx, mapping, &id);

        // Skip malformed manifests (no kind or no metadata.name)
        if (id.kind[0] == '\0' || id.name[0] == '\0') {
            continue;
        }

        char group[K8S_BUF_SIZE];
        k8s_api_group(id.api_version, group, sizeof(group));

        CBMDefinition def = {0};
        def.name = cbm_arena_sprintf(a, "%s/%s", id.kind, id.name);
        def.qualified_name = cbm_arena_sprintf(a, "%s::%s/%s/%s/%s", base, group, id.kind,
                                               id.ns[0] ? id.ns : "-", id.name);
        // "Resource" is the canonical def label for a K8s resource kind. It is a
        // valid graph label and is what the K8s pipeline pass (pass_k8s.c) filters
        // on to upsert Resource nodes and emit INFRA_MAPS edges.
        def.label = cbm_arena_strdup(a, "Resource");
        def.file_path = ctx->rel_path;
        def.start_line = ts_node_start_point(mapping).row + TS_LINE_OFFSET;
        def.end_line = ts_node_end_point(mapping).row + TS_LINE_OFFSET;
        cbm_defs_push(&ctx->result->defs, a, def);
        k8s_emit_facts(ctx, mapping, id.kind, ctx->result->defs.count - SKIP_ONE);
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

void cbm_extract_k8s(CBMExtractCtx *ctx) {
    if (ctx->language == CBM_LANG_KUSTOMIZE) {
        extract_kustomize(ctx);
    } else if (ctx->language == CBM_LANG_K8S) {
        extract_k8s_manifest(ctx);
    }
}
