/*
 * pass_terraform.c — the Terraform / OpenTofu infrastructure layer.
 *
 * PHASE 3 P3.4: a `resource "helm_release"` DEPLOYS its chart -- an edge from
 * the resource block (its node `resource.helm_release.<name>`) to existing
 * nodes only:
 *   chart = "./charts/x" / "${path.module}/charts/x"   the Chart of that
 *                                                      directory, relative to
 *                                                      the module's directory
 *   repository = "<url>", chart = "<name>"             the shared external
 *   chart = "oci://registry/.../<name>"                Chart of that name
 * Values are evaluated from string literals and ${path.module}; any other
 * expression is unknown, and an unknown chart is no edge. Run at the end of
 * the K8s pass, over the same files.
 */
#include "foundation/constants.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/hash_table.h"
#include "foundation/limits.h"
#include "foundation/log.h"
#include "foundation/mem_core.h"
#include "foundation/str_util.h"
#include "graph_buffer/graph_buffer.h"
#include "pipeline/pipeline.h"
#include "pipeline/pipeline_internal.h"
#include "cbm.h"
#include "helpers.h"
#include "lang_specs.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Blocks a helm_release lookup examined (complexity guard counter). */
_Atomic uint64_t g_tf_candidates = 0;

typedef struct {
    cbm_pipeline_ctx_t *ctx;
    CBMArena *arena;      /* lookup QNs */
    CBMHashTable *charts; /* Chart.yaml path -> local Chart node id */
    const char *src;
    const char *file;
    char mdir[CBM_SZ_1K]; /* the module's directory */
    int edges;
} tf_t;

static bool tf_type(TSNode n, const char *t) {
    return !ts_node_is_null(n) && strcmp(ts_node_type(n), t) == 0;
}

static const char *tf_basename(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + SKIP_ONE : p;
}

/* Append [p, p+n) to out (size sz); false when it does not fit. */
static bool tf_add(char *out, size_t sz, size_t *len, const char *p, size_t n) {
    if (*len + n + SKIP_ONE > sz) {
        return false;
    }
    memcpy(out + *len, p, n);
    *len += n;
    out[*len] = '\0';
    return true;
}

/* A string value: a literal, or a template of literals and ${path.module}.
 * false when any part is something else. */
static bool tf_string(const tf_t *t, TSNode n, char *out, size_t sz) {
    size_t len = 0;
    out[0] = '\0';
    while (tf_type(n, "expression") || tf_type(n, "literal_value") || tf_type(n, "template_expr") ||
           tf_type(n, "string_lit") || tf_type(n, "quoted_template")) {
        if (tf_type(n, "string_lit") || tf_type(n, "quoted_template")) {
            break;
        }
        if (ts_node_named_child_count(n) != SKIP_ONE) {
            return false;
        }
        n = ts_node_named_child(n, 0);
    }
    if (!tf_type(n, "string_lit") && !tf_type(n, "quoted_template")) {
        return false;
    }
    for (uint32_t i = 0; i < ts_node_named_child_count(n); i++) {
        TSNode c = ts_node_named_child(n, i);
        uint32_t b = ts_node_start_byte(c);
        uint32_t e = ts_node_end_byte(c);
        if (tf_type(c, "quoted_template_start") || tf_type(c, "quoted_template_end")) {
            continue;
        }
        if (tf_type(c, "template_literal")) {
            if (!tf_add(out, sz, &len, t->src + b, e - b)) {
                return false;
            }
            continue;
        }
        if (!tf_type(c, "template_interpolation")) {
            return false;
        }
        /* ${path.module} only */
        TSNode expr = {0};
        for (uint32_t j = 0; j < ts_node_named_child_count(c); j++) {
            if (tf_type(ts_node_named_child(c, j), "expression")) {
                expr = ts_node_named_child(c, j);
            }
        }
        if (ts_node_is_null(expr)) {
            return false;
        }
        uint32_t xb = ts_node_start_byte(expr);
        uint32_t xe = ts_node_end_byte(expr);
        static const char PATH_MODULE[] = "path.module";
        if (xe - xb != sizeof(PATH_MODULE) - SKIP_ONE ||
            strncmp(t->src + xb, PATH_MODULE, xe - xb) != 0) {
            return false;
        }
        /* an absolute marker: the module directory, from the repo root */
        if (!tf_add(out, sz, &len, "\x01", SKIP_ONE) ||
            !tf_add(out, sz, &len, t->mdir, strlen(t->mdir))) {
            return false;
        }
    }
    return true;
}

/* A path inside the module directory: "./a/../b" -> "<mdir>/b"; NULL past
 * the repository root. A value starting with the \x01 marker is already
 * from the root. */
static bool tf_repo_path(const char *mdir, const char *v, char *out, size_t sz) {
    bool anchored = v[0] == '\x01';
    const char *rel = anchored ? v + SKIP_ONE : v;
    char buf[CBM_SZ_2K];
    if (anchored) {
        snprintf(buf, sizeof(buf), "%s", rel);
    } else {
        snprintf(buf, sizeof(buf), "%s%s%s", mdir, mdir[0] ? "/" : "", rel);
    }
    size_t n = 0;
    out[0] = '\0';
    for (const char *p = buf; *p;) {
        while (*p == '/') {
            p++;
        }
        size_t sl = strcspn(p, "/");
        if (sl == 0) {
            break;
        }
        if (sl == SKIP_ONE && p[0] == '.') {
            p += sl;
            continue;
        }
        if (sl == PAIR_LEN && p[0] == '.' && p[SKIP_ONE] == '.') {
            if (n == 0) {
                return false;
            }
            while (n > 0 && out[n - SKIP_ONE] != '/') {
                n--;
            }
            if (n > 0) {
                n--;
            }
            out[n] = '\0';
            p += sl;
            continue;
        }
        if (n + sl + PAIR_LEN > sz) {
            return false;
        }
        if (n) {
            out[n++] = '/';
        }
        memcpy(out + n, p, sl);
        n += sl;
        out[n] = '\0';
        p += sl;
    }
    return true;
}

/* Chart.yaml path -> its (local) Chart node. */
static CBMHashTable *tf_chart_index(cbm_pipeline_ctx_t *ctx) {
    CBMHashTable *ix = cbm_ht_create(0);
    const cbm_gbuf_node_t **nodes = NULL;
    int count = 0;
    if (!ix || cbm_gbuf_find_by_label(ctx->gbuf, "Chart", &nodes, &count) != 0) {
        return ix;
    }
    for (int i = 0; i < count; i++) {
        const char *fp = nodes[i]->file_path;
        const char *qn = nodes[i]->qualified_name;
        const char *base = fp ? tf_basename(fp) : "";
        if (fp && qn && !strstr(qn, ".__helm_dep__.") &&
            (strcmp(base, "Chart.yaml") == 0 || strcmp(base, "Chart.yml") == 0)) {
            cbm_ht_set(ix, fp, (void *)(intptr_t)nodes[i]->id);
        }
    }
    return ix;
}

/* The Chart node of repository chart directory `dir`, 0 when none. */
static int64_t tf_local_chart(const tf_t *t, const char *dir) {
    static const char *const names[] = {"Chart.yaml", "Chart.yml"};
    for (size_t k = 0; t->charts && k < sizeof(names) / sizeof(names[0]); k++) {
        char want[CBM_SZ_2K];
        snprintf(want, sizeof(want), "%s%s%s", dir, dir[0] ? "/" : "", names[k]);
        int64_t id = (int64_t)(intptr_t)cbm_ht_get(t->charts, want);
        if (id > 0) {
            return id;
        }
    }
    return 0;
}

/* The shared external Chart of `name` (the one chart dependencies use). */
static int64_t tf_external_chart(cbm_pipeline_ctx_t *ctx, const char *name, const char *file) {
    char qn[CBM_SZ_512];
    snprintf(qn, sizeof(qn), "%s.__helm_dep__.%s", ctx->project_name, name);
    const cbm_gbuf_node_t *known = cbm_gbuf_find_by_qn(ctx->gbuf, qn);
    if (known) {
        return known->id;
    }
    return cbm_gbuf_upsert_node(ctx->gbuf, "Chart", name, qn, file, SKIP_ONE, 0,
                                "{\"source\":\"helm\",\"external\":true}");
}

/* The node of block `resource.helm_release.<name>` in the file, by the QN
 * its definition got -- not among every block of that name: modules that
 * share a release name (`this`) would make each lookup scan all of them. */
static int64_t tf_block_node(const tf_t *t, const char *name) {
    char full[CBM_SZ_512];
    snprintf(full, sizeof(full), "resource.helm_release.%s", name);
    const char *qn = cbm_fqn_compute(t->arena, t->ctx->project_name, t->file, full);
    const cbm_gbuf_node_t *n = qn ? cbm_gbuf_find_by_qn(t->ctx->gbuf, qn) : NULL;
    atomic_fetch_add_explicit(&g_tf_candidates, SKIP_ONE, memory_order_relaxed);
    return n && n->file_path && strcmp(n->file_path, t->file) == 0 ? n->id : 0;
}

static bool tf_plain_name(const char *s) {
    if (!s[0]) {
        return false;
    }
    for (const char *p = s; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
              *p == '-' || *p == '_' || *p == '.')) {
            return false;
        }
    }
    return true;
}

/* One `resource "helm_release" "<name>" { ... }` block. */
static void tf_helm_release(tf_t *t, TSNode block, const char *name) {
    TSNode body = {0};
    for (uint32_t i = 0; i < ts_node_named_child_count(block); i++) {
        if (tf_type(ts_node_named_child(block, i), "body")) {
            body = ts_node_named_child(block, i);
        }
    }
    if (ts_node_is_null(body)) {
        return;
    }
    char chart[CBM_SZ_1K] = "";
    bool has_chart = false;
    bool has_repo = false; /* a repository, even of unknown value: not a local chart */
    for (uint32_t i = 0; i < ts_node_named_child_count(body); i++) {
        TSNode a = ts_node_named_child(body, i);
        if (!tf_type(a, "attribute") || ts_node_named_child_count(a) < PAIR_LEN) {
            continue;
        }
        TSNode key = ts_node_named_child(a, 0);
        TSNode val = ts_node_named_child(a, SKIP_ONE);
        uint32_t kb = ts_node_start_byte(key);
        uint32_t ke = ts_node_end_byte(key);
        size_t kl = ke - kb;
        if (kl == strlen("chart") && strncmp(t->src + kb, "chart", kl) == 0) {
            has_chart = tf_string(t, val, chart, sizeof(chart));
        } else if (kl == strlen("repository") && strncmp(t->src + kb, "repository", kl) == 0) {
            has_repo = true;
        }
    }
    if (!has_chart) {
        return;
    }
    int64_t src = tf_block_node(t, name);
    int64_t tgt = 0;
    bool external = false;
    char path[CBM_SZ_1K] = "";
    static const char OCI[] = "oci://";
    if (strncmp(chart, OCI, sizeof(OCI) - SKIP_ONE) == 0) {
        const char *base = tf_basename(chart);
        if (tf_plain_name(base)) {
            snprintf(path, sizeof(path), "%s", base);
            external = true;
        }
    } else if (has_repo) {
        if (tf_plain_name(chart)) {
            snprintf(path, sizeof(path), "%s", chart);
            external = true;
        }
    } else if (tf_repo_path(t->mdir, chart, path, sizeof(path))) {
        tgt = tf_local_chart(t, path);
    }
    if (external) {
        tgt = tf_external_chart(t->ctx, path, t->file);
    }
    if (src <= 0 || tgt <= 0) {
        return;
    }
    char esc[CBM_SZ_1K];
    char props[CBM_SZ_2K];
    cbm_json_escape(esc, (int)sizeof(esc), path);
    snprintf(props, sizeof(props), "{\"via\":\"terraform\",\"chart\":\"%s\"%s,\"line\":%d}", esc,
             external ? ",\"external\":true" : "", (int)ts_node_start_point(block).row + SKIP_ONE);
    cbm_gbuf_insert_edge(t->ctx->gbuf, src, tgt, "DEPLOYS", props);
    t->edges++;
}

/* The text of a string_lit label: "helm_release" -> helm_release. */
static bool tf_label(const tf_t *t, TSNode n, char *out, size_t sz) {
    if (!tf_type(n, "string_lit")) {
        return false;
    }
    for (uint32_t i = 0; i < ts_node_named_child_count(n); i++) {
        TSNode c = ts_node_named_child(n, i);
        if (tf_type(c, "template_literal")) {
            uint32_t b = ts_node_start_byte(c);
            snprintf(out, sz, "%.*s", (int)(ts_node_end_byte(c) - b), t->src + b);
            return true;
        }
    }
    return false;
}

static void tf_file(tf_t *t, TSNode root) {
    TSNode body = {0}; /* comments are children of the file too */
    for (uint32_t i = 0; i < ts_node_named_child_count(root) && ts_node_is_null(body); i++) {
        if (tf_type(ts_node_named_child(root, i), "body")) {
            body = ts_node_named_child(root, i);
        }
    }
    for (uint32_t i = 0; !ts_node_is_null(body) && i < ts_node_named_child_count(body); i++) {
        TSNode b = ts_node_named_child(body, i);
        if (!tf_type(b, "block") || ts_node_named_child_count(b) < 3) {
            continue;
        }
        TSNode kw = ts_node_named_child(b, 0);
        uint32_t kb = ts_node_start_byte(kw);
        uint32_t ke = ts_node_end_byte(kw);
        char type[CBM_SZ_128];
        char name[CBM_SZ_256];
        if (ke - kb != strlen("resource") || strncmp(t->src + kb, "resource", ke - kb) != 0 ||
            !tf_label(t, ts_node_named_child(b, SKIP_ONE), type, sizeof(type)) ||
            !tf_label(t, ts_node_named_child(b, PAIR_LEN), name, sizeof(name))) {
            continue;
        }
        if (strcmp(type, "helm_release") == 0) {
            tf_helm_release(t, b, name);
        }
    }
}

static char *tf_read(const char *path, size_t *len) {
    FILE *f = cbm_fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    (void)fseek(f, 0, SEEK_END);
    long size = ftell(f);
    (void)fseek(f, 0, SEEK_SET);
    if (size <= 0 || size > cbm_max_file_bytes()) {
        (void)fclose(f);
        return NULL;
    }
    enum { TF_TS_PAD = 16 }; /* tree-sitter's lexer reads past the end */
    char *buf = cbm_alloc(CBM_MEM_CLASS_OTHER, (size_t)size + TF_TS_PAD);
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }
    size_t got = fread(buf, SKIP_ONE, (size_t)size, f);
    (void)fclose(f);
    memset(buf + got, 0, TF_TS_PAD);
    *len = got;
    return buf;
}

static bool tf_is_module_file(const char *rel) {
    const char *dot = strrchr(tf_basename(rel), '.');
    return dot && (strcmp(dot, ".tf") == 0 || strcmp(dot, ".tofu") == 0);
}

/* ── References (PHASE 6 P6.1) ─────────────────────────────────────── */

/* A Terraform module is a directory: every .tf / .tofu file of it. A
 * reference resolves inside its module only -- var.X to `variable "X"`,
 * local.X to the locals block declaring X, module.X to `module "X"`,
 * data.T.N to `data "T" "N"`, T.N to `resource "T" "N"` (T.N declared there);
 * anything else (each, count, self, path, terraform, a for-expression name, a
 * builtin function) to nothing. Edge: USAGE {ref, via: terraform, line} from
 * the top-level block holding the reference to the declaring block; an entry
 * of the block's depends_on list orders it after the object: DEPENDS_ON, the
 * same properties. */

typedef struct {
    char *file;      /* the referencing file */
    char *src;       /* the holding top-level block's definition name */
    char *key;       /* what it names: variable.X, local.X, module.X, data.T.N, resource.T.N */
    const char *ref; /* static: var, local, module, data, resource */
    int line;
    bool dep; /* stands in the holder's depends_on list */
} tf_ref_t;

typedef struct {
    cbm_pipeline_ctx_t *ctx;
    CBMArena *arena;
    CBMHashTable *decls; /* key (as tf_ref_t.key) -> declaring file (arena) */
    tf_ref_t *refs;
    int ref_n;
    int ref_cap;
    const char *src;  /* the file's text */
    const char *file; /* its repository path (arena) */
    bool dep;         /* walking a depends_on list */
} tf_mod_t;

static const char *tf_text(CBMArena *a, const char *src, TSNode n) {
    uint32_t b = ts_node_start_byte(n);
    return cbm_arena_strndup(a, src + b, ts_node_end_byte(n) - b);
}

/* A block label: a string_lit's text, or an identifier (`resource aws_x y`). */
static const char *tf_block_label(CBMArena *a, const char *src, TSNode n) {
    if (tf_type(n, "identifier")) {
        return tf_text(a, src, n);
    }
    for (uint32_t i = 0; tf_type(n, "string_lit") && i < ts_node_named_child_count(n); i++) {
        TSNode c = ts_node_named_child(n, i);
        if (tf_type(c, "template_literal")) {
            return tf_text(a, src, c);
        }
    }
    return NULL;
}

/* A top-level block's definition name: its keyword and labels joined by
 * "." (variable.X, resource.T.N, locals) -- the name extract_defs gives it. */
static const char *tf_block_name(CBMArena *a, const char *src, TSNode block, TSNode *body) {
    const char *name = NULL;
    *body = (TSNode){0};
    for (uint32_t i = 0; i < ts_node_named_child_count(block); i++) {
        TSNode c = ts_node_named_child(block, i);
        if (tf_type(c, "body")) {
            *body = c;
        } else if (i == 0 && tf_type(c, "identifier")) {
            name = tf_text(a, src, c);
        } else if (name) {
            const char *label = tf_block_label(a, src, c);
            name = label ? cbm_arena_sprintf(a, "%s.%s", name, label) : name;
        }
    }
    return name;
}

static void tf_ref_push(tf_mod_t *m, const char *src_block, const char *ref, const char *key,
                        int line) {
    if (m->ref_n >= m->ref_cap) {
        int cap = m->ref_cap ? m->ref_cap * PAIR_LEN : CBM_SZ_64;
        tf_ref_t *grown = cbm_realloc(CBM_MEM_CLASS_OTHER, m->refs, (size_t)cap * sizeof(*grown));
        if (!grown) {
            return;
        }
        m->refs = grown;
        m->ref_cap = cap;
    }
    m->refs[m->ref_n++] =
        (tf_ref_t){(char *)m->file, (char *)src_block, (char *)key, ref, line, m->dep};
}

/* The identifier of the k-th get_attr following `v` among its siblings (a
 * traversal is variable_expr, get_attr, get_attr, ... once the grammar's
 * hidden expression rule is flattened); NULL past the attributes. */
static const char *tf_attr(CBMArena *a, const char *src, TSNode v, int k) {
    TSNode s = ts_node_next_named_sibling(v);
    for (int i = 0; !ts_node_is_null(s) && tf_type(s, "get_attr"); i++) {
        if (i == k) {
            for (uint32_t c = 0; c < ts_node_named_child_count(s); c++) {
                if (tf_type(ts_node_named_child(s, c), "identifier")) {
                    return tf_text(a, src, ts_node_named_child(s, c));
                }
            }
            return NULL;
        }
        s = ts_node_next_named_sibling(s);
    }
    return NULL;
}

/* One traversal `root.attr...` inside block `src_block`. */
static void tf_traversal(tf_mod_t *m, const char *src_block, TSNode v) {
    if (ts_node_named_child_count(v) == 0) {
        return;
    }
    CBMArena *a = m->arena;
    const char *root = tf_text(a, m->src, ts_node_named_child(v, 0));
    const char *a1 = tf_attr(a, m->src, v, 0);
    if (!root || !a1) {
        return;
    }
    int line = (int)ts_node_start_point(v).row + SKIP_ONE;
    if (strcmp(root, "var") == 0) {
        tf_ref_push(m, src_block, "var", cbm_arena_sprintf(a, "variable.%s", a1), line);
    } else if (strcmp(root, "local") == 0) {
        tf_ref_push(m, src_block, "local", cbm_arena_sprintf(a, "local.%s", a1), line);
    } else if (strcmp(root, "module") == 0) {
        tf_ref_push(m, src_block, "module", cbm_arena_sprintf(a, "module.%s", a1), line);
    } else if (strcmp(root, "data") == 0) {
        const char *a2 = tf_attr(a, m->src, v, SKIP_ONE);
        if (a2) {
            tf_ref_push(m, src_block, "data", cbm_arena_sprintf(a, "data.%s.%s", a1, a2), line);
        }
    } else if (strchr(root, '_')) {
        tf_ref_push(m, src_block, "resource", cbm_arena_sprintf(a, "resource.%s.%s", root, a1),
                    line);
    }
}

/* Every traversal under `n` (iterative: deep expressions). */
static void tf_walk_refs(tf_mod_t *m, const char *src_block, TSNode n) {
    TSTreeCursor cur = ts_tree_cursor_new(n);
    bool more = true;
    while (more) {
        TSNode c = ts_tree_cursor_current_node(&cur);
        if (tf_type(c, "variable_expr")) {
            tf_traversal(m, src_block, c);
        }
        if (ts_tree_cursor_goto_first_child(&cur)) {
            continue;
        }
        while (!ts_tree_cursor_goto_next_sibling(&cur)) {
            if (!ts_tree_cursor_goto_parent(&cur)) {
                more = false;
                break;
            }
        }
    }
    ts_tree_cursor_delete(&cur);
}

/* Node `n`'s text is `word`. */
static bool tf_is_word(const tf_mod_t *m, TSNode n, const char *word) {
    uint32_t b = ts_node_start_byte(n);
    size_t len = strlen(word);
    return ts_node_end_byte(n) - b == len && memcmp(m->src + b, word, len) == 0;
}

/* The references of one top-level block's body, those of its depends_on
 * list marked as such. */
static void tf_walk_block(tf_mod_t *m, const char *src_block, TSNode body) {
    for (uint32_t i = 0; i < ts_node_named_child_count(body); i++) {
        TSNode c = ts_node_named_child(body, i);
        m->dep = tf_type(c, "attribute") && ts_node_named_child_count(c) > 0 &&
                 tf_is_word(m, ts_node_named_child(c, 0), "depends_on");
        tf_walk_refs(m, src_block, c);
    }
    m->dep = false;
}

/* One file of a module: its declarations (blocks, locals entries) and the
 * references of each top-level block. */
static void tf_mod_file(tf_mod_t *m, TSNode root) {
    CBMArena *a = m->arena;
    TSNode body = {0};
    for (uint32_t i = 0; i < ts_node_named_child_count(root) && ts_node_is_null(body); i++) {
        if (tf_type(ts_node_named_child(root, i), "body")) {
            body = ts_node_named_child(root, i);
        }
    }
    for (uint32_t i = 0; !ts_node_is_null(body) && i < ts_node_named_child_count(body); i++) {
        TSNode b = ts_node_named_child(body, i);
        TSNode bb;
        const char *name = tf_type(b, "block") ? tf_block_name(a, m->src, b, &bb) : NULL;
        if (!name) {
            continue;
        }
        cbm_ht_set(m->decls, name, (void *)m->file); /* `{}` declares too */
        if (ts_node_is_null(bb)) {
            continue;
        }
        if (strcmp(name, "locals") == 0) {
            for (uint32_t j = 0; j < ts_node_named_child_count(bb); j++) {
                TSNode at = ts_node_named_child(bb, j);
                if (tf_type(at, "attribute") && ts_node_named_child_count(at) > 0) {
                    const char *key = tf_text(a, m->src, ts_node_named_child(at, 0));
                    cbm_ht_set(m->decls, cbm_arena_sprintf(a, "local.%s", key), (void *)m->file);
                }
            }
        }
        tf_walk_block(m, name, bb);
    }
}

/* The node of definition `name` in `file`, by the QN extract_defs gave it. */
static int64_t tf_def_node(tf_mod_t *m, const char *file, const char *name) {
    const char *qn = cbm_fqn_compute(m->arena, m->ctx->project_name, file, name);
    const cbm_gbuf_node_t *n = qn ? cbm_gbuf_find_by_qn(m->ctx->gbuf, qn) : NULL;
    atomic_fetch_add_explicit(&g_tf_candidates, SKIP_ONE, memory_order_relaxed);
    return n && n->file_path && strcmp(n->file_path, file) == 0 ? n->id : 0;
}

/* Order paths by directory, then name: a directory's files are contiguous. */
static int tf_cmp_dir_path(const void *x, const void *y) {
    const char *p = *(const char *const *)x;
    const char *q = *(const char *const *)y;
    const char *ps = strrchr(p, '/');
    const char *qs = strrchr(q, '/');
    size_t pl = ps ? (size_t)(ps - p) : 0;
    size_t ql = qs ? (size_t)(qs - q) : 0;
    size_t n = pl < ql ? pl : ql;
    int c = strncmp(p, q, n);
    if (c == 0 && pl != ql) {
        c = pl < ql ? -1 : 1;
    }
    return c ? c : strcmp(p, q);
}

static bool tf_same_dir(const char *p, const char *q) {
    const char *ps = strrchr(p, '/');
    const char *qs = strrchr(q, '/');
    size_t pl = ps ? (size_t)(ps - p) : 0;
    size_t ql = qs ? (size_t)(qs - q) : 0;
    return pl == ql && strncmp(p, q, pl) == 0;
}

/* Resolve the module's references against its declarations. */
static int tf_mod_link(tf_mod_t *m) {
    int edges = 0;
    for (int i = 0; i < m->ref_n; i++) {
        const tf_ref_t *r = &m->refs[i];
        const char *tfile = cbm_ht_get(m->decls, r->key);
        if (!tfile) {
            continue;
        }
        bool local = strcmp(r->ref, "local") == 0;
        int64_t src = tf_def_node(m, r->file, r->src);
        int64_t tgt = tf_def_node(m, tfile, local ? "locals" : r->key);
        if (src <= 0 || tgt <= 0 || src == tgt) {
            continue;
        }
        char props[CBM_SZ_128];
        snprintf(props, sizeof(props), "{\"ref\":\"%s\",\"via\":\"terraform\",\"line\":%d}", r->ref,
                 r->line);
        cbm_gbuf_insert_edge(m->ctx->gbuf, src, tgt, r->dep ? "DEPENDS_ON" : "USAGE", props);
        edges++;
    }
    return edges;
}

/* One module directory, its files `paths[0..n)`: parse each (read from the
 * repository), then resolve. */
static int tf_link_module(cbm_pipeline_ctx_t *ctx, TSParser *parser, const char *const *paths,
                          int n) {
    CBMArena arena;
    cbm_arena_init_lazy(&arena, CBM_SZ_4K);
    tf_mod_t m = {.ctx = ctx, .arena = &arena, .decls = cbm_ht_create(0)};
    for (int i = 0; m.decls && i < n; i++) {
        char path[CBM_SZ_2K];
        snprintf(path, sizeof(path), "%s/%s", ctx->repo_path, paths[i]);
        size_t len = 0;
        char *src = tf_read(path, &len);
        TSTree *tree = src ? ts_parser_parse_string(parser, NULL, src, (uint32_t)len) : NULL;
        if (tree) {
            m.src = src;
            m.file = cbm_arena_strdup(&arena, paths[i]);
            tf_mod_file(&m, ts_tree_root_node(tree));
            ts_tree_delete(tree);
        }
        cbm_free(CBM_MEM_CLASS_OTHER, src);
    }
    int edges = m.decls ? tf_mod_link(&m) : 0;
    if (m.decls) {
        cbm_ht_free(m.decls);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, m.refs);
    cbm_arena_destroy(&arena);
    return edges;
}

/* Every module directory one of the run's .tf / .tofu files is in, resolved
 * whole: all its files (the graph's File nodes) -- on an incremental run an
 * unchanged file's reference may meet what a changed one declares. */
static int tf_link_refs(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files, int file_count,
                        TSParser *parser) {
    CBMHashTable *dirs = cbm_ht_create(0);
    if (!dirs) {
        return 0;
    }
    CBMArena keys;
    cbm_arena_init_lazy(&keys, CBM_SZ_4K);
    int ndirs = 0;
    for (int i = 0; i < file_count; i++) {
        const char *rel = files[i].rel_path;
        if (files[i].language == CBM_LANG_HCL && tf_is_module_file(rel)) {
            const char *slash = strrchr(rel, '/');
            const char *dir = cbm_arena_strndup(&keys, rel, slash ? (size_t)(slash - rel) : 0);
            if (dir && !cbm_ht_get(dirs, dir)) {
                cbm_ht_set(dirs, dir, (void *)dir);
                ndirs++;
            }
        }
    }
    const cbm_gbuf_node_t **fnodes = NULL;
    int fn = 0;
    if (ndirs == 0 || cbm_gbuf_find_by_label(ctx->gbuf, "File", &fnodes, &fn) != 0) {
        cbm_ht_free(dirs);
        cbm_arena_destroy(&keys);
        return 0;
    }
    const char **paths =
        cbm_calloc(CBM_MEM_CLASS_OTHER, (size_t)(fn ? fn : SKIP_ONE) * sizeof(char *));
    int pn = 0;
    for (int i = 0; paths && i < fn; i++) {
        const char *rel = fnodes[i]->file_path;
        if (!rel || !tf_is_module_file(rel)) {
            continue;
        }
        const char *slash = strrchr(rel, '/');
        char dir[CBM_SZ_1K];
        snprintf(dir, sizeof(dir), "%.*s", slash ? (int)(slash - rel) : 0, rel);
        if (cbm_ht_get(dirs, dir)) {
            paths[pn++] = rel;
        }
    }
    int edges = 0;
    if (paths && pn > 0 && ts_parser_set_language(parser, cbm_ts_language(CBM_LANG_HCL))) {
        qsort((void *)paths, (size_t)pn, sizeof(*paths), tf_cmp_dir_path);
        for (int i = 0; i < pn;) {
            int j = i;
            while (j < pn && tf_same_dir(paths[i], paths[j])) {
                j++;
            }
            edges += tf_link_module(ctx, parser, paths + i, j - i);
            i = j;
        }
    }
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)paths);
    cbm_ht_free(dirs);
    cbm_arena_destroy(&keys);
    return edges;
}

void cbm_pipeline_pass_terraform(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                                 int file_count) {
    TSParser *parser = NULL;
    CBMHashTable *charts = NULL;
    CBMArena arena;
    cbm_arena_init_lazy(&arena, CBM_SZ_4K);
    int edges = 0;
    for (int i = 0; i < file_count; i++) {
        if (files[i].language != CBM_LANG_HCL || !tf_is_module_file(files[i].rel_path)) {
            continue;
        }
        size_t len = 0;
        char *src = tf_read(files[i].path, &len);
        if (!src) {
            continue;
        }
        if (strstr(src, "helm_release")) {
            if (!parser) {
                parser = ts_parser_new();
                charts = tf_chart_index(ctx);
            }
            TSTree *tree = NULL;
            if (parser && ts_parser_set_language(parser, cbm_ts_language(CBM_LANG_HCL))) {
                tree = ts_parser_parse_string(parser, NULL, src, (uint32_t)len);
            }
            if (tree) {
                tf_t t = {.ctx = ctx,
                          .arena = &arena,
                          .charts = charts,
                          .src = src,
                          .file = files[i].rel_path};
                const char *slash = strrchr(files[i].rel_path, '/');
                snprintf(t.mdir, sizeof(t.mdir), "%.*s",
                         slash ? (int)(slash - files[i].rel_path) : 0, files[i].rel_path);
                tf_file(&t, ts_tree_root_node(tree));
                edges += t.edges;
                ts_tree_delete(tree);
            }
        }
        cbm_free(CBM_MEM_CLASS_OTHER, src);
    }
    if (!parser) {
        parser = ts_parser_new();
    }
    int refs = parser ? tf_link_refs(ctx, files, file_count, parser) : 0;
    if (parser) {
        ts_parser_delete(parser);
    }
    if (charts) {
        cbm_ht_free(charts);
    }
    cbm_arena_destroy(&arena);
    if (edges > 0 || refs > 0) {
        char buf[CBM_SZ_32];
        char rbuf[CBM_SZ_32];
        snprintf(buf, sizeof(buf), "%d", edges);
        snprintf(rbuf, sizeof(rbuf), "%d", refs);
        cbm_log_info("pass.terraform.edges", "deploys", buf, "refs", rbuf);
    }
}
