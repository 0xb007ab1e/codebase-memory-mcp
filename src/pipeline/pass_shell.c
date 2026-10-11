/*
 * pass_shell.c — the Bash (+ Make) infrastructure layer (PHASE 3 P3.2).
 *
 * A shell script or a Make recipe that puts manifests, a kustomization or a
 * chart on a cluster DEPLOYS them: an edge from the function running the
 * command (a bash function, a Make rule; top-level code: the Module) to the
 * node of what it deploys -- existing nodes only:
 *   kubectl apply|create|replace -f F     a File holding Kubernetes objects:
 *                                         F itself, F's *.yaml|*.yml|*.json
 *                                         (-R: below it), or a glob's matches
 *   kubectl ... -k D                      the Kustomization of D
 *   kustomize build D | ... | kubectl apply -f -   (also kubectl kustomize D)
 *   helm install|upgrade [NAME] CHART     the Chart of a chart dir, else the
 *                                         shared external Chart (repo/name,
 *                                         oci://.../name)
 *   helm template [NAME] CHART | ... | kubectl apply -f -
 *   find D -name G -exec kubectl apply -f {} \;    D's manifests matching G
 *
 * A program started by a path (./_build/kubermatic-installer, ${DIR}/x,
 * $(LOCALBIN)/controller-gen) SPAWNS the Process of its name, as
 * pass_spawns.c draws a call that starts a program; a path naming a file of
 * the repository is a script of its own and not linked here.
 *
 * Words are evaluated by constant propagation over the script, nothing is
 * executed: assignments (local / export / readonly / declare, arrays and
 * "${a[@]}"), ${X:-default}, $0 / BASH_SOURCE, $(dirname ..), $(basename ..),
 * $(cd .. && pwd), $(realpath ..), $(pwd), $(git rev-parse --show-toplevel).
 * A word with any other part is unknown, and an unknown target is no edge.
 * A value set in a branch, a loop or the right side of && / || is unknown
 * after it; a subshell's or pipeline element's changes do not leak; a
 * function body is read where it is defined, and the globals it sets are
 * unknown after it. cd / pushd / popd track the working directory. A
 * relative path resolves against it; with none tracked (a script runs from
 * wherever it is started), against the repository root and the script's
 * directory, linked only when exactly one of the two names a target.
 *
 * Make: the Makefile's variables expand into each recipe line (recursively,
 * with the last assignment; $(CURDIR) / $(shell pwd) are the Makefile's
 * directory, where its recipes run), which then evaluates as a shell line of
 * its own. A variable assigned under a conditional is unknown; an included
 * .mk file runs in its includer's directory, so it tracks none.
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
#include "lang_specs.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Candidate paths a target lookup scanned (complexity guard counter). */
_Atomic uint64_t g_sh_candidates = 0;

enum {
    SH_GROW_MIN = 16,
    SH_DEC = 10,
    SH_NO_DEPTH = -1,
};

/* A repository-anchored absolute path value: "\x01hack/ci" is <repo>/hack/ci. */
#define SH_ANCHOR '\x01'
static const char SH_ROOT[] = "\x01";

static bool sh_grow(void **items, int *cap, int count, size_t elem) {
    if (count < *cap) {
        return true;
    }
    int ncap = *cap ? *cap * PAIR_LEN : SH_GROW_MIN;
    void *grown = cbm_realloc(CBM_MEM_CLASS_OTHER, *items, (size_t)ncap * elem);
    if (!grown) {
        return false;
    }
    *items = grown;
    *cap = ncap;
    return true;
}

static const char *sh_basename(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + SKIP_ONE : p;
}

static bool sh_eq(const char *a, const char *b) {
    return a && b && strcmp(a, b) == 0;
}

static bool sh_starts(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/* ── The graph's deploy targets ────────────────────────────────────── */

typedef struct {
    const char **items; /* graph-owned paths */
    int count;
    int cap;
} sh_paths_t;

static void sh_paths_push(sh_paths_t *v, const char *p) {
    if (sh_grow((void **)&v->items, &v->cap, v->count, sizeof(*v->items))) {
        v->items[v->count++] = p;
    }
}

static int sh_cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void sh_paths_sort_unique(sh_paths_t *v) {
    if (v->count == 0) {
        return;
    }
    qsort((void *)v->items, (size_t)v->count, sizeof(*v->items), sh_cmp_str);
    int w = SKIP_ONE;
    for (int i = SKIP_ONE; i < v->count; i++) {
        if (strcmp(v->items[i], v->items[w - SKIP_ONE]) != 0) {
            v->items[w++] = v->items[i];
        }
    }
    v->count = w;
}

/* First index whose path is >= key. */
static int sh_lower_bound(const sh_paths_t *v, const char *key) {
    int lo = 0;
    int hi = v->count;
    while (lo < hi) {
        int mid = lo + (hi - lo) / PAIR_LEN;
        if (strcmp(v->items[mid], key) < 0) {
            lo = mid + SKIP_ONE;
        } else {
            hi = mid;
        }
    }
    return lo;
}

static bool sh_paths_has(const sh_paths_t *v, const char *p) {
    int i = sh_lower_bound(v, p);
    return i < v->count && strcmp(v->items[i], p) == 0;
}

typedef struct {
    cbm_pipeline_ctx_t *ctx;
    sh_paths_t files;       /* every File node's path */
    sh_paths_t manifests;   /* files holding Kubernetes objects (.yaml/.yml/.json) */
    CBMHashTable *file_ids; /* path -> File node id */
    CBMHashTable *kusts;    /* kustomization path -> its Kustomization Resource id */
    CBMHashTable *charts;   /* Chart.yaml path -> Chart node id */
} sh_index_t;

static bool sh_manifest_ext(const char *path) {
    const char *dot = strrchr(sh_basename(path), '.');
    return dot &&
           (strcmp(dot, ".yaml") == 0 || strcmp(dot, ".yml") == 0 || strcmp(dot, ".json") == 0);
}

static bool sh_kustomize_base(const char *base) {
    return cbm_is_kustomize_file(base) || strcmp(base, "Kustomization") == 0;
}

static bool sh_index_build(sh_index_t *ix, cbm_pipeline_ctx_t *ctx) {
    ix->ctx = ctx;
    ix->file_ids = cbm_ht_create(0);
    ix->kusts = cbm_ht_create(0);
    ix->charts = cbm_ht_create(0);
    if (!ix->file_ids || !ix->kusts || !ix->charts) {
        return false;
    }
    const cbm_gbuf_node_t **nodes = NULL;
    int n = 0;
    if (cbm_gbuf_find_by_label(ctx->gbuf, "File", &nodes, &n) == 0) {
        for (int i = 0; i < n; i++) {
            if (nodes[i]->file_path) {
                sh_paths_push(&ix->files, nodes[i]->file_path);
                cbm_ht_set(ix->file_ids, nodes[i]->file_path, (void *)(intptr_t)nodes[i]->id);
            }
        }
    }
    if (cbm_gbuf_find_by_label(ctx->gbuf, "Resource", &nodes, &n) == 0) {
        for (int i = 0; i < n; i++) {
            const char *fp = nodes[i]->file_path;
            if (!fp) {
                continue;
            }
            bool kust_file = sh_kustomize_base(sh_basename(fp));
            if (kust_file && sh_eq(nodes[i]->name, "Kustomization")) {
                cbm_ht_set(ix->kusts, fp, (void *)(intptr_t)nodes[i]->id);
            } else if (!kust_file && sh_manifest_ext(fp)) {
                sh_paths_push(&ix->manifests, fp);
            }
        }
    }
    if (cbm_gbuf_find_by_label(ctx->gbuf, "Chart", &nodes, &n) == 0) {
        for (int i = 0; i < n; i++) {
            const char *fp = nodes[i]->file_path;
            const char *base = fp ? sh_basename(fp) : "";
            const char *qn = nodes[i]->qualified_name;
            if ((strcmp(base, "Chart.yaml") == 0 || strcmp(base, "Chart.yml") == 0) && qn &&
                !strstr(qn, ".__helm_dep__.")) {
                cbm_ht_set(ix->charts, fp, (void *)(intptr_t)nodes[i]->id);
            }
        }
    }
    sh_paths_sort_unique(&ix->files);
    sh_paths_sort_unique(&ix->manifests);
    return true;
}

static void sh_index_free(sh_index_t *ix) {
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)ix->files.items);
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)ix->manifests.items);
    if (ix->file_ids) {
        cbm_ht_free(ix->file_ids);
    }
    if (ix->kusts) {
        cbm_ht_free(ix->kusts);
    }
    if (ix->charts) {
        cbm_ht_free(ix->charts);
    }
}

/* The paths of `v` below directory `dir` ("" = the root): [*lo, *hi). */
static void sh_range(const sh_paths_t *v, const char *dir, char *key, size_t key_sz, int *lo,
                     int *hi) {
    if (!dir[0]) {
        key[0] = '\0';
        *lo = 0;
        *hi = v->count;
        return;
    }
    snprintf(key, key_sz, "%s/", dir);
    size_t kl = strlen(key);
    *lo = sh_lower_bound(v, key);
    int h = *lo;
    while (h < v->count && strncmp(v->items[h], key, kl) == 0) {
        h++;
    }
    *hi = h;
}

static bool sh_dir_exists(const sh_index_t *ix, const char *dir) {
    if (!dir[0]) {
        return true;
    }
    char key[CBM_SZ_4K];
    int lo = 0;
    int hi = 0;
    sh_range(&ix->files, dir, key, sizeof(key), &lo, &hi);
    return hi > lo;
}

/* ── Path values ───────────────────────────────────────────────────── */

/* `rel` (a relative path: ./ and ../ allowed) inside repository directory
 * `base` ("" = the root), normalized; NULL when it leaves the repository. */
static char *sh_join(CBMArena *a, const char *base, const char *rel) {
    size_t bl = strlen(base);
    char *out = cbm_arena_alloc(a, bl + strlen(rel) + PAIR_LEN);
    if (!out) {
        return NULL;
    }
    memcpy(out, base, bl);
    size_t n = bl;
    out[n] = '\0';
    for (const char *p = rel; *p;) {
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
                return NULL;
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
        if (n) {
            out[n++] = '/';
        }
        memcpy(out + n, p, sl);
        n += sl;
        out[n] = '\0';
        p += sl;
    }
    return out;
}

static const char *sh_anchor(CBMArena *a, const char *repo_path) {
    return repo_path ? cbm_arena_sprintf(a, "%c%s", SH_ANCHOR, repo_path) : NULL;
}

/* dirname(1), on a value: textual, keeps an anchored path anchored. */
static const char *sh_dirname(CBMArena *a, const char *v) {
    bool anch = v[0] == SH_ANCHOR;
    const char *p = anch ? v + SKIP_ONE : v;
    size_t len = strlen(p);
    while (len > SKIP_ONE && p[len - SKIP_ONE] == '/') {
        len--;
    }
    size_t k = len;
    while (k > 0 && p[k - SKIP_ONE] != '/') {
        k--;
    }
    if (k == 0) {
        return anch ? SH_ROOT : ".";
    }
    size_t dl = k - SKIP_ONE;
    while (dl > 0 && p[dl - SKIP_ONE] == '/') {
        dl--;
    }
    if (dl == 0) {
        return anch ? SH_ROOT : "/";
    }
    return anch ? cbm_arena_sprintf(a, "%c%.*s", SH_ANCHOR, (int)dl, p)
                : cbm_arena_strndup(a, p, dl);
}

/* basename(1), on a value. */
static const char *sh_value_basename(CBMArena *a, const char *v) {
    const char *p = v[0] == SH_ANCHOR ? v + SKIP_ONE : v;
    size_t len = strlen(p);
    while (len > SKIP_ONE && p[len - SKIP_ONE] == '/') {
        len--;
    }
    size_t k = len;
    while (k > 0 && p[k - SKIP_ONE] != '/') {
        k--;
    }
    return cbm_arena_strndup(a, p + k, len - k);
}

/* ── Hits: what a command deploys ──────────────────────────────────── */

typedef struct {
    const char *file; /* the script (caller-owned path) */
    int line;
    const char *via;  /* static */
    int64_t tgt;      /* the target node; 0: the external chart `ext` */
    const char *ext;  /* pass-arena */
    const char *path; /* pass-arena: the deployed path or chart */
    bool chart;
    bool spawn; /* SPAWNS the Process `ext`, not DEPLOYS */
} sh_hit_t;

typedef struct {
    sh_hit_t *items;
    int count;
    int cap;
    CBMArena arena;
} sh_hits_t;

typedef struct {
    int64_t id;
    const char *path; /* graph-owned or file-arena */
} sh_target_t;

typedef struct {
    sh_target_t *items;
    int count;
    int cap;
} sh_targets_t;

static void sh_targets_push(sh_targets_t *v, int64_t id, const char *path) {
    if (id > 0 && sh_grow((void **)&v->items, &v->cap, v->count, sizeof(*v->items))) {
        v->items[v->count++] = (sh_target_t){id, path};
    }
}

/* ── Shell state ───────────────────────────────────────────────────── */

typedef struct {
    const char *s;      /* scalar value; NULL: unknown */
    const char **items; /* array items (an item NULL: unknown); NULL: no array */
    int n;
} sh_val_t;

static const sh_val_t SH_UNKNOWN_VAL = {NULL, NULL, 0};

typedef enum { SH_FREE, SH_AT, SH_LOST } sh_cwd_mode_t;

typedef struct {
    sh_cwd_mode_t mode;
    const char *dir; /* SH_AT: repository path ("" = the root) */
} sh_cwd_t;

typedef struct {
    const char *name;
    const sh_val_t *prev; /* NULL: was unset */
    bool local;
} sh_undo_t;

typedef struct {
    int undo;
    sh_cwd_t cwd;
    int ndirs;
} sh_mark_t;

typedef struct {
    const char **names;
    int n;
    int cap;
    bool cwd;
} sh_touch_t;

typedef struct {
    sh_index_t *ix;
    sh_hits_t *hits;
    CBMArena *a;        /* this file's values */
    const char *src;    /* the parsed text */
    const char *file;   /* the script / Makefile path */
    const char *script; /* $0: anchored script path; NULL: none (Make) */
    const char *sdir;   /* the script's directory */
    int line_base;      /* Make: the recipe line's row */
    int in_func;
    CBMHashTable *env; /* name -> const sh_val_t * */
    sh_undo_t *undo;
    int nundo;
    int cap_undo;
    sh_cwd_t cwd;
    sh_cwd_t *dirs; /* pushd stack */
    int ndirs;
    int cap_dirs;
} sh_t;

static void sh_set(sh_t *s, const char *name, const sh_val_t *v, bool local) {
    if (!sh_grow((void **)&s->undo, &s->cap_undo, s->nundo, sizeof(*s->undo))) {
        return;
    }
    s->undo[s->nundo++] = (sh_undo_t){name, cbm_ht_get(s->env, name), local};
    cbm_ht_set(s->env, name, (void *)v);
}

static sh_mark_t sh_mark(const sh_t *s) {
    return (sh_mark_t){s->nundo, s->cwd, s->ndirs};
}

static bool sh_cwd_same(sh_cwd_t a, sh_cwd_t b) {
    return a.mode == b.mode && (a.mode != SH_AT || strcmp(a.dir, b.dir) == 0);
}

static void sh_rewind(sh_t *s, sh_mark_t m) {
    while (s->nundo > m.undo) {
        const sh_undo_t *u = &s->undo[--s->nundo];
        if (u->prev) {
            cbm_ht_set(s->env, u->name, (void *)u->prev);
        } else {
            (void)cbm_ht_delete(s->env, u->name);
        }
    }
    s->cwd = m.cwd;
    s->ndirs = m.ndirs;
}

static void sh_touch_add(sh_touch_t *t, const char *name) {
    if (sh_grow((void **)&t->names, &t->cap, t->n, sizeof(*t->names))) {
        t->names[t->n++] = name;
    }
}

/* End one alternative of a conditional: what it set is noted, then undone. */
static void sh_clause_end(sh_t *s, sh_mark_t m, sh_touch_t *t) {
    for (int i = m.undo; i < s->nundo; i++) {
        sh_touch_add(t, s->undo[i].name);
    }
    if (!sh_cwd_same(s->cwd, m.cwd) || s->ndirs != m.ndirs) {
        t->cwd = true;
    }
    sh_rewind(s, m);
}

/* After the conditional: whatever any alternative set is unknown. */
static void sh_group_end(sh_t *s, sh_touch_t *t) {
    for (int i = 0; i < t->n; i++) {
        sh_set(s, t->names[i], &SH_UNKNOWN_VAL, false);
    }
    if (t->cwd) {
        s->cwd = (sh_cwd_t){SH_LOST, NULL};
    }
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)t->names);
    *t = (sh_touch_t){0};
}

/* ── Word evaluation ───────────────────────────────────────────────── */

static const char *sh_text(sh_t *s, TSNode n) {
    uint32_t b = ts_node_start_byte(n);
    uint32_t e = ts_node_end_byte(n);
    return cbm_arena_strndup(s->a, s->src + b, e - b);
}

static bool sh_type(TSNode n, const char *t) {
    return !ts_node_is_null(n) && strcmp(ts_node_type(n), t) == 0;
}

/* A growable string in the file arena. */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    bool bad; /* an unknown part */
} sh_str_t;

static void sh_str_add(CBMArena *a, sh_str_t *b, const char *p, size_t n) {
    if (b->bad || !p) {
        b->bad = true;
        return;
    }
    if (b->len + n + SKIP_ONE > b->cap) {
        size_t ncap = (b->cap ? b->cap : SH_GROW_MIN) * PAIR_LEN;
        while (ncap < b->len + n + SKIP_ONE) {
            ncap *= PAIR_LEN;
        }
        char *nb = cbm_arena_alloc(a, ncap);
        if (!nb) {
            b->bad = true;
            return;
        }
        if (b->len) {
            memcpy(nb, b->buf, b->len);
        }
        b->buf = nb;
        b->cap = ncap;
    }
    memcpy(b->buf + b->len, p, n);
    b->len += n;
    b->buf[b->len] = '\0';
}

static const char *sh_str_done(sh_str_t *b) {
    if (b->bad) {
        return NULL;
    }
    return b->buf ? b->buf : "";
}

/* Text with backslash escapes removed; in_dq: only the double-quote ones. */
static void sh_add_unescaped(CBMArena *a, sh_str_t *b, const char *p, size_t n, bool in_dq) {
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && p[j] != '\\') {
            j++;
        }
        sh_str_add(a, b, p + i, j - i);
        if (j + SKIP_ONE >= n) {
            if (j < n) {
                sh_str_add(a, b, p + j, SKIP_ONE);
            }
            return;
        }
        char c = p[j + SKIP_ONE];
        if (c == '\n') {
            i = j + PAIR_LEN;
            continue;
        }
        if (!in_dq || c == '"' || c == '\\' || c == '$' || c == '`') {
            sh_str_add(a, b, p + j + SKIP_ONE, SKIP_ONE);
        } else {
            sh_str_add(a, b, p + j, PAIR_LEN);
        }
        i = j + PAIR_LEN;
    }
}

static const char *sh_eval(sh_t *s, TSNode n);

/* The cwd as a value: the anchored directory, or NULL. */
static const char *sh_cwd_value(sh_t *s) {
    return s->cwd.mode == SH_AT ? sh_anchor(s->a, s->cwd.dir) : NULL;
}

/* A variable's value; *found: it is set (or a special that exists). */
static const sh_val_t *sh_lookup(sh_t *s, const char *name, bool *found) {
    *found = true;
    if (strcmp(name, "0") == 0 || strcmp(name, "BASH_SOURCE") == 0) {
        if (!s->script) {
            return &SH_UNKNOWN_VAL;
        }
        sh_val_t *v = cbm_arena_alloc(s->a, sizeof(*v));
        if (v) {
            *v = (sh_val_t){s->script, NULL, 0};
        }
        return v ? v : &SH_UNKNOWN_VAL;
    }
    if (strcmp(name, "PWD") == 0) {
        sh_val_t *v = cbm_arena_alloc(s->a, sizeof(*v));
        if (v) {
            *v = (sh_val_t){sh_cwd_value(s), NULL, 0};
        }
        return v ? v : &SH_UNKNOWN_VAL;
    }
    if (!name[0] || (strchr("123456789@*#?$!-", name[0]) &&
                     (name[SKIP_ONE] == '\0' || (name[0] >= '1' && name[0] <= '9')))) {
        return &SH_UNKNOWN_VAL; /* positional and special parameters */
    }
    const sh_val_t *v = cbm_ht_get(s->env, name);
    if (!v) {
        *found = false;
        return &SH_UNKNOWN_VAL;
    }
    return v;
}

/* Concatenate the children of `n` in [from, to), source gaps included. */
static void sh_concat(sh_t *s, sh_str_t *b, TSNode n, uint32_t from, uint32_t to, bool in_dq) {
    uint32_t pos = from;
    for (uint32_t i = 0; i < ts_node_child_count(n) && !b->bad; i++) {
        TSNode c = ts_node_child(n, i);
        uint32_t cb = ts_node_start_byte(c);
        uint32_t ce = ts_node_end_byte(c);
        if (cb < from || ce > to) {
            continue;
        }
        if (cb > pos) {
            sh_add_unescaped(s->a, b, s->src + pos, cb - pos, in_dq);
        }
        if (!ts_node_is_named(c)) {
            if (!(in_dq && strcmp(ts_node_type(c), "\"") == 0)) {
                sh_str_add(s->a, b, s->src + cb, ce - cb);
            }
        } else if (sh_type(c, "string_content")) {
            sh_add_unescaped(s->a, b, s->src + cb, ce - cb, in_dq);
        } else {
            const char *v = sh_eval(s, c);
            sh_str_add(s->a, b, v, v ? strlen(v) : 0);
        }
        pos = ce;
    }
    if (pos < to && !b->bad) {
        sh_add_unescaped(s->a, b, s->src + pos, to - pos, in_dq);
    }
}

/* ${...}: a plain variable, an element 0, or a default (:- - := =). */
static const char *sh_eval_expansion(sh_t *s, TSNode n) {
    TSNode name = {0};
    const char *op = NULL;
    uint32_t op_end = 0;
    uint32_t close = ts_node_end_byte(n);
    uint32_t cc = ts_node_child_count(n);
    for (uint32_t i = 0; i < cc; i++) {
        TSNode c = ts_node_child(n, i);
        const char *t = ts_node_type(c);
        if (ts_node_is_named(c)) {
            if (ts_node_is_null(name)) {
                name = c;
            } else if (!op) {
                return NULL; /* ${X%pattern} and the like: no plain value */
            }
            continue;
        }
        if (strcmp(t, "${") == 0) {
            continue;
        }
        if (strcmp(t, "}") == 0) {
            close = ts_node_start_byte(c);
            continue;
        }
        if (op) {
            continue; /* inside the default */
        }
        if (ts_node_is_null(name)) {
            return NULL; /* ${#X}, ${!X}: not the value */
        }
        if (strcmp(t, ":-") != 0 && strcmp(t, "-") != 0 && strcmp(t, ":=") != 0 &&
            strcmp(t, "=") != 0) {
            return NULL; /* ${X%..}, ${X/..}, ${X:+..}, ... */
        }
        op = t;
        op_end = ts_node_end_byte(c);
    }
    if (ts_node_is_null(name)) {
        return NULL;
    }
    const char *nm = NULL;
    int index = SH_NO_DEPTH;
    if (sh_type(name, "subscript")) {
        TSNode base = ts_node_child_by_field_name(name, TS_FIELD("name"));
        TSNode idx = ts_node_child_by_field_name(name, TS_FIELD("index"));
        if (ts_node_is_null(base) || ts_node_is_null(idx)) {
            return NULL;
        }
        const char *it = sh_text(s, idx);
        if (!it || strcmp(it, "0") != 0) {
            return NULL;
        }
        nm = sh_text(s, base);
        index = 0;
    } else if (sh_type(name, "variable_name") || sh_type(name, "special_variable_name")) {
        nm = sh_text(s, name);
    } else {
        return NULL;
    }
    if (!nm) {
        return NULL;
    }
    bool found = false;
    const sh_val_t *v = sh_lookup(s, nm, &found);
    const char *val = v->s;
    if (index == 0 && v->items) {
        val = v->n > 0 ? v->items[0] : "";
    }
    if (!op) {
        return found ? val : NULL;
    }
    bool colon = op[0] == ':';
    bool use_default = !found || (colon && val && !val[0]);
    if (!use_default) {
        return val;
    }
    sh_str_t b = {0};
    sh_concat(s, &b, n, op_end, close, true);
    const char *d = sh_str_done(&b);
    if (d && strchr(op, '=')) {
        sh_val_t *nv = cbm_arena_alloc(s->a, sizeof(*nv));
        if (nv) {
            *nv = (sh_val_t){d, NULL, 0};
            sh_set(s, nm, nv, false);
        }
    }
    return d;
}

/* A value as a repository path: anchored, or relative to a tracked
 * directory. NULL when it is neither. */
static const char *sh_cd_target(sh_t *s, const char *v, sh_cwd_t *out);

/* realpath / readlink -f: the anchored path, when it is decidable. */
static const char *sh_absolute(sh_t *s, const char *v) {
    if (!v) {
        return NULL;
    }
    if (v[0] == SH_ANCHOR) {
        return sh_anchor(s->a, sh_join(s->a, "", v + SKIP_ONE));
    }
    if (v[0] == '/' || s->cwd.mode != SH_AT) {
        return NULL;
    }
    return sh_anchor(s->a, sh_join(s->a, s->cwd.dir, v));
}

typedef struct {
    const char **v;
    bool *split;
    uint32_t *span; /* source bytes of the word: [2i] start, [2i+1] end */
    int n;
    int cap;
} sh_argv_t;

static void sh_argv_build(sh_t *s, TSNode cmd, sh_argv_t *out);

static void sh_argv_free(sh_argv_t *a) {
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)a->v);
    cbm_free(CBM_MEM_CLASS_OTHER, a->split);
    cbm_free(CBM_MEM_CLASS_OTHER, a->span);
    *a = (sh_argv_t){0};
}

/* The command a statement runs: the body of a redirection. */
static TSNode sh_unwrap(TSNode n) {
    while (sh_type(n, "redirected_statement")) {
        TSNode body = ts_node_child_by_field_name(n, TS_FIELD("body"));
        if (ts_node_is_null(body)) {
            break;
        }
        n = body;
    }
    return n;
}

/* The first non-option argument after argv[0]. */
static const char *sh_first_operand(const sh_argv_t *a, int from) {
    for (int i = from; i < a->n; i++) {
        if (a->v[i] && a->v[i][0] == '-' && a->v[i][SKIP_ONE]) {
            continue;
        }
        return a->v[i];
    }
    return NULL;
}

/* $(dirname ..), $(basename ..), $(pwd), $(realpath ..), $(readlink -f ..),
 * $(git rev-parse --show-toplevel). */
static const char *sh_eval_subst_command(sh_t *s, TSNode cmd) {
    sh_argv_t a = {0};
    sh_argv_build(s, cmd, &a);
    const char *out = NULL;
    const char *name = a.n > 0 ? a.v[0] : NULL;
    if (sh_eq(name, "dirname") && a.n == PAIR_LEN && a.v[SKIP_ONE]) {
        out = sh_dirname(s->a, a.v[SKIP_ONE]);
    } else if (sh_eq(name, "basename") && a.n == PAIR_LEN && a.v[SKIP_ONE]) {
        out = sh_value_basename(s->a, a.v[SKIP_ONE]);
    } else if (sh_eq(name, "pwd")) {
        out = sh_cwd_value(s);
    } else if (sh_eq(name, "realpath") ||
               (sh_eq(name, "readlink") && a.n > PAIR_LEN && a.v[SKIP_ONE] &&
                (sh_eq(a.v[SKIP_ONE], "-f") || sh_eq(a.v[SKIP_ONE], "-e") ||
                 sh_eq(a.v[SKIP_ONE], "-m")))) {
        out = sh_absolute(s, sh_first_operand(&a, SKIP_ONE));
    } else if (sh_eq(name, "git") && a.n == 3 && sh_eq(a.v[SKIP_ONE], "rev-parse") &&
               sh_eq(a.v[PAIR_LEN], "--show-toplevel")) {
        out = SH_ROOT;
    }
    sh_argv_free(&a);
    return out;
}

/* `cd DIR` as the left half of $(cd DIR && pwd): the directory, or NULL. */
static const char *sh_subst_cd(sh_t *s, TSNode cd) {
    cd = sh_unwrap(cd);
    if (!sh_type(cd, "command")) {
        return NULL;
    }
    sh_argv_t a = {0};
    sh_argv_build(s, cd, &a);
    const char *out = NULL;
    if (a.n > 0 && sh_eq(a.v[0], "cd")) {
        sh_cwd_t to = {SH_LOST, NULL};
        (void)sh_cd_target(s, sh_first_operand(&a, SKIP_ONE), &to);
        out = to.mode == SH_AT ? sh_anchor(s->a, to.dir) : NULL;
    }
    sh_argv_free(&a);
    return out;
}

static bool sh_is_pwd(sh_t *s, TSNode n) {
    n = sh_unwrap(n);
    if (!sh_type(n, "command")) {
        return false;
    }
    sh_argv_t a = {0};
    sh_argv_build(s, n, &a);
    bool pwd = a.n > 0 && sh_eq(a.v[0], "pwd");
    sh_argv_free(&a);
    return pwd;
}

static const char *sh_eval_subst(sh_t *s, TSNode n) {
    TSNode st[PAIR_LEN];
    int k = 0;
    for (uint32_t i = 0; i < ts_node_named_child_count(n); i++) {
        TSNode c = ts_node_named_child(n, i);
        if (sh_type(c, "comment")) {
            continue;
        }
        if (k == PAIR_LEN) {
            return NULL;
        }
        st[k++] = c;
    }
    if (k == SKIP_ONE && sh_type(st[0], "list") && ts_node_named_child_count(st[0]) == PAIR_LEN) {
        TSNode l = st[0];
        st[0] = ts_node_named_child(l, 0);
        st[SKIP_ONE] = ts_node_named_child(l, SKIP_ONE);
        k = PAIR_LEN;
    }
    if (k == PAIR_LEN) {
        return sh_is_pwd(s, st[SKIP_ONE]) ? sh_subst_cd(s, st[0]) : NULL;
    }
    if (k == SKIP_ONE) {
        TSNode c = sh_unwrap(st[0]);
        return sh_type(c, "command") ? sh_eval_subst_command(s, c) : NULL;
    }
    return NULL;
}

static const char *sh_eval(sh_t *s, TSNode n) {
    if (ts_node_is_null(n)) {
        return NULL;
    }
    const char *t = ts_node_type(n);
    uint32_t b = ts_node_start_byte(n);
    uint32_t e = ts_node_end_byte(n);
    if (strcmp(t, "word") == 0 || strcmp(t, "number") == 0 || strcmp(t, "extglob_pattern") == 0) {
        if (s->src[b] == '~') {
            return NULL;
        }
        sh_str_t out = {0};
        sh_add_unescaped(s->a, &out, s->src + b, e - b, false);
        return sh_str_done(&out);
    }
    if (strcmp(t, "raw_string") == 0) {
        return e - b >= PAIR_LEN ? cbm_arena_strndup(s->a, s->src + b + SKIP_ONE, e - b - PAIR_LEN)
                                 : NULL;
    }
    if (strcmp(t, "string") == 0 || strcmp(t, "concatenation") == 0) {
        sh_str_t out = {0};
        bool dq = strcmp(t, "string") == 0;
        uint32_t from = dq ? b + SKIP_ONE : b;
        uint32_t to = dq && e > b + SKIP_ONE ? e - SKIP_ONE : e;
        sh_concat(s, &out, n, from, to, dq);
        return sh_str_done(&out);
    }
    if (strcmp(t, "simple_expansion") == 0) {
        TSNode v = ts_node_named_child(n, 0);
        const char *nm = ts_node_is_null(v) ? NULL : sh_text(s, v);
        if (!nm) {
            return NULL;
        }
        bool found = false;
        const sh_val_t *val = sh_lookup(s, nm, &found);
        return found ? val->s : NULL;
    }
    if (strcmp(t, "expansion") == 0) {
        return sh_eval_expansion(s, n);
    }
    if (strcmp(t, "command_substitution") == 0) {
        return sh_eval_subst(s, n);
    }
    return NULL;
}

/* A command word: its value; an option whose value is unknown is still that
 * option (--context="${ctx}" -> "--context="). */
static const char *sh_eval_word(sh_t *s, TSNode w) {
    const char *v = sh_eval(s, w);
    if (v || s->src[ts_node_start_byte(w)] != '-') {
        return v;
    }
    uint32_t b = ts_node_start_byte(w);
    uint32_t e = b;
    while (e < ts_node_end_byte(w) && !strchr("$\"'`\\", s->src[e])) {
        e++;
    }
    return cbm_arena_strndup(s->a, s->src + b, e - b);
}

/* "${name[@]}" / ${name[*]} as a whole word: the array, NULL when not. */
static const sh_val_t *sh_array_word(sh_t *s, TSNode w) {
    if (sh_type(w, "string") && ts_node_named_child_count(w) == SKIP_ONE) {
        w = ts_node_named_child(w, 0);
    }
    if (!sh_type(w, "expansion") || ts_node_named_child_count(w) != SKIP_ONE) {
        return NULL;
    }
    TSNode sub = ts_node_named_child(w, 0);
    if (!sh_type(sub, "subscript")) {
        return NULL;
    }
    TSNode base = ts_node_child_by_field_name(sub, TS_FIELD("name"));
    TSNode idx = ts_node_child_by_field_name(sub, TS_FIELD("index"));
    const char *it = ts_node_is_null(idx) ? NULL : sh_text(s, idx);
    if (ts_node_is_null(base) || !it || (strcmp(it, "@") != 0 && strcmp(it, "*") != 0)) {
        return NULL;
    }
    bool found = false;
    const sh_val_t *v = sh_lookup(s, sh_text(s, base), &found);
    return v;
}

/* An unquoted expansion may split into several words. */
static bool sh_may_split(TSNode w) {
    const char *t = ts_node_type(w);
    if (strcmp(t, "simple_expansion") == 0 || strcmp(t, "expansion") == 0 ||
        strcmp(t, "command_substitution") == 0) {
        return true;
    }
    if (strcmp(t, "concatenation") == 0) {
        for (uint32_t i = 0; i < ts_node_named_child_count(w); i++) {
            if (sh_may_split(ts_node_named_child(w, i))) {
                return true;
            }
        }
    }
    return false;
}

static void sh_argv_push(sh_argv_t *a, const char *v, bool split, uint32_t b, uint32_t e) {
    if (a->n >= a->cap) {
        int ncap = a->cap ? a->cap * PAIR_LEN : SH_GROW_MIN;
        const char **nv =
            cbm_realloc(CBM_MEM_CLASS_OTHER, (void *)a->v, (size_t)ncap * sizeof(*nv));
        if (!nv) {
            return;
        }
        a->v = nv;
        bool *ns = cbm_realloc(CBM_MEM_CLASS_OTHER, a->split, (size_t)ncap * sizeof(*ns));
        if (!ns) {
            return;
        }
        a->split = ns;
        uint32_t *nsp =
            cbm_realloc(CBM_MEM_CLASS_OTHER, a->span, (size_t)ncap * PAIR_LEN * sizeof(*nsp));
        if (!nsp) {
            return;
        }
        a->span = nsp;
        a->cap = ncap;
    }
    a->v[a->n] = v;
    a->split[a->n] = split;
    a->span[PAIR_LEN * a->n] = b;
    a->span[PAIR_LEN * a->n + SKIP_ONE] = e;
    a->n++;
}

static void sh_argv_word(sh_t *s, TSNode w, sh_argv_t *out) {
    uint32_t b = ts_node_start_byte(w);
    uint32_t e = ts_node_end_byte(w);
    const sh_val_t *arr = sh_array_word(s, w);
    if (arr) {
        if (!arr->items) {
            sh_argv_push(out, NULL, true, b, e);
            return;
        }
        for (int i = 0; i < arr->n; i++) {
            sh_argv_push(out, arr->items[i], false, b, e);
        }
        return;
    }
    const char *v = sh_eval_word(s, w);
    sh_argv_push(out, v, v ? false : sh_may_split(w), b, e);
}

/* argv of a command: its name and arguments, evaluated (NULL: unknown). */
static void sh_argv_build(sh_t *s, TSNode cmd, sh_argv_t *out) {
    uint32_t cc = ts_node_child_count(cmd);
    for (uint32_t i = 0; i < cc; i++) {
        const char *field = ts_node_field_name_for_child(cmd, i);
        TSNode c = ts_node_child(cmd, i);
        if (sh_eq(field, "name")) {
            TSNode w = ts_node_named_child(c, 0);
            if (!ts_node_is_null(w)) {
                sh_argv_word(s, w, out);
            }
        } else if (sh_eq(field, "argument")) {
            sh_argv_word(s, c, out);
        }
    }
}

/* ── Paths to targets ──────────────────────────────────────────────── */

typedef struct {
    bool recursive;
    const char *name; /* find -name glob; NULL: any */
    int maxdepth;     /* find -maxdepth; SH_NO_DEPTH: none */
} sh_find_t;

typedef int (*sh_target_fn)(sh_t *s, const char *path, const sh_find_t *f, sh_targets_t *out);

/* Candidate repository paths of a value: the anchored path; a relative one
 * in the tracked directory, or -- none tracked -- in the root and in the
 * script's directory. */
static int sh_candidates(sh_t *s, const char *v, const char *out[PAIR_LEN]) {
    if (!v || !v[0] || strstr(v, "://")) {
        return 0;
    }
    if (v[0] == SH_ANCHOR) {
        out[0] = sh_join(s->a, "", v + SKIP_ONE);
        return out[0] ? SKIP_ONE : 0;
    }
    if (v[0] == '/' || v[0] == '~') {
        return 0;
    }
    if (s->cwd.mode == SH_LOST) {
        return 0;
    }
    if (s->cwd.mode == SH_AT) {
        out[0] = sh_join(s->a, s->cwd.dir, v);
        return out[0] ? SKIP_ONE : 0;
    }
    int n = 0;
    const char *r = sh_join(s->a, "", v);
    const char *d = sh_join(s->a, s->sdir, v);
    if (r) {
        out[n++] = r;
    }
    if (d && (!r || strcmp(d, r) != 0)) {
        out[n++] = d;
    }
    return n;
}

/* The targets of value `v`: of its one candidate, or of the only one of two
 * candidates that has any. */
static void sh_targets_of(sh_t *s, const char *v, sh_target_fn fn, const sh_find_t *f,
                          sh_targets_t *out) {
    const char *c[PAIR_LEN] = {NULL, NULL};
    int n = sh_candidates(s, v, c);
    int mark = out->count;
    int found = 0;
    for (int i = 0; i < n; i++) {
        if (fn(s, c[i], f, out) > 0) {
            found++;
        }
    }
    if (found > SKIP_ONE) {
        out->count = mark;
    }
}

static bool sh_glob_seg(const char *p, size_t pn, const char *t, size_t tn) {
    size_t pi = 0;
    size_t ti = 0;
    size_t star = (size_t)-1;
    size_t mark = 0;
    while (ti < tn) {
        if (pi < pn && (p[pi] == '?' || p[pi] == t[ti])) {
            pi++;
            ti++;
        } else if (pi < pn && p[pi] == '*') {
            star = pi++;
            mark = ti;
        } else if (star != (size_t)-1) {
            pi = star + SKIP_ONE;
            ti = ++mark;
        } else {
            return false;
        }
    }
    while (pi < pn && p[pi] == '*') {
        pi++;
    }
    return pi == pn;
}

/* A path glob: * and ? within a segment, segment for segment. */
static bool sh_glob_path(const char *pat, const char *path) {
    for (;;) {
        size_t pl = strcspn(pat, "/");
        size_t tl = strcspn(path, "/");
        if (!sh_glob_seg(pat, pl, path, tl)) {
            return false;
        }
        if (!pat[pl] || !path[tl]) {
            return !pat[pl] && !path[tl];
        }
        pat += pl + SKIP_ONE;
        path += tl + SKIP_ONE;
    }
}

static int sh_add_manifest(sh_t *s, const char *p, sh_targets_t *out) {
    int64_t id = (int64_t)(intptr_t)cbm_ht_get(s->ix->file_ids, p);
    if (id <= 0) {
        return 0;
    }
    sh_targets_push(out, id, p);
    return SKIP_ONE;
}

/* kubectl -f PATH: the manifest, a directory's manifests, a glob's. */
static int sh_t_files(sh_t *s, const char *path, const sh_find_t *f, sh_targets_t *out) {
    const sh_paths_t *m = &s->ix->manifests;
    char key[CBM_SZ_4K];
    int lo = 0;
    int hi = 0;
    int added = 0;
    if (strpbrk(path, "*?[")) {
        if (strchr(path, '[')) {
            return 0;
        }
        const char *g = strpbrk(path, "*?");
        size_t dl = (size_t)(g - path);
        while (dl > 0 && path[dl - SKIP_ONE] != '/') {
            dl--;
        }
        char dir[CBM_SZ_4K];
        snprintf(dir, sizeof(dir), "%.*s", (int)(dl ? dl - SKIP_ONE : 0), path);
        sh_range(m, dir, key, sizeof(key), &lo, &hi);
        for (int i = lo; i < hi; i++) {
            atomic_fetch_add_explicit(&g_sh_candidates, SKIP_ONE, memory_order_relaxed);
            if (sh_glob_path(path, m->items[i])) {
                added += sh_add_manifest(s, m->items[i], out);
            }
        }
        return added;
    }
    if (sh_paths_has(m, path)) {
        return sh_add_manifest(s, path, out);
    }
    sh_range(m, path, key, sizeof(key), &lo, &hi);
    size_t kl = strlen(key);
    for (int i = lo; i < hi; i++) {
        atomic_fetch_add_explicit(&g_sh_candidates, SKIP_ONE, memory_order_relaxed);
        if (f->recursive || !strchr(m->items[i] + kl, '/')) {
            added += sh_add_manifest(s, m->items[i], out);
        }
    }
    return added;
}

/* find DIR -name G: DIR's manifests (to -maxdepth) whose name matches. */
static int sh_t_found(sh_t *s, const char *dir, const sh_find_t *f, sh_targets_t *out) {
    const sh_paths_t *m = &s->ix->manifests;
    char key[CBM_SZ_4K];
    int lo = 0;
    int hi = 0;
    int added = 0;
    if (!sh_dir_exists(s->ix, dir)) {
        return 0;
    }
    sh_range(m, dir, key, sizeof(key), &lo, &hi);
    size_t kl = strlen(key);
    for (int i = lo; i < hi; i++) {
        atomic_fetch_add_explicit(&g_sh_candidates, SKIP_ONE, memory_order_relaxed);
        const char *rest = m->items[i] + kl;
        int depth = SKIP_ONE;
        for (const char *p = rest; *p; p++) {
            depth += *p == '/';
        }
        const char *base = sh_basename(rest);
        if ((f->maxdepth == SH_NO_DEPTH || depth <= f->maxdepth) &&
            (!f->name || sh_glob_seg(f->name, strlen(f->name), base, strlen(base)))) {
            added += sh_add_manifest(s, m->items[i], out);
        }
    }
    return added;
}

/* -k DIR / kustomize build DIR: the Kustomization of DIR. */
static int sh_t_kust(sh_t *s, const char *dir, const sh_find_t *f, sh_targets_t *out) {
    (void)f;
    static const char *const names[] = {"kustomization.yaml", "kustomization.yml", "Kustomization"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        const char *p = cbm_arena_sprintf(s->a, "%s%s%s", dir, dir[0] ? "/" : "", names[i]);
        const char *key = p ? cbm_ht_get_key(s->ix->kusts, p) : NULL;
        if (key) {
            sh_targets_push(out, (int64_t)(intptr_t)cbm_ht_get(s->ix->kusts, key), dir);
            return SKIP_ONE;
        }
    }
    return 0;
}

/* A chart directory: its Chart. */
static int sh_t_chart(sh_t *s, const char *dir, const sh_find_t *f, sh_targets_t *out) {
    (void)f;
    static const char *const names[] = {"Chart.yaml", "Chart.yml"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        const char *p = cbm_arena_sprintf(s->a, "%s%s%s", dir, dir[0] ? "/" : "", names[i]);
        const char *key = p ? cbm_ht_get_key(s->ix->charts, p) : NULL;
        if (key) {
            sh_targets_push(out, (int64_t)(intptr_t)cbm_ht_get(s->ix->charts, key), dir);
            return SKIP_ONE;
        }
    }
    return 0;
}

/* Where `cd v` lands: *out = AT an existing directory, else LOST. */
static const char *sh_cd_target(sh_t *s, const char *v, sh_cwd_t *out) {
    *out = (sh_cwd_t){SH_LOST, NULL};
    if (!v) {
        return NULL;
    }
    const char *c[PAIR_LEN] = {NULL, NULL};
    int n = sh_candidates(s, v, c);
    const char *hit = NULL;
    for (int i = 0; i < n; i++) {
        if (sh_dir_exists(s->ix, c[i])) {
            if (hit) {
                return NULL;
            }
            hit = c[i];
        }
    }
    if (hit) {
        *out = (sh_cwd_t){SH_AT, hit};
    }
    return hit;
}

/* ── Deploy commands ───────────────────────────────────────────────── */

static void sh_hit(sh_t *s, TSNode cmd, const char *via, const sh_target_t *t, const char *ext,
                   bool chart) {
    sh_hits_t *h = s->hits;
    if (!sh_grow((void **)&h->items, &h->cap, h->count, sizeof(*h->items))) {
        return;
    }
    const char *path = t ? t->path : ext;
    h->items[h->count++] =
        (sh_hit_t){.file = s->file,
                   .line = (int)ts_node_start_point(cmd).row + SKIP_ONE + s->line_base,
                   .via = via,
                   .tgt = t ? t->id : 0,
                   .ext = ext ? cbm_arena_strdup(&h->arena, ext) : NULL,
                   .path = path ? cbm_arena_strdup(&h->arena, path) : NULL,
                   .chart = chart};
}

static void sh_hit_all(sh_t *s, TSNode cmd, const char *via, const sh_targets_t *ts, bool chart) {
    for (int i = 0; i < ts->count; i++) {
        sh_hit(s, cmd, via, &ts->items[i], NULL, chart);
    }
}

static bool sh_in(const char *v, const char *const *set) {
    for (int i = 0; v && set[i]; i++) {
        if (strcmp(v, set[i]) == 0) {
            return true;
        }
    }
    return false;
}

static bool sh_numberish(const char *v) {
    if (!v[0] || v[0] < '0' || v[0] > '9') {
        return false;
    }
    for (const char *p = v; *p; p++) {
        if (!((*p >= '0' && *p <= '9') || *p == '.' || strchr("smhd", *p))) {
            return false;
        }
    }
    return true;
}

/* The index of the program argv runs, past wrappers (time, sudo, retry N,
 * timeout D, env A=B, ...); -1 when argv has none. Its value may be unknown
 * (NULL). */
static int sh_program(const sh_argv_t *a) {
    static const char *const wrappers[] = {"time",    "sudo", "exec",    "nice",  "nohup",
                                           "command", "env",  "timeout", "retry", NULL};
    int i = 0;
    while (i < a->n) {
        if (!a->v[i] || !sh_in(sh_basename(a->v[i]), wrappers)) {
            return i;
        }
        if (strcmp(a->v[i], "command") == 0 && i + SKIP_ONE < a->n &&
            (sh_eq(a->v[i + SKIP_ONE], "-v") || sh_eq(a->v[i + SKIP_ONE], "-V"))) {
            return -1; /* command -v X: is there an X, not a run of it */
        }
        i++;
        while (i < a->n && a->v[i] &&
               (a->v[i][0] == '-' || strchr(a->v[i], '=') || sh_numberish(a->v[i]))) {
            i++;
        }
    }
    return -1;
}

/* kubectl's options that take a separate value (before the verb). */
static const char *const SH_KUBECTL_VALUED[] = {"-n",
                                                "--namespace",
                                                "--context",
                                                "--kubeconfig",
                                                "--cluster",
                                                "--user",
                                                "-l",
                                                "--selector",
                                                "-o",
                                                "--output",
                                                "--server",
                                                "-s",
                                                "--token",
                                                "--as",
                                                "--as-group",
                                                "--request-timeout",
                                                "--cache-dir",
                                                "--certificate-authority",
                                                "--client-certificate",
                                                "--client-key",
                                                NULL};

/* helm's options that take a separate value. */
static const char *const SH_HELM_VALUED[] = {"-n",
                                             "--namespace",
                                             "-f",
                                             "--values",
                                             "--set",
                                             "--set-string",
                                             "--set-file",
                                             "--set-json",
                                             "--set-literal",
                                             "--version",
                                             "--timeout",
                                             "--kubeconfig",
                                             "--kube-context",
                                             "--repo",
                                             "--post-renderer",
                                             "--post-renderer-args",
                                             "--description",
                                             "--username",
                                             "--password",
                                             "--ca-file",
                                             "--cert-file",
                                             "--key-file",
                                             "--keyring",
                                             "--history-max",
                                             "--name-template",
                                             "--registry-config",
                                             "--repository-config",
                                             "--repository-cache",
                                             "-o",
                                             "--output",
                                             "--api-versions",
                                             "-a",
                                             "--kube-version",
                                             "--labels",
                                             "-l",
                                             "--show-only",
                                             "-s",
                                             "--output-dir",
                                             "--release-name",
                                             "--kube-apiserver",
                                             "--kube-as-user",
                                             "--kube-as-group",
                                             "--kube-ca-file",
                                             "--kube-token",
                                             "--burst-limit",
                                             "--qps",
                                             NULL};

typedef enum { SH_SRC_NONE, SH_SRC_KUST, SH_SRC_CHART } sh_src_kind_t;

typedef struct {
    sh_src_kind_t kind;
    const char *v;
    const char *via;
} sh_src_t;

typedef struct {
    int verb; /* index of the verb in argv; -1 none */
    const char **files;
    int nfiles;
    const char **kusts;
    int nkusts;
    int cap_files;
    int cap_kusts;
    bool recursive;
} sh_kubectl_t;

static void sh_kubectl_free(sh_kubectl_t *k) {
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)k->files);
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)k->kusts);
}

static void sh_kubectl_add(const char ***v, int *n, int *cap, const char *p) {
    if (sh_grow((void **)v, cap, *n, sizeof(**v))) {
        (*v)[(*n)++] = p;
    }
}

/* kubectl [options] VERB ...: the verb and its -f / -k / -R. */
static void sh_kubectl_parse(const sh_argv_t *a, int from, sh_kubectl_t *k) {
    k->verb = -1;
    int i = from;
    while (i < a->n && k->verb < 0) {
        const char *w = a->v[i];
        if (!w) {
            return;
        }
        if (w[0] != '-') {
            k->verb = i++;
            break;
        }
        i += (sh_in(w, SH_KUBECTL_VALUED) && !strchr(w, '=')) ? PAIR_LEN : SKIP_ONE;
    }
    for (; i < a->n; i++) {
        const char *w = a->v[i];
        if (!w || w[0] != '-') {
            continue;
        }
        const char *next = i + SKIP_ONE < a->n ? a->v[i + SKIP_ONE] : NULL;
        if (strcmp(w, "--recursive") == 0) {
            k->recursive = true;
        } else if (strcmp(w, "--filename") == 0 || strcmp(w, "--kustomize") == 0) {
            bool fl = w[PAIR_LEN] == 'f';
            sh_kubectl_add(fl ? &k->files : &k->kusts, fl ? &k->nfiles : &k->nkusts,
                           fl ? &k->cap_files : &k->cap_kusts, next);
            i++;
        } else if (sh_starts(w, "--filename=")) {
            sh_kubectl_add(&k->files, &k->nfiles, &k->cap_files, strchr(w, '=') + SKIP_ONE);
        } else if (sh_starts(w, "--kustomize=")) {
            sh_kubectl_add(&k->kusts, &k->nkusts, &k->cap_kusts, strchr(w, '=') + SKIP_ONE);
        } else if (w[SKIP_ONE] != '-') {
            /* a cluster of short options: -f, -k, -R, -Rf */
            size_t len = strlen(w);
            bool ok = len > SKIP_ONE;
            for (size_t c = SKIP_ONE; c < len; c++) {
                ok = ok && ((w[c] >= 'a' && w[c] <= 'z') || (w[c] >= 'A' && w[c] <= 'Z'));
            }
            if (!ok) {
                continue;
            }
            if (strchr(w, 'R')) {
                k->recursive = true;
            }
            char last = w[len - SKIP_ONE];
            if (last == 'f' || last == 'k') {
                sh_kubectl_add(last == 'f' ? &k->files : &k->kusts,
                               last == 'f' ? &k->nfiles : &k->nkusts,
                               last == 'f' ? &k->cap_files : &k->cap_kusts, next);
                i++;
            }
        }
    }
}

static void sh_deploy_src(sh_t *s, TSNode cmd, const sh_src_t *src);

/* kubectl: apply / create / replace -f / -k, or `kubectl kustomize D` as a
 * pipe's source. */
static void sh_kubectl(sh_t *s, TSNode cmd, const sh_argv_t *a, int prog, const sh_src_t *in,
                       sh_src_t *out) {
    sh_kubectl_t k = {0};
    sh_kubectl_parse(a, prog + SKIP_ONE, &k);
    const char *verb = k.verb >= 0 ? a->v[k.verb] : NULL;
    if (sh_eq(verb, "kustomize")) {
        const char *d = sh_first_operand(a, k.verb + SKIP_ONE);
        *out = (sh_src_t){SH_SRC_KUST, d ? d : ".", "kustomize"};
    } else if (sh_eq(verb, "apply") || sh_eq(verb, "create") || sh_eq(verb, "replace")) {
        sh_find_t f = {k.recursive, NULL, SH_NO_DEPTH};
        for (int i = 0; i < k.nfiles; i++) {
            if (sh_eq(k.files[i], "-")) {
                sh_deploy_src(s, cmd, in);
                continue;
            }
            sh_targets_t ts = {0};
            sh_targets_of(s, k.files[i], sh_t_files, &f, &ts);
            sh_hit_all(s, cmd, "kubectl", &ts, false);
            cbm_free(CBM_MEM_CLASS_OTHER, ts.items);
        }
        for (int i = 0; i < k.nkusts; i++) {
            sh_targets_t ts = {0};
            sh_targets_of(s, k.kusts[i], sh_t_kust, &f, &ts);
            sh_hit_all(s, cmd, "kubectl", &ts, false);
            cbm_free(CBM_MEM_CLASS_OTHER, ts.items);
        }
    }
    sh_kubectl_free(&k);
}

/* The chart a helm word names: a chart dir, else an external chart. */
static void sh_chart(sh_t *s, TSNode cmd, const char *v) {
    if (!v) {
        return;
    }
    if (sh_starts(v, "oci://")) {
        const char *ext = sh_value_basename(s->a, v + strlen("oci://"));
        if (ext && ext[0] && !strchr(ext, ':')) {
            sh_hit(s, cmd, "helm", NULL, ext, true);
        }
        return;
    }
    sh_targets_t ts = {0};
    sh_targets_of(s, v, sh_t_chart, NULL, &ts);
    if (ts.count > 0) {
        sh_hit_all(s, cmd, "helm", &ts, true);
        cbm_free(CBM_MEM_CLASS_OTHER, ts.items);
        return;
    }
    cbm_free(CBM_MEM_CLASS_OTHER, ts.items);
    /* repo/name: one slash, a plain name on each side */
    const char *slash = strchr(v, '/');
    if (!slash || strchr(slash + SKIP_ONE, '/') || v[0] == '.' || slash == v || !slash[SKIP_ONE]) {
        return;
    }
    for (const char *p = v; *p; p++) {
        if (!(*p == '/' || *p == '.' || *p == '_' || *p == '-' || (*p >= '0' && *p <= '9') ||
              (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z'))) {
            return;
        }
    }
    sh_hit(s, cmd, "helm", NULL, slash + SKIP_ONE, true);
}

/* helm install|upgrade [NAME] CHART; helm template [NAME] CHART as a source. */
static void sh_helm(sh_t *s, TSNode cmd, const sh_argv_t *a, int prog, sh_src_t *out) {
    const char *verb = NULL;
    int pos[PAIR_LEN] = {0, 0};
    int npos = 0;
    int first_split = SH_NO_DEPTH; /* an unknown unquoted word: maybe several */
    bool gen = false;
    for (int i = prog + SKIP_ONE; i < a->n; i++) {
        const char *w = a->v[i];
        if (w && w[0] == '-') {
            gen = gen || strcmp(w, "--generate-name") == 0 || strcmp(w, "-g") == 0;
            if (sh_in(w, SH_HELM_VALUED) && !strchr(w, '=')) {
                i++;
            }
            continue;
        }
        if (!verb) {
            if (!w) {
                return;
            }
            verb = w;
            continue;
        }
        if (!w && a->split[i] && first_split == SH_NO_DEPTH) {
            first_split = npos;
        }
        if (npos < PAIR_LEN) {
            pos[npos] = i;
        }
        npos++;
    }
    if (!verb) {
        return;
    }
    if (strcmp(verb, "install") == 0 || strcmp(verb, "upgrade") == 0) {
        int at = gen ? 0 : SKIP_ONE;
        if (npos > at && (first_split == SH_NO_DEPTH || first_split > at)) {
            sh_chart(s, cmd, a->v[pos[at]]);
        }
    } else if (strcmp(verb, "template") == 0 && npos > 0 &&
               (first_split == SH_NO_DEPTH || first_split > SKIP_ONE)) {
        int at = npos >= PAIR_LEN ? SKIP_ONE : 0;
        *out = (sh_src_t){SH_SRC_CHART, a->v[pos[at]], "helm"};
    }
}

/* What a `kubectl apply -f -` reading the pipe deploys. */
static void sh_deploy_src(sh_t *s, TSNode cmd, const sh_src_t *src) {
    if (!src || src->kind == SH_SRC_NONE || !src->v) {
        return;
    }
    if (src->kind == SH_SRC_CHART) {
        sh_chart(s, cmd, src->v);
        return;
    }
    sh_targets_t ts = {0};
    sh_targets_of(s, src->v, sh_t_kust, NULL, &ts);
    sh_hit_all(s, cmd, src->via, &ts, false);
    cbm_free(CBM_MEM_CLASS_OTHER, ts.items);
}

/* find DIR [-type f] [-name G] [-maxdepth N] -exec kubectl apply -f {} \; */
static void sh_find(sh_t *s, TSNode cmd, const sh_argv_t *a, int prog) {
    int i = prog + SKIP_ONE;
    if (i >= a->n || !a->v[i] || a->v[i][0] == '-') {
        return;
    }
    const char *root = a->v[i++];
    sh_find_t f = {false, NULL, SH_NO_DEPTH};
    while (i < a->n) {
        const char *w = a->v[i];
        const char *next = i + SKIP_ONE < a->n ? a->v[i + SKIP_ONE] : NULL;
        if (!w) {
            return;
        }
        if (strcmp(w, "-exec") == 0) {
            break;
        }
        if (strcmp(w, "-name") == 0 && next) {
            f.name = next;
        } else if (strcmp(w, "-maxdepth") == 0 && next && sh_numberish(next)) {
            f.maxdepth = (int)strtol(next, NULL, SH_DEC);
        } else if (!(strcmp(w, "-type") == 0 && sh_eq(next, "f"))) {
            return;
        }
        i += PAIR_LEN; /* each test takes one value */
    }
    /* -exec PROGRAM ... {} ; */
    sh_argv_t e = {0};
    for (i++; i < a->n && !sh_eq(a->v[i], ";") && !sh_eq(a->v[i], "+"); i++) {
        sh_argv_push(&e, a->v[i], a->split[i], a->span[PAIR_LEN * i],
                     a->span[PAIR_LEN * i + SKIP_ONE]);
    }
    int p = sh_program(&e);
    if (p >= 0 && e.v[p] && strcmp(sh_basename(e.v[p]), "kubectl") == 0) {
        sh_kubectl_t k = {0};
        sh_kubectl_parse(&e, p + SKIP_ONE, &k);
        const char *verb = k.verb >= 0 ? e.v[k.verb] : NULL;
        if ((sh_eq(verb, "apply") || sh_eq(verb, "create") || sh_eq(verb, "replace")) &&
            k.nfiles == SKIP_ONE && k.nkusts == 0 && sh_eq(k.files[0], "{}")) {
            sh_targets_t ts = {0};
            sh_targets_of(s, root, sh_t_found, &f, &ts);
            sh_hit_all(s, cmd, "kubectl", &ts, false);
            cbm_free(CBM_MEM_CLASS_OTHER, ts.items);
        }
        sh_kubectl_free(&k);
    }
    sh_argv_free(&e);
}

/* One command of a pipeline (or a lone one): its deploys; *out: what it
 * writes to the pipe, when that is a kustomize build or a helm template. */
static void sh_deploy_command(sh_t *s, TSNode cmd, const sh_argv_t *a, const sh_src_t *in,
                              sh_src_t *out) {
    *out = (sh_src_t){SH_SRC_NONE, NULL, NULL};
    int prog = sh_program(a);
    if (prog < 0 || !a->v[prog]) {
        return;
    }
    const char *base = sh_basename(a->v[prog]);
    if (strcmp(base, "kubectl") == 0) {
        sh_kubectl(s, cmd, a, prog, in, out);
    } else if (strcmp(base, "helm") == 0) {
        sh_helm(s, cmd, a, prog, out);
    } else if (strcmp(base, "kustomize") == 0) {
        const char *verb = sh_first_operand(a, prog + SKIP_ONE);
        if (sh_eq(verb, "build")) {
            int at = SH_NO_DEPTH;
            for (int i = prog + SKIP_ONE; i < a->n; i++) {
                if (a->v[i] == verb) {
                    at = i;
                    break;
                }
            }
            const char *d = at >= 0 ? sh_first_operand(a, at + SKIP_ONE) : NULL;
            *out = (sh_src_t){SH_SRC_KUST, d ? d : ".", "kustomize"};
        }
    } else if (strcmp(base, "find") == 0) {
        sh_find(s, cmd, a, prog);
    }
}

/* A repository file: the path names a File node. */
static int sh_t_repo_file(sh_t *s, const char *path, const sh_find_t *f, sh_targets_t *out) {
    (void)f;
    int64_t id = (int64_t)(intptr_t)cbm_ht_get(s->ix->file_ids, path);
    if (id <= 0) {
        return 0;
    }
    sh_targets_push(out, id, path);
    return SKIP_ONE;
}

/* A program started by a path (./_build/x, ${DIR}/x, $(LOCALBIN)/x) SPAWNS
 * the Process of its name -- the value's last segment, or, the value
 * unknown, the word's literal last segment. A path naming a file of the
 * repository is a script of its own, not linked here. */
static void sh_spawn(sh_t *s, TSNode cmd, const sh_argv_t *a) {
    int p = sh_program(a);
    if (p < 0) {
        return;
    }
    const char *v = a->v[p];
    const char *name = NULL;
    if (v) {
        if (!strchr(v, '/') || strpbrk(v, "*?[")) {
            return;
        }
        const char *c[PAIR_LEN] = {NULL, NULL};
        int n = sh_candidates(s, v, c);
        for (int i = 0; i < n; i++) {
            sh_targets_t ts = {0};
            int hit = sh_t_repo_file(s, c[i], NULL, &ts);
            cbm_free(CBM_MEM_CLASS_OTHER, ts.items);
            if (hit) {
                return;
            }
        }
        name = sh_value_basename(s->a, v);
    } else {
        uint32_t b = a->span[PAIR_LEN * p];
        uint32_t e = a->span[PAIR_LEN * p + SKIP_ONE];
        while (e > b && (s->src[e - SKIP_ONE] == '"' || s->src[e - SKIP_ONE] == '\'')) {
            e--;
        }
        uint32_t k = e;
        while (k > b && s->src[k - SKIP_ONE] != '/') {
            k--;
        }
        if (k == b) {
            return;
        }
        name = cbm_arena_strndup(s->a, s->src + k, e - k);
        if (name && strpbrk(name, "$`*?[]{}()\"' \t\\")) {
            return;
        }
    }
    if (!name || !name[0] || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return;
    }
    sh_hits_t *h = s->hits;
    if (sh_grow((void **)&h->items, &h->cap, h->count, sizeof(*h->items))) {
        h->items[h->count++] =
            (sh_hit_t){.file = s->file,
                       .line = (int)ts_node_start_point(cmd).row + SKIP_ONE + s->line_base,
                       .via = "shell",
                       .ext = cbm_arena_strdup(&h->arena, name),
                       .spawn = true};
    }
}

/* ── Statements ────────────────────────────────────────────────────── */

static void sh_walk(sh_t *s, TSNode n);

static void sh_walk_children(sh_t *s, TSNode n) {
    for (uint32_t i = 0; i < ts_node_named_child_count(n); i++) {
        sh_walk(s, ts_node_named_child(n, i));
    }
}

/* The commands inside $( ) and <( ) of a word, a value or a redirect run
 * too, each in a subshell of its own. */
static void sh_walk_substs(sh_t *s, TSNode n) {
    if (sh_type(n, "command_substitution") || sh_type(n, "process_substitution")) {
        sh_mark_t m = sh_mark(s);
        sh_walk_children(s, n);
        sh_rewind(s, m);
        return;
    }
    for (uint32_t i = 0; i < ts_node_named_child_count(n); i++) {
        sh_walk_substs(s, ts_node_named_child(n, i));
    }
}

static void sh_assign(sh_t *s, TSNode n, bool local) {
    TSNode name = ts_node_child_by_field_name(n, TS_FIELD("name"));
    TSNode value = ts_node_child_by_field_name(n, TS_FIELD("value"));
    if (!ts_node_is_null(value)) {
        sh_walk_substs(s, value);
    }
    if (ts_node_is_null(name)) {
        return;
    }
    if (sh_type(name, "subscript")) {
        TSNode base = ts_node_child_by_field_name(name, TS_FIELD("name"));
        if (!ts_node_is_null(base)) {
            sh_set(s, sh_text(s, base), &SH_UNKNOWN_VAL, local);
        }
        return;
    }
    const char *nm = sh_text(s, name);
    sh_val_t *v = cbm_arena_alloc(s->a, sizeof(*v));
    if (!nm || !v) {
        return;
    }
    *v = (sh_val_t){"", NULL, 0};
    if (sh_type(value, "array")) {
        uint32_t cnt = ts_node_named_child_count(value);
        const char **items = cbm_arena_alloc(s->a, (cnt ? cnt : SKIP_ONE) * sizeof(*items));
        if (!items) {
            return;
        }
        int k = 0;
        for (uint32_t i = 0; i < cnt; i++) {
            TSNode c = ts_node_named_child(value, i);
            if (!sh_type(c, "comment")) {
                items[k++] = sh_eval_word(s, c);
            }
        }
        *v = (sh_val_t){k > 0 ? items[0] : "", items, k};
    } else if (!ts_node_is_null(value)) {
        v->s = sh_eval(s, value);
    }
    bool append = false;
    for (uint32_t i = 0; i < ts_node_child_count(n); i++) {
        TSNode c = ts_node_child(n, i);
        append = append || (!ts_node_is_named(c) && strcmp(ts_node_type(c), "+=") == 0);
    }
    if (append) {
        bool found = false;
        const sh_val_t *prev = sh_lookup(s, nm, &found);
        if (found) {
            v->s = (prev->s && v->s) ? cbm_arena_sprintf(s->a, "%s%s", prev->s, v->s) : NULL;
            v->items = NULL;
        }
    }
    sh_set(s, nm, v, local);
}

/* local / declare / typeset / export / readonly NAME[=VALUE] ... */
static void sh_declare(sh_t *s, TSNode n) {
    TSNode kw = ts_node_child(n, 0);
    const char *k = ts_node_is_null(kw) ? "" : ts_node_type(kw);
    bool local = strcmp(k, "local") == 0 ||
                 (s->in_func && (strcmp(k, "declare") == 0 || strcmp(k, "typeset") == 0));
    bool declares = local || strcmp(k, "declare") == 0 || strcmp(k, "typeset") == 0;
    for (uint32_t i = 0; i < ts_node_named_child_count(n); i++) {
        TSNode c = ts_node_named_child(n, i);
        if (sh_type(c, "variable_assignment")) {
            sh_assign(s, c, local);
        } else if (declares && sh_type(c, "variable_name")) {
            sh_set(s, sh_text(s, c), &SH_UNKNOWN_VAL, local);
        }
    }
}

/* cd / pushd / popd; true when the command is one. */
static bool sh_chdir(sh_t *s, const sh_argv_t *a) {
    const char *name = a->n > 0 ? a->v[0] : NULL;
    if (sh_eq(name, "popd")) {
        s->cwd = s->ndirs > 0 ? s->dirs[--s->ndirs] : (sh_cwd_t){SH_LOST, NULL};
        return true;
    }
    if (!sh_eq(name, "cd") && !sh_eq(name, "pushd")) {
        return false;
    }
    if (sh_eq(name, "pushd")) {
        if (sh_grow((void **)&s->dirs, &s->cap_dirs, s->ndirs, sizeof(*s->dirs))) {
            s->dirs[s->ndirs++] = s->cwd;
        }
    }
    const char *to = sh_first_operand(a, SKIP_ONE);
    sh_cwd_t next = {SH_LOST, NULL};
    if (to && strcmp(to, "-") != 0) {
        (void)sh_cd_target(s, to, &next);
    }
    s->cwd = next;
    return true;
}

static void sh_command(sh_t *s, TSNode cmd) {
    sh_walk_substs(s, cmd);
    sh_argv_t a = {0};
    sh_argv_build(s, cmd, &a);
    if (!sh_chdir(s, &a)) {
        sh_src_t out;
        sh_deploy_command(s, cmd, &a, NULL, &out);
        sh_spawn(s, cmd, &a);
    }
    sh_argv_free(&a);
}

/* The redirects of a statement: `cat <<EOF | kubectl ...` -- the rest of
 * that pipe follows the heredoc start, inside the redirect, and reads the
 * heredoc, not this pipe; `< <(cmd)` runs cmd. */
static void sh_redirects(sh_t *s, TSNode el) {
    for (uint32_t r = 0; sh_type(el, "redirected_statement") && r < ts_node_child_count(el); r++) {
        TSNode red = ts_node_child(el, r);
        if (!ts_node_is_named(red) || sh_eq(ts_node_field_name_for_child(el, r), "body")) {
            continue;
        }
        if (sh_type(red, "heredoc_redirect")) {
            sh_walk_children(s, red);
        } else {
            sh_walk_substs(s, red);
        }
    }
}

/* The elements of a pipeline, in order, with what flows through it. An
 * element that redirects a pipeline continues this one: tree-sitter-bash
 * folds `a | b` followed by a line `cat <<EOF | c` into `a | (b cat | c)`. */
static void sh_pipe_run(sh_t *s, TSNode n, sh_src_t *src) {
    for (uint32_t i = 0; i < ts_node_named_child_count(n); i++) {
        TSNode el = ts_node_named_child(n, i);
        TSNode cmd = sh_unwrap(el);
        if (sh_type(cmd, "pipeline")) {
            sh_pipe_run(s, cmd, src);
            sh_redirects(s, el);
            continue;
        }
        if (!sh_type(cmd, "command")) {
            sh_walk(s, el);
            *src = (sh_src_t){SH_SRC_NONE, NULL, NULL};
            continue;
        }
        sh_walk_substs(s, cmd);
        sh_argv_t a = {0};
        sh_argv_build(s, cmd, &a);
        sh_src_t out;
        sh_deploy_command(s, cmd, &a, src, &out);
        if (out.kind != SH_SRC_NONE) {
            *src = out;
        }
        sh_spawn(s, cmd, &a);
        sh_argv_free(&a);
        sh_redirects(s, el);
    }
}

/* A pipeline: every element runs in a subshell; a kustomize build or helm
 * template feeds the kubectl that reads the pipe. */
static void sh_pipeline(sh_t *s, TSNode n) {
    sh_mark_t m = sh_mark(s);
    sh_src_t src = {SH_SRC_NONE, NULL, NULL};
    sh_pipe_run(s, n, &src);
    sh_rewind(s, m);
}

/* a && b || c: the first runs, the rest only maybe. */
static void sh_list(sh_t *s, TSNode n) {
    sh_touch_t t = {0};
    uint32_t cnt = ts_node_named_child_count(n);
    for (uint32_t i = 0; i < cnt; i++) {
        TSNode c = ts_node_named_child(n, i);
        if (i == 0) {
            sh_walk(s, c);
            continue;
        }
        sh_mark_t m = sh_mark(s);
        sh_walk(s, c);
        sh_clause_end(s, m, &t);
    }
    sh_group_end(s, &t);
}

static void sh_if(sh_t *s, TSNode n) {
    sh_touch_t t = {0};
    sh_mark_t m = {0};
    bool open = false;
    for (uint32_t i = 0; i < ts_node_child_count(n); i++) {
        TSNode c = ts_node_child(n, i);
        if (!ts_node_is_named(c) || sh_type(c, "comment")) {
            continue;
        }
        const char *field = ts_node_field_name_for_child(n, i);
        if (sh_eq(field, "condition")) {
            sh_walk(s, c);
            continue;
        }
        if (sh_type(c, "elif_clause") || sh_type(c, "else_clause")) {
            if (open) {
                sh_clause_end(s, m, &t);
                open = false;
            }
            sh_mark_t mc = sh_mark(s);
            sh_walk_children(s, c);
            sh_clause_end(s, mc, &t);
            continue;
        }
        if (!open) {
            m = sh_mark(s);
            open = true;
        }
        sh_walk(s, c);
    }
    if (open) {
        sh_clause_end(s, m, &t);
    }
    sh_group_end(s, &t);
}

static void sh_case(sh_t *s, TSNode n) {
    TSNode value = ts_node_child_by_field_name(n, TS_FIELD("value"));
    if (!ts_node_is_null(value)) {
        sh_walk_substs(s, value); /* case "$(cmd)" in */
    }
    sh_touch_t t = {0};
    for (uint32_t i = 0; i < ts_node_named_child_count(n); i++) {
        TSNode item = ts_node_named_child(n, i);
        if (!sh_type(item, "case_item")) {
            continue;
        }
        sh_mark_t m = sh_mark(s);
        for (uint32_t j = 0; j < ts_node_child_count(item); j++) {
            TSNode c = ts_node_child(item, j);
            if (ts_node_is_named(c) && !sh_eq(ts_node_field_name_for_child(item, j), "value")) {
                sh_walk(s, c);
            }
        }
        sh_clause_end(s, m, &t);
    }
    sh_group_end(s, &t);
}

/* A loop's body runs zero or more times, with its variable unknown. */
static void sh_loop(sh_t *s, TSNode n) {
    for (uint32_t i = 0; i < ts_node_child_count(n); i++) {
        if (sh_eq(ts_node_field_name_for_child(n, i), "value")) {
            sh_walk_substs(s, ts_node_child(n, i)); /* for x in $(cmd) */
        }
    }
    sh_touch_t t = {0};
    sh_mark_t m = sh_mark(s);
    TSNode var = ts_node_child_by_field_name(n, TS_FIELD("variable"));
    if (!ts_node_is_null(var)) {
        sh_set(s, sh_text(s, var), &SH_UNKNOWN_VAL, false);
    }
    TSNode cond = ts_node_child_by_field_name(n, TS_FIELD("condition"));
    if (!ts_node_is_null(cond)) {
        sh_walk(s, cond);
    }
    TSNode body = ts_node_child_by_field_name(n, TS_FIELD("body"));
    if (!ts_node_is_null(body)) {
        sh_walk_children(s, body);
    }
    sh_clause_end(s, m, &t);
    sh_group_end(s, &t);
}

/* A function body, read where it is defined: its locals stay inside; the
 * globals it sets and a directory it changes are unknown after it. */
static void sh_function(sh_t *s, TSNode n) {
    TSNode body = ts_node_child_by_field_name(n, TS_FIELD("body"));
    if (ts_node_is_null(body)) {
        return;
    }
    sh_mark_t m = sh_mark(s);
    s->in_func++;
    if (sh_type(body, "compound_statement")) {
        sh_walk_children(s, body);
    } else {
        sh_walk(s, body);
    }
    s->in_func--;
    sh_touch_t t = {0};
    CBMHashTable *locals = cbm_ht_create(0);
    for (int i = m.undo; locals && i < s->nundo; i++) {
        if (s->undo[i].local) {
            cbm_ht_set(locals, s->undo[i].name, (void *)s->undo[i].name);
        }
    }
    for (int i = m.undo; i < s->nundo; i++) {
        if (!locals || !cbm_ht_get(locals, s->undo[i].name)) {
            sh_touch_add(&t, s->undo[i].name);
        }
    }
    if (locals) {
        cbm_ht_free(locals);
    }
    t.cwd = !sh_cwd_same(s->cwd, m.cwd) || s->ndirs != m.ndirs;
    sh_rewind(s, m);
    sh_group_end(s, &t);
}

static void sh_walk(sh_t *s, TSNode n) {
    const char *t = ts_node_type(n);
    if (strcmp(t, "program") == 0 || strcmp(t, "compound_statement") == 0 ||
        strcmp(t, "negated_command") == 0) {
        sh_walk_children(s, n);
    } else if (strcmp(t, "variable_assignment") == 0) {
        sh_assign(s, n, false);
    } else if (strcmp(t, "variable_assignments") == 0) {
        for (uint32_t i = 0; i < ts_node_named_child_count(n); i++) {
            sh_assign(s, ts_node_named_child(n, i), false);
        }
    } else if (strcmp(t, "declaration_command") == 0) {
        sh_declare(s, n);
    } else if (strcmp(t, "unset_command") == 0) {
        for (uint32_t i = 0; i < ts_node_named_child_count(n); i++) {
            TSNode c = ts_node_named_child(n, i);
            if (sh_type(c, "variable_name") || sh_type(c, "word")) {
                sh_set(s, sh_text(s, c), &SH_UNKNOWN_VAL, false);
            }
        }
    } else if (strcmp(t, "command") == 0) {
        sh_command(s, n);
    } else if (strcmp(t, "redirected_statement") == 0) {
        TSNode body = ts_node_child_by_field_name(n, TS_FIELD("body"));
        if (!ts_node_is_null(body)) {
            sh_walk(s, body);
        }
        sh_mark_t m = sh_mark(s);
        sh_redirects(s, n);
        sh_rewind(s, m);
    } else if (strcmp(t, "pipeline") == 0) {
        sh_pipeline(s, n);
    } else if (strcmp(t, "list") == 0) {
        sh_list(s, n);
    } else if (strcmp(t, "subshell") == 0) {
        sh_mark_t m = sh_mark(s);
        sh_walk_children(s, n);
        sh_rewind(s, m);
    } else if (strcmp(t, "if_statement") == 0) {
        sh_if(s, n);
    } else if (strcmp(t, "case_statement") == 0) {
        sh_case(s, n);
    } else if (strcmp(t, "for_statement") == 0 || strcmp(t, "c_style_for_statement") == 0 ||
               strcmp(t, "while_statement") == 0) {
        sh_loop(s, n);
    } else if (strcmp(t, "function_definition") == 0) {
        sh_function(s, n);
    } else {
        sh_walk_substs(s, n); /* [[ -n "$(cmd)" ]], ((...)), a bare word */
    }
}

/* ── Files ─────────────────────────────────────────────────────────── */

static bool sh_mentions_deploy_tool(const char *src, size_t n) {
    static const char *const tools[] = {"kubectl", "helm", "kustomize"};
    for (size_t i = 0; i < n; i++) {
        char c = src[i] | ' ';
        if (c != 'k' && c != 'h') {
            continue;
        }
        for (size_t t = 0; t < sizeof(tools) / sizeof(tools[0]); t++) {
            size_t tl = strlen(tools[t]);
            size_t j = 0;
            while (j < tl && i + j < n && (src[i + j] | ' ') == tools[t][j]) {
                j++;
            }
            if (j == tl) {
                return true;
            }
        }
    }
    return false;
}

static char *sh_read(const char *path, size_t *len) {
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
    enum { SH_TS_PAD = 16 }; /* tree-sitter's lexer reads past the end */
    char *buf = cbm_alloc(CBM_MEM_CLASS_OTHER, (size_t)size + SH_TS_PAD);
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }
    size_t got = fread(buf, SKIP_ONE, (size_t)size, f);
    (void)fclose(f);
    memset(buf + got, 0, SH_TS_PAD);
    *len = got;
    return buf;
}

typedef struct {
    sh_index_t *ix;
    sh_hits_t *hits;
    TSParser *parser;
    bool ix_ready;
    bool ix_ok;
} sh_pass_t;

static void sh_state_init(sh_t *s, sh_pass_t *p, CBMArena *a, const char *rel) {
    *s = (sh_t){.ix = p->ix, .hits = p->hits, .a = a, .file = rel};
    s->env = cbm_ht_create(0);
    const char *dir = sh_dirname(a, rel);
    s->sdir = (dir && strcmp(dir, ".") != 0) ? dir : "";
}

static void sh_state_free(sh_t *s) {
    if (s->env) {
        cbm_ht_free(s->env);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, s->undo);
    cbm_free(CBM_MEM_CLASS_OTHER, s->dirs);
}

/* Parse `text` as bash and walk it. */
static void sh_run(sh_t *s, TSParser *parser, const char *text, size_t len) {
    if (!ts_parser_set_language(parser, cbm_ts_language(CBM_LANG_BASH))) {
        return;
    }
    TSTree *tree = ts_parser_parse_string(parser, NULL, text, (uint32_t)len);
    if (!tree) {
        return;
    }
    s->src = text;
    sh_walk(s, ts_tree_root_node(tree));
    ts_tree_delete(tree);
}

static void sh_script(sh_pass_t *p, const char *rel, const char *src, size_t len) {
    CBMArena a;
    cbm_arena_init(&a);
    sh_t s;
    sh_state_init(&s, p, &a, rel);
    if (s.env) {
        s.script = sh_anchor(&a, rel);
        s.cwd = (sh_cwd_t){SH_FREE, NULL};
        sh_run(&s, p->parser, src, len);
    }
    sh_state_free(&s);
    cbm_arena_destroy(&a);
}

/* ── Make ──────────────────────────────────────────────────────────── */

typedef struct {
    const char *raw;      /* the assigned text */
    const char *expanded; /* memo; NULL: not yet */
    bool known;
    bool busy;
} mk_var_t;

/* One recipe line as make runs it: a tab-led line and its \-continuations,
 * without the @ - + prefixes. */
typedef struct {
    uint32_t b; /* source bytes [b, e) */
    uint32_t e;
    uint32_t row; /* 0-based row of b */
} mk_line_t;

typedef struct {
    CBMArena *a;
    const char *src;
    CBMHashTable *vars; /* name -> mk_var_t */
    bool makefile;      /* a Makefile (its recipes run in its dir), not an included .mk */
    mk_line_t *lines;
    int nlines;
    int cap_lines;
} mk_t;

static const char MK_UNKNOWN[] = "${__cbm_unknown}";

static const char *mk_expand(mk_t *m, const char *text);

static const char *mk_lookup(mk_t *m, const char *name) {
    if (strcmp(name, "CURDIR") == 0) {
        return m->makefile ? "${__cbm_curdir}" : MK_UNKNOWN;
    }
    mk_var_t *v = cbm_ht_get(m->vars, name);
    if (!v || !v->known || v->busy) {
        return MK_UNKNOWN;
    }
    if (!v->expanded) {
        v->busy = true;
        v->expanded = mk_expand(m, v->raw);
        v->busy = false;
    }
    return v->expanded ? v->expanded : MK_UNKNOWN;
}

static const char *mk_trim(CBMArena *a, const char *p, size_t n) {
    while (n && (*p == ' ' || *p == '\t')) {
        p++;
        n--;
    }
    while (n && (p[n - SKIP_ONE] == ' ' || p[n - SKIP_ONE] == '\t')) {
        n--;
    }
    return cbm_arena_strndup(a, p, n);
}

/* `cmd` is exactly the words `words` (NULL-terminated), however spaced. */
static bool mk_words(const char *cmd, const char *const *words) {
    const char *p = cmd;
    for (int i = 0; words[i]; i++) {
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        size_t wl = strlen(words[i]);
        if (strncmp(p, words[i], wl) != 0 || (p[wl] && p[wl] != ' ' && p[wl] != '\t')) {
            return false;
        }
        p += wl;
    }
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    return *p == '\0';
}

/* $(NAME) / ${NAME} / $(shell pwd) / $(abspath X): its expansion. */
static const char *mk_reference(mk_t *m, const char *ref) {
    static const char *const pwd[] = {"pwd", NULL};
    static const char *const pwd_p[] = {"pwd", "-P", NULL};
    static const char *const toplevel[] = {"git", "rev-parse", "--show-toplevel", NULL};
    size_t rl = strcspn(ref, " \t");
    if (!ref[rl]) {
        return mk_lookup(m, ref);
    }
    const char *fn = cbm_arena_strndup(m->a, ref, rl);
    const char *arg = mk_trim(m->a, ref + rl, strlen(ref + rl));
    if (!fn || !arg) {
        return MK_UNKNOWN;
    }
    if (strcmp(fn, "shell") == 0) {
        const char *cmd = mk_expand(m, arg);
        if (cmd && (mk_words(cmd, pwd) || mk_words(cmd, pwd_p))) {
            return m->makefile ? "${__cbm_curdir}" : MK_UNKNOWN;
        }
        if (cmd && mk_words(cmd, toplevel)) {
            return "${__cbm_root}";
        }
        return MK_UNKNOWN;
    }
    if (strcmp(fn, "abspath") == 0 || strcmp(fn, "realpath") == 0) {
        const char *v = mk_expand(m, arg);
        return v && !strchr(v, ' ') ? v : MK_UNKNOWN;
    }
    return MK_UNKNOWN;
}

/* Make's expansion of `text`: references replaced, $$ -> $, what is not
 * known -> a shell variable no line sets. */
static const char *mk_expand(mk_t *m, const char *text) {
    sh_str_t b = {0};
    size_t n = strlen(text);
    size_t i = 0;
    while (i < n && !b.bad) {
        if (text[i] != '$') {
            size_t j = i;
            while (j < n && text[j] != '$') {
                j++;
            }
            sh_str_add(m->a, &b, text + i, j - i);
            i = j;
            continue;
        }
        if (i + SKIP_ONE >= n) {
            sh_str_add(m->a, &b, "$", SKIP_ONE);
            i++;
            continue;
        }
        char c = text[i + SKIP_ONE];
        if (c == '$') {
            sh_str_add(m->a, &b, "$", SKIP_ONE);
            i += PAIR_LEN;
            continue;
        }
        if (c != '(' && c != '{') {
            sh_str_add(m->a, &b, MK_UNKNOWN, strlen(MK_UNKNOWN));
            i += PAIR_LEN;
            continue;
        }
        char close = c == '(' ? ')' : '}';
        int depth = 0;
        size_t j = i + SKIP_ONE;
        for (; j < n; j++) {
            if (text[j] == c) {
                depth++;
            } else if (text[j] == close && --depth == 0) {
                break;
            }
        }
        if (j >= n) {
            sh_str_add(m->a, &b, MK_UNKNOWN, strlen(MK_UNKNOWN));
            break;
        }
        const char *ref = cbm_arena_strndup(m->a, text + i + PAIR_LEN, j - i - PAIR_LEN);
        const char *v = ref ? mk_reference(m, ref) : MK_UNKNOWN;
        sh_str_add(m->a, &b, v, strlen(v));
        i = j + SKIP_ONE;
    }
    return sh_str_done(&b);
}

static void mk_assign(mk_t *m, TSNode n, bool cond) {
    TSNode name = ts_node_child_by_field_name(n, TS_FIELD("name"));
    TSNode value = ts_node_child_by_field_name(n, TS_FIELD("value"));
    if (ts_node_is_null(name)) {
        return;
    }
    uint32_t nb = ts_node_start_byte(name);
    const char *nm = mk_trim(m->a, m->src + nb, ts_node_end_byte(name) - nb);
    const char *raw = "";
    if (!ts_node_is_null(value)) {
        uint32_t vb = ts_node_start_byte(value);
        raw = mk_trim(m->a, m->src + vb, ts_node_end_byte(value) - vb);
    }
    const char *op = "=";
    for (uint32_t i = 0; i < ts_node_child_count(n); i++) {
        TSNode c = ts_node_child(n, i);
        if (!ts_node_is_named(c) && strchr(ts_node_type(c), '=')) {
            op = ts_node_type(c);
        }
    }
    if (!nm || !raw) {
        return;
    }
    mk_var_t *old = cbm_ht_get(m->vars, nm);
    if (strcmp(op, "?=") == 0 && old) {
        return;
    }
    mk_var_t *v = cbm_arena_alloc(m->a, sizeof(*v));
    if (!v) {
        return;
    }
    *v = (mk_var_t){raw, NULL, !cond && strcmp(op, "!=") != 0, false};
    if (strcmp(op, "+=") == 0 && old) {
        v->known = v->known && old->known;
        v->raw = cbm_arena_sprintf(m->a, "%s %s", old->raw, raw);
    }
    cbm_ht_set(m->vars, nm, v);
}

/* Variables and recipe lines of a makefile; `cond`: under a conditional. */
/* The recipe lines in the bytes of a recipe_line node, split as make splits
 * them: tree-sitter-make can let one node run over several lines (a quote in
 * `"Don't ..."` does it). */
static void mk_split_lines(mk_t *m, TSNode node) {
    const char *src = m->src;
    uint32_t p = ts_node_start_byte(node);
    uint32_t end = ts_node_end_byte(node);
    uint32_t row = ts_node_start_point(node).row;
    while (p < end) {
        uint32_t b = p;
        uint32_t brow = row;
        uint32_t q = p;
        for (;;) {
            while (q < end && src[q] != '\n') {
                q++;
            }
            uint32_t k = (q > p && src[q - SKIP_ONE] == '\r') ? q - SKIP_ONE : q;
            bool cont = k > p && src[k - SKIP_ONE] == '\\';
            if (!cont || q >= end) {
                break;
            }
            q++;
            row++;
            p = q;
        }
        uint32_t e = q;
        p = q < end ? q + SKIP_ONE : q;
        row++;
        while (e > b && src[e - SKIP_ONE] == '\r') {
            e--;
        }
        while (b < e && src[b] && strchr(" \t@-+", src[b])) {
            b++;
        }
        if (b < e && src[b] != '#' &&
            sh_grow((void **)&m->lines, &m->cap_lines, m->nlines, sizeof(*m->lines))) {
            m->lines[m->nlines++] = (mk_line_t){b, e, brow};
        }
    }
}

static int mk_cmp_line(const void *a, const void *b) {
    uint32_t x = ((const mk_line_t *)a)->b;
    uint32_t y = ((const mk_line_t *)b)->b;
    return (x > y) - (x < y);
}

static void mk_collect(mk_t *m, TSNode n, bool cond);
static void mk_collect_error(mk_t *m, TSNode err, bool cond);

static void mk_collect_one(mk_t *m, TSNode c, bool cond) {
    const char *t = ts_node_type(c);
    if (strcmp(t, "variable_assignment") == 0) {
        mk_assign(m, c, cond);
    } else if (strcmp(t, "recipe_line") == 0) {
        mk_split_lines(m, c);
    } else if (strcmp(t, "rule") == 0 || strcmp(t, "recipe") == 0) {
        mk_collect(m, c, cond);
    } else if (strcmp(t, "ERROR") == 0) {
        mk_collect_error(m, c, cond);
    } else if (strcmp(t, "define_directive") == 0) {
        TSNode name = ts_node_child_by_field_name(c, TS_FIELD("name"));
        if (!ts_node_is_null(name)) {
            uint32_t nb = ts_node_start_byte(name);
            const char *nm = mk_trim(m->a, m->src + nb, ts_node_end_byte(name) - nb);
            mk_var_t *v = cbm_arena_alloc(m->a, sizeof(*v));
            if (nm && v) {
                *v = (mk_var_t){"", NULL, false, false};
                cbm_ht_set(m->vars, nm, v);
            }
        }
    } else if (strstr(t, "conditional") || strstr(t, "if") == t ||
               strcmp(t, "else_directive") == 0 || strcmp(t, "elsif_directive") == 0) {
        mk_collect(m, c, true);
    } else if (strstr(t, "directive")) {
        mk_collect(m, c, cond);
    }
}

static void mk_collect(mk_t *m, TSNode n, bool cond) {
    for (uint32_t i = 0; i < ts_node_named_child_count(n); i++) {
        mk_collect_one(m, ts_node_named_child(n, i), cond);
    }
}

/* +1 for a line opening a conditional or a define, -1 for its end, else 0. */
static int mk_directive_delta(const char *p, const char *end) {
    static const struct {
        const char *kw;
        int delta;
    } kws[] = {{"ifeq", SKIP_ONE},   {"ifneq", SKIP_ONE}, {"ifdef", SKIP_ONE}, {"ifndef", SKIP_ONE},
               {"define", SKIP_ONE}, {"endif", -1},       {"endef", -1}};
    while (p < end && (*p == ' ' || *p == '\t')) {
        p++;
    }
    for (size_t i = 0; i < sizeof(kws) / sizeof(kws[0]); i++) {
        size_t kl = strlen(kws[i].kw);
        if ((size_t)(end - p) >= kl && strncmp(p, kws[i].kw, kl) == 0 &&
            (p + kl == end || strchr(" \t(\r", p[kl]))) {
            return kws[i].delta;
        }
    }
    return 0;
}

/* A region tree-sitter-make could not parse (an indented, nested ifeq does
 * it) still holds rules and assignments; an assignment counts as certain
 * only outside the conditionals its lines open. */
static void mk_collect_error(mk_t *m, TSNode err, bool cond) {
    uint32_t scan = ts_node_start_byte(err);
    uint32_t end = ts_node_end_byte(err);
    int depth = 0;
    for (uint32_t i = 0; i < ts_node_named_child_count(err); i++) {
        TSNode c = ts_node_named_child(err, i);
        uint32_t cb = ts_node_start_byte(c);
        while (scan < cb && scan < end) {
            uint32_t le = scan;
            while (le < end && m->src[le] != '\n') {
                le++;
            }
            depth += mk_directive_delta(m->src + scan, m->src + le);
            depth = depth < 0 ? 0 : depth;
            scan = le + SKIP_ONE;
        }
        mk_collect_one(m, c, cond || depth > 0);
    }
}

static void sh_makefile(sh_pass_t *p, const char *rel, const char *src, size_t len) {
    if (!ts_parser_set_language(p->parser, cbm_ts_language(CBM_LANG_MAKEFILE))) {
        return;
    }
    TSTree *tree = ts_parser_parse_string(p->parser, NULL, src, (uint32_t)len);
    if (!tree) {
        return;
    }
    CBMArena a;
    cbm_arena_init(&a);
    const char *base = sh_basename(rel);
    mk_t m = {.a = &a,
              .src = src,
              .vars = cbm_ht_create(0),
              .makefile = strcmp(base, "Makefile") == 0 || strcmp(base, "GNUmakefile") == 0 ||
                          strcmp(base, "makefile") == 0};
    if (m.vars) {
        mk_collect(&m, ts_tree_root_node(tree), false);
    }
    if (m.nlines > SKIP_ONE) {
        qsort(m.lines, (size_t)m.nlines, sizeof(*m.lines), mk_cmp_line);
    }
    for (int r = 0; m.vars && r < m.nlines; r++) {
        if (r > 0 && m.lines[r].b == m.lines[r - SKIP_ONE].b) {
            continue; /* nested nodes covered it already */
        }
        uint32_t b = m.lines[r].b;
        uint32_t e = m.lines[r].e;
        const char *raw = cbm_arena_strndup(&a, src + b, e - b);
        const char *text = raw ? mk_expand(&m, raw) : NULL;
        if (!text || (!strchr(text, '/') && !sh_mentions_deploy_tool(text, strlen(text)))) {
            continue; /* neither a deploy nor a program started by a path */
        }
        size_t tl = strlen(text);
        char *buf = cbm_arena_alloc(&a, tl + CBM_SZ_16);
        if (!buf) {
            continue;
        }
        memcpy(buf, text, tl);
        memset(buf + tl, 0, CBM_SZ_16);
        sh_t s;
        sh_state_init(&s, p, &a, rel);
        if (s.env) {
            s.line_base = (int)m.lines[r].row;
            sh_val_t *root = cbm_arena_alloc(&a, sizeof(*root));
            sh_val_t *cur = cbm_arena_alloc(&a, sizeof(*cur));
            if (root && cur) {
                *root = (sh_val_t){SH_ROOT, NULL, 0};
                *cur = (sh_val_t){sh_anchor(&a, s.sdir), NULL, 0};
                cbm_ht_set(s.env, "__cbm_root", root);
                if (m.makefile) {
                    cbm_ht_set(s.env, "__cbm_curdir", cur);
                }
            }
            s.cwd = m.makefile ? (sh_cwd_t){SH_AT, s.sdir} : (sh_cwd_t){SH_FREE, NULL};
            sh_run(&s, p->parser, buf, tl);
        }
        sh_state_free(&s);
    }
    if (m.vars) {
        cbm_ht_free(m.vars);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, m.lines);
    cbm_arena_destroy(&a);
    ts_tree_delete(tree);
}

/* ── Edges ─────────────────────────────────────────────────────────── */

typedef struct {
    const char *file;
    const cbm_gbuf_node_t *node;
} sh_span_t;

static int sh_cmp_span(const void *a, const void *b) {
    const sh_span_t *x = a;
    const sh_span_t *y = b;
    return strcmp(x->file, y->file);
}

/* The innermost Function around `line` in `file`, else its Module, else its
 * File node. */
static int64_t sh_source(cbm_pipeline_ctx_t *ctx, const sh_span_t *spans, int n,
                         CBMHashTable *modules, const char *file, int line) {
    int lo = 0;
    int hi = n;
    while (lo < hi) {
        int mid = lo + (hi - lo) / PAIR_LEN;
        if (strcmp(spans[mid].file, file) < 0) {
            lo = mid + SKIP_ONE;
        } else {
            hi = mid;
        }
    }
    const cbm_gbuf_node_t *best = NULL;
    for (int i = lo; i < n && strcmp(spans[i].file, file) == 0; i++) {
        const cbm_gbuf_node_t *f = spans[i].node;
        if (f->start_line > line || f->end_line < line) {
            continue;
        }
        int w = f->end_line - f->start_line;
        int bw = best ? best->end_line - best->start_line : 0;
        if (!best || w < bw ||
            (w == bw && strcmp(f->qualified_name ? f->qualified_name : "",
                               best->qualified_name ? best->qualified_name : "") < 0)) {
            best = f;
        }
    }
    if (best) {
        return best->id;
    }
    int64_t mod = (int64_t)(intptr_t)cbm_ht_get(modules, file);
    if (mod > 0) {
        return mod;
    }
    const cbm_gbuf_node_t *fn = cbm_pipeline_file_node(ctx->gbuf, ctx->project_name, file);
    return fn ? fn->id : 0;
}

/* The shared external Chart of `name` (the one chart dependencies use). */
static int64_t sh_external_chart(cbm_pipeline_ctx_t *ctx, const char *name, const char *file) {
    char qn[CBM_SZ_512];
    snprintf(qn, sizeof(qn), "%s.__helm_dep__.%s", ctx->project_name, name);
    const cbm_gbuf_node_t *known = cbm_gbuf_find_by_qn(ctx->gbuf, qn);
    if (known) {
        return known->id;
    }
    return cbm_gbuf_upsert_node(ctx->gbuf, "Chart", name, qn, file, SKIP_ONE, 0,
                                "{\"source\":\"helm\",\"external\":true}");
}

/* SPAWNS to the Process of `program`, as pass_spawns.c draws it. */
static int sh_link_spawn(cbm_pipeline_ctx_t *ctx, int64_t src, const sh_hit_t *x) {
    char program[CBM_SZ_128];
    cbm_json_escape(program, (int)sizeof(program), x->ext);
    char qn[CBM_SZ_256];
    snprintf(qn, sizeof(qn), "__process__%s", x->ext);
    char node_props[CBM_SZ_256];
    snprintf(node_props, sizeof(node_props), "{\"program\":\"%s\"}", program);
    int64_t process = cbm_gbuf_upsert_node(ctx->gbuf, "Process", x->ext, qn, "", 0, 0, node_props);
    if (process <= 0) {
        return 0;
    }
    char props[CBM_SZ_512];
    snprintf(props, sizeof(props),
             "{\"api\":\"%s\",\"program\":\"%s\",\"line\":%d,\"confidence\":1.00}", x->via, program,
             x->line);
    cbm_gbuf_insert_edge(ctx->gbuf, src, process, "SPAWNS", props);
    return SKIP_ONE;
}

static int sh_link(cbm_pipeline_ctx_t *ctx, const sh_hits_t *h) {
    CBMHashTable *files = cbm_ht_create(0);
    CBMHashTable *modules = cbm_ht_create(0);
    if (!files || !modules) {
        if (files) {
            cbm_ht_free(files);
        }
        if (modules) {
            cbm_ht_free(modules);
        }
        return 0;
    }
    for (int i = 0; i < h->count; i++) {
        cbm_ht_set(files, h->items[i].file, (void *)h->items[i].file);
    }
    sh_span_t *spans = NULL;
    int n = 0;
    int cap = 0;
    const cbm_gbuf_node_t **nodes = NULL;
    int count = 0;
    if (cbm_gbuf_find_by_label(ctx->gbuf, "Function", &nodes, &count) == 0) {
        for (int i = 0; i < count; i++) {
            const char *fp = nodes[i]->file_path;
            const char *key = fp ? cbm_ht_get_key(files, fp) : NULL;
            if (key && sh_grow((void **)&spans, &cap, n, sizeof(*spans))) {
                spans[n++] = (sh_span_t){key, nodes[i]};
            }
        }
    }
    if (n > SKIP_ONE) {
        qsort(spans, (size_t)n, sizeof(*spans), sh_cmp_span);
    }
    if (cbm_gbuf_find_by_label(ctx->gbuf, "Module", &nodes, &count) == 0) {
        for (int i = 0; i < count; i++) {
            const char *fp = nodes[i]->file_path;
            const char *key = fp ? cbm_ht_get_key(files, fp) : NULL;
            if (key && !cbm_ht_get(modules, key)) {
                cbm_ht_set(modules, key, (void *)(intptr_t)nodes[i]->id);
            }
        }
    }
    int edges = 0;
    for (int i = 0; i < h->count; i++) {
        const sh_hit_t *x = &h->items[i];
        int64_t src = sh_source(ctx, spans, n, modules, x->file, x->line);
        if (x->spawn) {
            edges += src > 0 ? sh_link_spawn(ctx, src, x) : 0;
            continue;
        }
        int64_t tgt = x->tgt > 0 ? x->tgt : sh_external_chart(ctx, x->ext, x->file);
        if (src <= 0 || tgt <= 0 || src == tgt) {
            continue;
        }
        char esc[CBM_SZ_1K];
        char props[CBM_SZ_2K];
        cbm_json_escape(esc, (int)sizeof(esc), x->path ? x->path : "");
        snprintf(props, sizeof(props), "{\"via\":\"%s\",\"%s\":\"%s\"%s,\"line\":%d}", x->via,
                 x->chart ? "chart" : "path", esc, x->tgt > 0 ? "" : ",\"external\":true", x->line);
        cbm_gbuf_insert_edge(ctx->gbuf, src, tgt, "DEPLOYS", props);
        edges++;
    }
    cbm_free(CBM_MEM_CLASS_OTHER, spans);
    cbm_ht_free(files);
    cbm_ht_free(modules);
    return edges;
}

void cbm_pipeline_pass_shell(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                             int file_count) {
    sh_index_t ix = {0};
    sh_hits_t hits = {0};
    cbm_arena_init(&hits.arena);
    sh_pass_t p = {.ix = &ix, .hits = &hits, .parser = NULL};
    for (int i = 0; i < file_count; i++) {
        CBMLanguage lang = files[i].language;
        if (lang != CBM_LANG_BASH && lang != CBM_LANG_MAKEFILE) {
            continue;
        }
        size_t len = 0;
        char *src = sh_read(files[i].path, &len);
        if (!src) {
            continue;
        }
        if (!p.ix_ready) {
            p.ix_ready = true;
            p.ix_ok = sh_index_build(&ix, ctx);
            p.parser = ts_parser_new();
        }
        if (p.ix_ok && p.parser) {
            if (lang == CBM_LANG_BASH) {
                sh_script(&p, files[i].rel_path, src, len);
            } else {
                sh_makefile(&p, files[i].rel_path, src, len);
            }
        }
        cbm_free(CBM_MEM_CLASS_OTHER, src);
    }
    int edges = hits.count > 0 ? sh_link(ctx, &hits) : 0;
    if (p.parser) {
        ts_parser_delete(p.parser);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, hits.items);
    cbm_arena_destroy(&hits.arena);
    if (p.ix_ready) {
        sh_index_free(&ix);
    }
    if (edges > 0) {
        char buf[CBM_SZ_32];
        snprintf(buf, sizeof(buf), "%d", edges);
        cbm_log_info("pass.shell.deploys", "edges", buf);
    }
}
