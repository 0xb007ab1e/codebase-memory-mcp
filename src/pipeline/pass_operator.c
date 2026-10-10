/*
 * pass_operator.c — Go Kubernetes operators (PHASE1 P1.2).
 *
 * A controller-runtime operator ties Go code to Kubernetes kinds in three
 * ways the type graph alone does not carry:
 *   - a controller is built `For(&v1.Widget{})`, `Owns(&v1.Gadget{})`,
 *     `Watches(&v1.X{}, ...)` or watches `source.Kind(cache, &v1.X{})`:
 *     HANDLES {via: controller, role} from the function that builds it to
 *     the Go type, resolved as Go does: `v1` is an import of the file, and
 *     the type is the struct of that name in the imported package's
 *     directory (unqualified: the file's own package);
 *   - a CRD's group/kind is backed by `type <Kind> struct` in the package
 *     marked `+groupName=<group>` (or `GroupName = "<group>"`): USAGE
 *     {ref: crd-type} from the CRD Resource to that Struct;
 *   - `//go:embed <patterns>` puts files into the binary: REFERENCES_FILE
 *     {via: go:embed} from the Go file to each embedded file.
 * Runs after USAGE resolution; reads each Go file once.
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

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OP_SLEN(lit) (sizeof(lit) - SKIP_ONE)

enum { OP_GROW_MIN = 16, OP_IDENT_MAX = 128 };

/* Candidates examined by the resolvers below (pipeline_internal.h). */
_Atomic uint64_t g_op_candidates = 0;

/* Read a whole file into a core-owned NUL-terminated buffer, NULL on error
 * or past the indexer's file-size policy. */
static char *op_read_file(const char *path) {
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
    char *buf = cbm_alloc(CBM_MEM_CLASS_OTHER, (size_t)size + SKIP_ONE);
    if (buf) {
        size_t n = fread(buf, SKIP_ONE, (size_t)size, f);
        buf[n] = '\0';
    }
    (void)fclose(f);
    return buf;
}

static void op_dirname(const char *path, char *out, size_t out_sz) {
    const char *slash = strrchr(path, '/');
    snprintf(out, out_sz, "%.*s", slash ? (int)(slash - path) : 0, path);
}

/* ── Functions per file ──────────────────────────────────────────────── */

/* One definition span of a function node: Go method QNs carry no receiver,
 * so the methods of several types in one package (every reconciler's
 * SetupWithManager) are one node standing for spans in several files. */
typedef struct {
    const cbm_gbuf_node_t *node;
    int start;
    int end;
} op_span_t;

typedef struct {
    op_span_t *items;
    int count;
    int cap;
} op_spans_t;

static void op_spans_push(op_spans_t *v, op_span_t span) {
    if (v->count == v->cap) {
        int cap = v->cap ? v->cap * PAIR_LEN : OP_GROW_MIN;
        op_span_t *grown = cbm_realloc(CBM_MEM_CLASS_OTHER, v->items, (size_t)cap * sizeof(*grown));
        if (!grown) {
            return;
        }
        v->items = grown;
        v->cap = cap;
    }
    v->items[v->count++] = span;
}

static void op_free_spans(const char *key, void *value, void *ud) {
    (void)ud;
    op_spans_t *v = value;
    cbm_free(CBM_MEM_CLASS_OTHER, v->items);
    cbm_free(CBM_MEM_CLASS_OTHER, v);
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)key);
}

typedef struct {
    CBMHashTable *by_file;
    const cbm_gbuf_node_t *node;
} op_index_ctx_t;

static void op_index_span(const char *file, int start, int end, void *ud) {
    op_index_ctx_t *c = ud;
    op_spans_t *v = cbm_ht_get(c->by_file, file);
    if (!v) {
        v = cbm_calloc(CBM_MEM_CLASS_OTHER, sizeof(*v));
        char *key = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, file);
        if (!v || !key) {
            cbm_free(CBM_MEM_CLASS_OTHER, v);
            cbm_free(CBM_MEM_CLASS_OTHER, key);
            return;
        }
        cbm_ht_set(c->by_file, key, v);
    }
    op_spans_push(v, (op_span_t){c->node, start, end});
}

/* file_path -> the spans of Function and Method nodes in it (owned keys). */
static CBMHashTable *op_functions_by_file(const cbm_gbuf_t *gb) {
    CBMHashTable *by_file = cbm_ht_create(0);
    static const char *const labels[] = {"Function", "Method"};
    for (size_t l = 0; by_file && l < sizeof(labels) / sizeof(labels[0]); l++) {
        const cbm_gbuf_node_t **nodes = NULL;
        int count = 0;
        if (cbm_gbuf_find_by_label(gb, labels[l], &nodes, &count) != 0) {
            continue;
        }
        for (int i = 0; i < count; i++) {
            op_index_ctx_t c = {by_file, nodes[i]};
            cbm_gbuf_foreach_span(gb, nodes[i], op_index_span, &c);
        }
    }
    return by_file;
}

/* Is span `a` a better enclosing function than `b`: shorter, then (equal
 * spans of two nodes) the lower QN, so the choice never follows index order. */
static bool op_span_better(const op_span_t *a, const op_span_t *b) {
    int la = a->end - a->start;
    int lb = b->end - b->start;
    if (la != lb) {
        return la < lb;
    }
    const char *qa = a->node->qualified_name ? a->node->qualified_name : "";
    const char *qb = b->node->qualified_name ? b->node->qualified_name : "";
    return strcmp(qa, qb) < 0;
}

/* The innermost function of `file` spanning `line`. */
static const cbm_gbuf_node_t *op_enclosing(CBMHashTable *by_file, const char *file, int line) {
    const op_spans_t *v = cbm_ht_get(by_file, file);
    const op_span_t *best = NULL;
    for (int i = 0; v && i < v->count; i++) {
        const op_span_t *sp = &v->items[i];
        if (sp->start <= line && line <= sp->end && (!best || op_span_better(sp, best))) {
            best = sp;
        }
    }
    return best ? best->node : NULL;
}

/* ── Go modules: import path -> directory ─────────────────────────────── */

/* A go.mod of the repository: module path and the directory it roots. */
typedef struct {
    char *path;
    char *dir;
} op_module_t;

typedef struct {
    op_module_t *items;
    int count;
    int cap;
} op_modules_t;

static void op_modules_free(op_modules_t *m) {
    for (int i = 0; i < m->count; i++) {
        cbm_free(CBM_MEM_CLASS_OTHER, m->items[i].path);
        cbm_free(CBM_MEM_CLASS_OTHER, m->items[i].dir);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, m->items);
    *m = (op_modules_t){0};
}

/* Note the `module` line of a go.mod at `file`. */
static void op_note_module(op_modules_t *m, const char *file, const char *text) {
    for (const char *p = strstr(text, "module"); p; p = strstr(p + SKIP_ONE, "module")) {
        if ((p > text && p[-SKIP_ONE] != '\n') ||
            (p[OP_SLEN("module")] != ' ' && p[OP_SLEN("module")] != '\t')) {
            continue;
        }
        const char *q = p + OP_SLEN("module");
        while (*q == ' ' || *q == '\t' || *q == '"') {
            q++;
        }
        size_t n = strcspn(q, " \t\r\n\"/");
        while (q[n] == '/') { /* module paths contain '/' */
            n += SKIP_ONE + strcspn(q + n + SKIP_ONE, " \t\r\n\"/");
        }
        if (n == 0) {
            return;
        }
        if (m->count == m->cap) {
            int cap = m->cap ? m->cap * PAIR_LEN : OP_GROW_MIN;
            op_module_t *grown =
                cbm_realloc(CBM_MEM_CLASS_OTHER, m->items, (size_t)cap * sizeof(*grown));
            if (!grown) {
                return;
            }
            m->items = grown;
            m->cap = cap;
        }
        char path[CBM_SZ_1K];
        char dir[CBM_SZ_1K];
        snprintf(path, sizeof(path), "%.*s", (int)n, q);
        op_dirname(file, dir, sizeof(dir));
        m->items[m->count].path = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, path);
        m->items[m->count].dir = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, dir);
        m->count++;
        return;
    }
}

/* The repository directory of import path `import`: below the go.mod whose
 * module path is its longest prefix ("" when no module of the repository
 * has it). */
static bool op_import_dir(const op_modules_t *m, const char *import, char *out, size_t out_sz) {
    const op_module_t *best = NULL;
    for (int i = 0; i < m->count; i++) {
        size_t pl = strlen(m->items[i].path);
        if (strncmp(import, m->items[i].path, pl) == 0 &&
            (import[pl] == '\0' || import[pl] == '/') && (!best || pl > strlen(best->path))) {
            best = &m->items[i];
        }
    }
    if (!best) {
        return false;
    }
    const char *rest = import + strlen(best->path);
    rest += *rest == '/';
    snprintf(out, out_sz, "%s%s%s", best->dir, best->dir[0] && rest[0] ? "/" : "", rest);
    return true;
}

/* ── Indexes: Go types by package dir, module roots ───────────────────── */

/* Graph-owned nodes. */
typedef struct {
    const cbm_gbuf_node_t **items;
    int count;
    int cap;
} op_nodes_t;

static void op_nodes_push(op_nodes_t *v, const cbm_gbuf_node_t *n) {
    if (v->count == v->cap) {
        int cap = v->cap ? v->cap * PAIR_LEN : OP_GROW_MIN;
        const cbm_gbuf_node_t **grown =
            cbm_realloc(CBM_MEM_CLASS_OTHER, (void *)v->items, (size_t)cap * sizeof(*grown));
        if (!grown) {
            return;
        }
        v->items = grown;
        v->cap = cap;
    }
    v->items[v->count++] = n;
}

static void op_free_nodes_entry(const char *key, void *value, void *ud) {
    (void)ud;
    op_nodes_t *v = value;
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)v->items);
    cbm_free(CBM_MEM_CLASS_OTHER, v);
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)key);
}

/* "<a>\x1f<b>": a directory (or module root) with a name. */
static void op_key(char *out, size_t out_sz, const char *a, const char *b) {
    snprintf(out, out_sz, "%s\x1f%s", a, b);
}

/* "<dir>\x1f<Name>" -> the Struct / Class / Type nodes Name names in dir. */
static CBMHashTable *op_types_by_dir(const cbm_gbuf_t *gb) {
    CBMHashTable *ix = cbm_ht_create(0);
    static const char *const labels[] = {"Struct", "Class", "Type"};
    for (size_t l = 0; ix && l < sizeof(labels) / sizeof(labels[0]); l++) {
        const cbm_gbuf_node_t **nodes = NULL;
        int count = 0;
        if (cbm_gbuf_find_by_label(gb, labels[l], &nodes, &count) != 0) {
            continue;
        }
        for (int i = 0; i < count; i++) {
            if (!nodes[i]->file_path || !nodes[i]->name) {
                continue;
            }
            char dir[CBM_SZ_1K];
            char key[PAIR_LEN * CBM_SZ_1K];
            op_dirname(nodes[i]->file_path, dir, sizeof(dir));
            op_key(key, sizeof(key), dir, nodes[i]->name);
            op_nodes_t *v = cbm_ht_get(ix, key);
            if (!v) {
                v = cbm_calloc(CBM_MEM_CLASS_OTHER, sizeof(*v));
                char *owned = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, key);
                if (!v || !owned) {
                    cbm_free(CBM_MEM_CLASS_OTHER, v);
                    cbm_free(CBM_MEM_CLASS_OTHER, owned);
                    continue;
                }
                cbm_ht_set(ix, owned, v);
            }
            op_nodes_push(v, nodes[i]);
        }
    }
    return ix;
}

typedef struct {
    const op_modules_t *mods;
    CBMHashTable *dir_types; /* op_types_by_dir */
} op_index_t;

/* ── Controllers: For / Owns / Watches / source.Kind ──────────────────── */

static int op_line_of(const char *text, const char *at) {
    int line = SKIP_ONE;
    for (const char *p = text; p < at; p++) {
        line += *p == '\n';
    }
    return line;
}

static bool op_is_quote(char c) {
    return c == '"' || c == '\'' || c == '`';
}

/* Where a `//` comment starts in the line text [ls, le), outside string and
 * rune literals; le when there is none. */
static const char *op_comment_start(const char *ls, const char *le) {
    char quote = 0;
    for (const char *p = ls; p < le; p++) {
        if (quote) {
            if (*p == '\\' && quote != '`' && p + SKIP_ONE < le) {
                p++;
            } else if (*p == quote) {
                quote = 0;
            }
        } else if (op_is_quote(*p)) {
            quote = *p;
        } else if (*p == '/' && p + SKIP_ONE < le && p[SKIP_ONE] == '/') {
            return p;
        }
    }
    return le;
}

static const char *op_line_start(const char *text, const char *p) {
    while (p > text && p[-SKIP_ONE] != '\n') {
        p--;
    }
    return p;
}

/* The code character before `at`, past blanks and `//` comments: gofmt
 * puts a chain's '.' at the end of an earlier line, and comment lines may
 * sit between. NULL at the start of the text. */
static const char *op_prev_code(const char *text, const char *at) {
    const char *le = at;
    for (;;) {
        const char *ls = op_line_start(text, le);
        const char *end = op_comment_start(ls, le);
        while (end > ls &&
               (end[-SKIP_ONE] == ' ' || end[-SKIP_ONE] == '\t' || end[-SKIP_ONE] == '\r')) {
            end--;
        }
        if (end > ls) {
            return end - SKIP_ONE;
        }
        if (ls == text) {
            return NULL;
        }
        le = ls - SKIP_ONE; /* the previous line, without its '\n' */
    }
}

/* The end of the argument list opened at `open` ('('), balanced; parentheses
 * in `//` comments and literals do not count. */
static const char *op_args_end(const char *open) {
    int depth = 0;
    char quote = 0;
    for (const char *p = open; *p; p++) {
        if (quote) {
            if (*p == '\\' && quote != '`' && p[SKIP_ONE]) {
                p++;
            } else if (*p == quote || (*p == '\n' && quote != '`')) {
                quote = 0;
            }
            continue;
        }
        if (op_is_quote(*p)) {
            quote = *p;
            continue;
        }
        if (*p == '/' && p[SKIP_ONE] == '/') {
            p = strchr(p, '\n');
            if (!p) {
                break;
            }
            continue;
        }
        depth += *p == '(';
        depth -= *p == ')';
        if (depth == 0) {
            return p;
        }
    }
    return open + strlen(open);
}

static bool op_ident_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

/* The import path a file binds to `alias` (an explicit alias, else the
 * path's last segment, Go's usual package name); "" when none. */
static void op_import_path(const char *text, const char *alias, char *out, size_t out_sz) {
    out[0] = '\0';
    size_t al = strlen(alias);
    for (const char *p = strstr(text, "import"); p; p = strstr(p + SKIP_ONE, "import")) {
        if ((p > text && p[-SKIP_ONE] != '\n') || op_ident_char(p[OP_SLEN("import")])) {
            continue;
        }
        const char *q = p + OP_SLEN("import");
        const char *end = q;
        while (*end == ' ' || *end == '\t') {
            end++;
        }
        end = *end == '(' ? strchr(end, ')') : strchr(end, '\n');
        end = end ? end : q + strlen(q);
        /* each import line: [alias] "path" */
        for (const char *l = q; l < end;) {
            while (l < end && (*l == ' ' || *l == '\t' || *l == '(' || *l == '\n' || *l == '\r')) {
                l++;
            }
            const char *name = l;
            while (l < end && op_ident_char(*l)) {
                l++;
            }
            size_t nl = (size_t)(l - name);
            while (l < end && (*l == ' ' || *l == '\t')) {
                l++;
            }
            if (l >= end || *l != '"') {
                while (l < end && *l != '\n') {
                    l++;
                }
                continue;
            }
            const char *ps = l + SKIP_ONE;
            const char *pe = strchr(ps, '"');
            if (!pe || pe > end) {
                break;
            }
            const char *seg = pe;
            while (seg > ps && seg[-SKIP_ONE] != '/') {
                seg--;
            }
            bool hit = nl ? (nl == al && strncmp(name, alias, al) == 0)
                          : ((size_t)(pe - seg) == al && strncmp(seg, alias, al) == 0);
            if (hit) {
                snprintf(out, out_sz, "%.*s", (int)(pe - ps), ps);
                return;
            }
            l = pe + SKIP_ONE;
        }
    }
}

/* Is directory `dir` the package at import path `path`: the path ends with
 * the directory, on a segment boundary (the module path is its prefix). */
static bool op_dir_is_import(const char *dir, const char *path) {
    size_t dl = strlen(dir);
    size_t pl = strlen(path);
    if (dl == 0 || dl > pl || strcmp(path + pl - dl, dir) != 0) {
        return false;
    }
    return dl == pl || path[pl - dl - SKIP_ONE] == '/';
}

/* HANDLES from `fn` to the Go type `type` resolved as Go resolves it: the
 * package the file imports as `qual`, or (unqualified) the file's own -- one
 * directory, looked up in the type index. Only an import no module of the
 * repository has falls back to the same-named types whose directory ends
 * the import path. */
static int op_handle(cbm_gbuf_t *gb, const op_index_t *ix, const cbm_gbuf_node_t *fn,
                     const char *file, const char *text, const char *qual, const char *type,
                     const char *role) {
    char import[CBM_SZ_1K] = "";
    char pkg_dir[CBM_SZ_1K] = "";
    bool in_repo = false;
    if (qual[0]) {
        op_import_path(text, qual, import, sizeof(import));
        if (!import[0]) {
            return 0;
        }
        in_repo = op_import_dir(ix->mods, import, pkg_dir, sizeof(pkg_dir));
    } else {
        op_dirname(file, pkg_dir, sizeof(pkg_dir));
    }
    char props[CBM_SZ_128];
    snprintf(props, sizeof(props), "{\"via\":\"controller\",\"role\":\"%s\"}", role);
    int linked = 0;
    if (!qual[0] || in_repo) {
        char key[PAIR_LEN * CBM_SZ_1K];
        op_key(key, sizeof(key), pkg_dir, type);
        const op_nodes_t *v = cbm_ht_get(ix->dir_types, key);
        atomic_fetch_add_explicit(&g_op_candidates, (uint64_t)(v ? v->count : 0),
                                  memory_order_relaxed);
        for (int i = 0; v && i < v->count; i++) {
            cbm_gbuf_insert_edge(gb, fn->id, v->items[i]->id, "HANDLES", props);
            linked++;
        }
        return linked;
    }
    const cbm_gbuf_node_t **types = NULL;
    int tn = 0;
    if (cbm_gbuf_find_by_name(gb, type, &types, &tn) != 0) {
        return 0;
    }
    atomic_fetch_add_explicit(&g_op_candidates, (uint64_t)(tn), memory_order_relaxed);
    for (int i = 0; i < tn; i++) {
        const cbm_gbuf_node_t *t = types[i];
        if (!t->label || !t->file_path ||
            (strcmp(t->label, "Struct") != 0 && strcmp(t->label, "Class") != 0 &&
             strcmp(t->label, "Type") != 0)) {
            continue;
        }
        char dir[CBM_SZ_1K];
        op_dirname(t->file_path, dir, sizeof(dir));
        if (op_dir_is_import(dir, import)) {
            cbm_gbuf_insert_edge(gb, fn->id, t->id, "HANDLES", props);
            linked++;
        }
    }
    return linked;
}

/* Every `&[pkg.]Type{` in the arguments of a controller builder call. */
static int op_controller_calls(cbm_gbuf_t *gb, CBMHashTable *by_file, const op_index_t *ix,
                               const char *file, const char *text) {
    /* method name + "(", called on a receiver outside a comment: the previous
     * code char is '.', and Kind's receiver is the `source` package. */
    static const struct {
        const char *name;
        const char *recv;
        const char *role;
    } calls[] = {{"For(", NULL, "for"},
                 {"Owns(", NULL, "owns"},
                 {"Watches(", NULL, "watches"},
                 {"Kind(", "source", "watches"}};
    int linked = 0;
    for (size_t c = 0; c < sizeof(calls) / sizeof(calls[0]); c++) {
        for (const char *p = strstr(text, calls[c].name); p;
             p = strstr(p + SKIP_ONE, calls[c].name)) {
            if (p > text && op_ident_char(p[-SKIP_ONE])) {
                continue; /* part of a longer name */
            }
            if (op_comment_start(op_line_start(text, p), p) < p) {
                continue;
            }
            const char *dot = op_prev_code(text, p);
            if (!dot || *dot != '.') {
                continue;
            }
            if (calls[c].recv) {
                size_t rl = strlen(calls[c].recv);
                const char *r = dot - rl;
                if (r < text || strncmp(r, calls[c].recv, rl) != 0 ||
                    (r > text && op_ident_char(r[-SKIP_ONE]))) {
                    continue;
                }
            }
            const char *open = p + strlen(calls[c].name) - SKIP_ONE;
            const char *end = op_args_end(open);
            const cbm_gbuf_node_t *fn = op_enclosing(by_file, file, op_line_of(text, p));
            if (!fn) {
                continue;
            }
            for (const char *a = open; a < end; a++) {
                if (*a == '/' && a[SKIP_ONE] == '/') {
                    const char *nl = strchr(a, '\n');
                    a = nl && nl < end ? nl : end;
                    continue;
                }
                if (*a != '&') {
                    continue;
                }
                const char *q = a + SKIP_ONE;
                const char *first = q;
                const char *last = q;
                while (q < end && (op_ident_char(*q) || *q == '.')) {
                    if (*q == '.') {
                        last = q + SKIP_ONE;
                    }
                    q++;
                }
                if (q < end && *q == '{' && q > last && (size_t)(q - last) < OP_IDENT_MAX &&
                    (size_t)(last - first) < OP_IDENT_MAX) {
                    char type[OP_IDENT_MAX];
                    char qual[OP_IDENT_MAX];
                    snprintf(type, sizeof(type), "%.*s", (int)(q - last), last);
                    snprintf(qual, sizeof(qual), "%.*s",
                             last > first ? (int)(last - first - SKIP_ONE) : 0, first);
                    linked += op_handle(gb, ix, fn, file, text, qual, type, calls[c].role);
                }
            }
        }
    }
    return linked;
}

/* ── API groups: +groupName / GroupName ───────────────────────────────── */

/* A Go identifier-or-DNS token at p (the group name). */
static void op_token(const char *p, char *out, size_t out_sz) {
    size_t n = 0;
    while (p[n] && (op_ident_char(p[n]) || p[n] == '.' || p[n] == '-') && n + SKIP_ONE < out_sz) {
        n++;
    }
    snprintf(out, out_sz, "%.*s", (int)n, p);
}

/* Owned strings. */
typedef struct {
    char **items;
    int count;
    int cap;
} op_strs_t;

static void op_strs_push(op_strs_t *v, const char *s) {
    if (v->count == v->cap) {
        int cap = v->cap ? v->cap * PAIR_LEN : OP_GROW_MIN;
        char **grown = cbm_realloc(CBM_MEM_CLASS_OTHER, v->items, (size_t)cap * sizeof(*grown));
        if (!grown) {
            return;
        }
        v->items = grown;
        v->cap = cap;
    }
    char *copy = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, s);
    if (copy) {
        v->items[v->count++] = copy;
    }
}

/* group -> the package directories that declare it (owned keys and lists);
 * `seen` holds "group\x1fdir" (owned keys) so a repeat is one lookup. */
static void op_note_group(CBMHashTable *groups, CBMHashTable *seen, const char *group,
                          const char *dir) {
    char key[PAIR_LEN * CBM_SZ_1K];
    op_key(key, sizeof(key), group, dir);
    if (!group[0] || cbm_ht_get(seen, key)) {
        return;
    }
    char *seen_key = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, key);
    if (!seen_key) {
        return;
    }
    cbm_ht_set(seen, seen_key, seen_key);
    op_strs_t *dirs = cbm_ht_get(groups, group);
    if (!dirs) {
        dirs = cbm_calloc(CBM_MEM_CLASS_OTHER, sizeof(*dirs));
        char *gkey = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, group);
        if (!dirs || !gkey) {
            cbm_free(CBM_MEM_CLASS_OTHER, dirs);
            cbm_free(CBM_MEM_CLASS_OTHER, gkey);
            return;
        }
        cbm_ht_set(groups, gkey, dirs);
    }
    op_strs_push(dirs, dir);
}

static void op_scan_groups(CBMHashTable *groups, CBMHashTable *seen, const char *file,
                           const char *text) {
    char dir[CBM_SZ_1K];
    op_dirname(file, dir, sizeof(dir));
    for (const char *p = strstr(text, "+groupName="); p; p = strstr(p + SKIP_ONE, "+groupName=")) {
        char g[CBM_SZ_256];
        op_token(p + OP_SLEN("+groupName="), g, sizeof(g));
        op_note_group(groups, seen, g, dir);
    }
    for (const char *p = strstr(text, "GroupName"); p; p = strstr(p + SKIP_ONE, "GroupName")) {
        const char *q = p + OP_SLEN("GroupName");
        while (*q == ' ' || *q == '\t') {
            q++;
        }
        if (*q != '=') {
            continue;
        }
        q++;
        while (*q == ' ' || *q == '\t') {
            q++;
        }
        if (*q == '"') {
            char g[CBM_SZ_256];
            op_token(q + SKIP_ONE, g, sizeof(g));
            op_note_group(groups, seen, g, dir);
        }
    }
}

static void op_free_seen(const char *key, void *value, void *ud) {
    (void)value;
    (void)ud;
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)key);
}

static void op_free_groups(const char *key, void *value, void *ud) {
    (void)ud;
    op_strs_t *dirs = value;
    for (int i = 0; i < dirs->count; i++) {
        cbm_free(CBM_MEM_CLASS_OTHER, dirs->items[i]);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, dirs->items);
    cbm_free(CBM_MEM_CLASS_OTHER, dirs);
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)key);
}

/* A JSON string property's value (simple, unescaped scalars). */
static bool op_prop(const char *props, const char *key, char *out, size_t out_sz) {
    char pat[CBM_SZ_64];
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = props ? strstr(props, pat) : NULL;
    if (!p) {
        return false;
    }
    p += strlen(pat);
    const char *e = strchr(p, '"');
    if (!e) {
        return false;
    }
    snprintf(out, out_sz, "%.*s", (int)(e - p), p);
    return true;
}

/* CRD -> the Go type declared under its group, in every package marking it:
 * an API group is one identity, and its CRDs and Go types routinely sit in
 * different modules (cluster-api's api/, kubermatic's sdk/). */
static int op_link_crd_types(cbm_gbuf_t *gb, const op_index_t *ix, CBMHashTable *groups) {
    const cbm_gbuf_node_t **res = NULL;
    int count = 0;
    int linked = 0;
    if (cbm_gbuf_find_by_label(gb, "Resource", &res, &count) != 0) {
        return 0;
    }
    for (int i = 0; i < count; i++) {
        char group[CBM_SZ_256];
        char kind[CBM_SZ_256];
        if (!res[i]->file_path ||
            !op_prop(res[i]->properties_json, "crd_group", group, sizeof(group)) ||
            !op_prop(res[i]->properties_json, "crd_kind", kind, sizeof(kind))) {
            continue;
        }
        char key[PAIR_LEN * CBM_SZ_1K];
        const op_strs_t *dirs = cbm_ht_get(groups, group);
        if (!dirs) {
            continue;
        }
        atomic_fetch_add_explicit(&g_op_candidates, (uint64_t)dirs->count, memory_order_relaxed);
        for (int d = 0; d < dirs->count; d++) {
            op_key(key, sizeof(key), dirs->items[d], kind);
            const op_nodes_t *v = cbm_ht_get(ix->dir_types, key);
            for (int t = 0; v && t < v->count; t++) {
                if (v->items[t]->label && strcmp(v->items[t]->label, "Struct") == 0) {
                    cbm_gbuf_insert_edge(gb, res[i]->id, v->items[t]->id, "USAGE",
                                         "{\"ref\":\"crd-type\"}");
                    linked++;
                }
            }
        }
    }
    return linked;
}

/* ── go:embed ─────────────────────────────────────────────────────────── */

/* Go's path.Match for one segment: '*', '?', '[...]', '\\' escapes. */
static bool op_match(const char *pat, const char *s) {
    while (*pat) {
        if (*pat == '*') {
            pat++;
            for (const char *t = s;; t++) {
                if (op_match(pat, t)) {
                    return true;
                }
                if (!*t) {
                    return false;
                }
            }
        }
        if (!*s) {
            return false;
        }
        if (*pat == '?') {
            pat++;
            s++;
            continue;
        }
        if (*pat == '[') {
            const char *q = pat + SKIP_ONE;
            bool neg = *q == '^';
            q += neg;
            bool hit = false;
            while (*q && *q != ']') {
                char lo = *q;
                char hi = lo;
                if (q[SKIP_ONE] == '-' && q[PAIR_LEN] && q[PAIR_LEN] != ']') {
                    hi = q[PAIR_LEN];
                    q += PAIR_LEN;
                }
                hit = hit || (*s >= lo && *s <= hi);
                q++;
            }
            if (*q != ']' || hit == neg) {
                return false;
            }
            pat = q + SKIP_ONE;
            s++;
            continue;
        }
        if (*pat == '\\' && pat[SKIP_ONE]) {
            pat++;
        }
        if (*pat != *s) {
            return false;
        }
        pat++;
        s++;
    }
    return *s == '\0';
}

/* Does `rel` (a path below the Go file's directory) match the embed
 * pattern: segment by segment, a matched directory taking its files except
 * hidden ones ('.', '_') unless `all`. */
static bool op_embeds(const char *pattern, const char *rel, bool all) {
    char pat[CBM_SZ_1K];
    char path[CBM_SZ_1K];
    snprintf(pat, sizeof(pat), "%s", pattern);
    snprintf(path, sizeof(path), "%s", rel);
    char *ps = pat;
    char *rs = path;
    while (ps && rs) {
        char *pn = strchr(ps, '/');
        char *rn = strchr(rs, '/');
        if (pn) {
            *pn = '\0';
        }
        if (rn) {
            *rn = '\0';
        }
        if (!op_match(ps, rs)) {
            return false;
        }
        ps = pn ? pn + SKIP_ONE : NULL;
        rs = rn ? rn + SKIP_ONE : NULL;
        if (!ps) {
            /* pattern consumed: the file itself, or a file under a matched dir */
            for (char *seg = rs; seg && !all;) {
                if (seg[0] == '.' || seg[0] == '_') {
                    return false;
                }
                char *next = strchr(seg, '/');
                seg = next ? next + SKIP_ONE : NULL;
            }
            return true;
        }
    }
    return false;
}

static int op_cmp_path(const void *a, const void *b) {
    const cbm_gbuf_node_t *x = *(const cbm_gbuf_node_t *const *)a;
    const cbm_gbuf_node_t *y = *(const cbm_gbuf_node_t *const *)b;
    return strcmp(x->file_path, y->file_path);
}

/* REFERENCES_FILE from the Go file to every file its //go:embed lines name;
 * `files` is every File node sorted by path, so a directory's files are one
 * range. */
static int op_embed(cbm_gbuf_t *gb, const cbm_gbuf_node_t *go_file, const char *text,
                    const cbm_gbuf_node_t **files, int nfiles) {
    char dir[CBM_SZ_1K];
    op_dirname(go_file->file_path, dir, sizeof(dir));
    size_t dl = strlen(dir);
    int linked = 0;
    for (const char *p = strstr(text, "//go:embed "); p; p = strstr(p + SKIP_ONE, "//go:embed ")) {
        if (p != text && p[-SKIP_ONE] != '\n') {
            continue; /* a directive starts its line */
        }
        const char *eol = strchr(p, '\n');
        char line[CBM_SZ_1K];
        const char *args = p + OP_SLEN("//go:embed ");
        snprintf(line, sizeof(line), "%.*s", eol ? (int)(eol - args) : (int)strlen(args), args);
        for (char *tok = line; *tok;) {
            while (*tok == ' ' || *tok == '\t' || *tok == '\r') {
                tok++;
            }
            char *e = tok;
            while (*e && *e != ' ' && *e != '\t' && *e != '\r') {
                e++;
            }
            char save = *e;
            *e = '\0';
            bool all = strncmp(tok, "all:", OP_SLEN("all:")) == 0;
            const char *pattern = all ? tok + OP_SLEN("all:") : tok;
            if (pattern[0] && pattern[0] != '"' && pattern[0] != '`') {
                /* files below dir: the sorted range starting at "dir/" */
                int lo = 0;
                int hi = dl ? nfiles : 0;
                while (lo < hi) {
                    int mid = lo + (hi - lo) / PAIR_LEN;
                    if (strncmp(files[mid]->file_path, dir, dl) < 0 ||
                        (strncmp(files[mid]->file_path, dir, dl) == 0 &&
                         files[mid]->file_path[dl] < '/')) {
                        lo = mid + SKIP_ONE;
                    } else {
                        hi = mid;
                    }
                }
                for (int i = lo; i < nfiles; i++) {
                    const char *fp = files[i]->file_path;
                    if (dl && (strncmp(fp, dir, dl) != 0 || fp[dl] != '/')) {
                        break;
                    }
                    const char *rel = dl ? fp + dl + SKIP_ONE : fp;
                    if (files[i] != go_file && op_embeds(pattern, rel, all)) {
                        cbm_gbuf_insert_edge(gb, go_file->id, files[i]->id, "REFERENCES_FILE",
                                             "{\"via\":\"go:embed\"}");
                        linked++;
                    }
                }
            }
            *e = save;
            tok = e;
        }
    }
    return linked;
}

/* ── The pass ─────────────────────────────────────────────────────────── */

static bool op_is_go(const char *path) {
    size_t n = strlen(path);
    return n > OP_SLEN(".go") && strcmp(path + n - OP_SLEN(".go"), ".go") == 0;
}

int cbm_pipeline_pass_operator(cbm_pipeline_ctx_t *ctx) {
    cbm_gbuf_t *gb = ctx->gbuf;
    const cbm_gbuf_node_t **all = NULL;
    int count = 0;
    if (!gb || !ctx->repo_path || cbm_gbuf_find_by_label(gb, "File", &all, &count) != 0) {
        return 0;
    }
    const cbm_gbuf_node_t **files =
        cbm_calloc(CBM_MEM_CLASS_OTHER, (size_t)(count ? count : SKIP_ONE) * sizeof(*files));
    if (!files) {
        return CBM_NOT_FOUND;
    }
    int nfiles = 0;
    for (int i = 0; i < count; i++) {
        if (all[i]->file_path) {
            files[nfiles++] = all[i];
        }
    }
    qsort((void *)files, (size_t)nfiles, sizeof(*files), op_cmp_path);
    CBMHashTable *by_file = op_functions_by_file(gb);
    CBMHashTable *groups = cbm_ht_create(0);
    CBMHashTable *seen = cbm_ht_create(0);
    op_modules_t mods = {0};
    for (int i = 0; i < nfiles; i++) {
        const char *slash = strrchr(files[i]->file_path, '/');
        if (strcmp(slash ? slash + SKIP_ONE : files[i]->file_path, "go.mod") == 0) {
            char path[CBM_SZ_4K];
            snprintf(path, sizeof(path), "%s/%s", ctx->repo_path, files[i]->file_path);
            char *text = op_read_file(path);
            if (text) {
                op_note_module(&mods, files[i]->file_path, text);
                cbm_free(CBM_MEM_CLASS_OTHER, text);
            }
        }
    }
    op_index_t ix = {.mods = &mods, .dir_types = op_types_by_dir(gb)};
    int handles = 0;
    int embeds = 0;
    bool ready = by_file && groups && seen && ix.dir_types;
    for (int i = 0; ready && i < nfiles; i++) {
        if (!op_is_go(files[i]->file_path) || cbm_pipeline_check_cancel(ctx)) {
            continue;
        }
        char path[CBM_SZ_4K];
        snprintf(path, sizeof(path), "%s/%s", ctx->repo_path, files[i]->file_path);
        char *text = op_read_file(path);
        if (!text) {
            continue;
        }
        if (strstr(text, "controller-runtime") || strstr(text, "source.Kind(")) {
            handles += op_controller_calls(gb, by_file, &ix, files[i]->file_path, text);
        }
        op_scan_groups(groups, seen, files[i]->file_path, text);
        if (strstr(text, "//go:embed ")) {
            embeds += op_embed(gb, files[i], text, files, nfiles);
        }
        cbm_free(CBM_MEM_CLASS_OTHER, text);
    }
    int crd_types = ready ? op_link_crd_types(gb, &ix, groups) : 0;
    if (ix.dir_types) {
        cbm_ht_foreach(ix.dir_types, op_free_nodes_entry, NULL);
        cbm_ht_free(ix.dir_types);
    }
    op_modules_free(&mods);
    if (groups) {
        cbm_ht_foreach(groups, op_free_groups, NULL);
        cbm_ht_free(groups);
    }
    if (seen) {
        cbm_ht_foreach(seen, op_free_seen, NULL);
        cbm_ht_free(seen);
    }
    if (by_file) {
        cbm_ht_foreach(by_file, op_free_spans, NULL);
        cbm_ht_free(by_file);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)files);
    if (handles + embeds + crd_types > 0) {
        char h[CBM_SZ_32];
        char e[CBM_SZ_32];
        char c[CBM_SZ_32];
        snprintf(h, sizeof(h), "%d", handles);
        snprintf(e, sizeof(e), "%d", embeds);
        snprintf(c, sizeof(c), "%d", crd_types);
        cbm_log_info("pass.operator", "handles", h, "embeds", e, "crd_types", c);
    }
    return 0;
}
