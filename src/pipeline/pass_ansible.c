/*
 * pass_ansible.c — the Ansible layer.
 *
 * PHASE 7 P7.1: composition. A playbook or a task file -- a YAML file whose
 * top level is a sequence (manifests, values, CI and compose files are
 * mappings) -- IMPORTS {local_name: <directive>, via: ansible, line} what its
 * directives name:
 *   import_playbook: P                    the playbook P, from the file's
 *                                         directory
 *   include_tasks / import_tasks /
 *   include: T  (or {file: T})            the task file T, from the file's
 *                                         directory, else from the tasks/
 *                                         directory of the role holding it
 *   include_role / import_role: {name: R},
 *   roles: [R | {role: R} | {name: R}]    the role R: roles/R in the file's
 *                                         directory or above (a name may hold
 *                                         "/", roles/kubernetes/node), or a
 *                                         path ("./", "../") from the
 *                                         file's directory
 * (the ansible.builtin. prefix allowed). The edge goes from the file to the
 * target file's Module, or to the role's Folder; a target the graph does not
 * hold, or one holding a Jinja expression ({{ }}), makes none.
 */
#include "foundation/constants.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/hash_table.h"
#include "foundation/limits.h"
#include "foundation/log.h"
#include "foundation/mem_core.h"
#include "graph_buffer/graph_buffer.h"
#include "pipeline/pipeline.h"
#include "pipeline/pipeline_internal.h"
#include "cbm.h"
#include "helpers.h"
#include "lang_specs.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    cbm_pipeline_ctx_t *ctx;
    CBMHashTable *modules; /* file path -> its Module node */
    CBMHashTable *folders; /* directory -> its Folder node */
    const char *src;       /* the file's text */
    const char *file;      /* its repository path */
    char dir[CBM_SZ_1K];   /* its directory */
    char role[CBM_SZ_1K];  /* the role holding it (roles/<name>), or "" */
    int64_t from;          /* its File node */
    int edges;
} an_t;

static bool an_type(TSNode n, const char *t) {
    return !ts_node_is_null(n) && strcmp(ts_node_type(n), t) == 0;
}

/* A scalar's text (quotes stripped) into out; false for anything else. */
static bool an_scalar(const an_t *a, TSNode n, char *out, size_t sz) {
    while ((an_type(n, "flow_node") || an_type(n, "block_node") || an_type(n, "plain_scalar")) &&
           ts_node_named_child_count(n) == SKIP_ONE) {
        n = ts_node_named_child(n, 0);
    }
    if (ts_node_is_null(n)) { /* a pair without its key or value */
        return false;
    }
    uint32_t b = ts_node_start_byte(n);
    uint32_t e = ts_node_end_byte(n);
    if (an_type(n, "double_quote_scalar") || an_type(n, "single_quote_scalar")) {
        b++;
        e = e > b ? e - SKIP_ONE : b;
    } else if (!an_type(n, "string_scalar") && !an_type(n, "plain_scalar")) {
        return false;
    }
    if (e - b + SKIP_ONE > sz) {
        return false;
    }
    memcpy(out, a->src + b, e - b);
    out[e - b] = '\0';
    return out[0] != '\0';
}

/* The key of a mapping pair, its text, the ansible.builtin. prefix dropped. */
static bool an_key(const an_t *a, TSNode pair, char *out, size_t sz) {
    static const char BUILTIN[] = "ansible.builtin.";
    if (!an_scalar(a, ts_node_child_by_field_name(pair, "key", sizeof("key") - SKIP_ONE), out,
                   sz)) {
        return false;
    }
    size_t bl = sizeof(BUILTIN) - SKIP_ONE;
    if (strncmp(out, BUILTIN, bl) == 0) {
        memmove(out, out + bl, strlen(out + bl) + SKIP_ONE);
    }
    return true;
}

/* The value of `key` in a block mapping (under its block_node), or a null node. */
static TSNode an_get(const an_t *a, TSNode value, const char *key) {
    while (an_type(value, "block_node") && ts_node_named_child_count(value) == SKIP_ONE) {
        value = ts_node_named_child(value, 0);
    }
    for (uint32_t i = 0; an_type(value, "block_mapping") && i < ts_node_named_child_count(value);
         i++) {
        TSNode pair = ts_node_named_child(value, i);
        char k[CBM_SZ_64];
        if (an_type(pair, "block_mapping_pair") && an_key(a, pair, k, sizeof(k)) &&
            strcmp(k, key) == 0) {
            return ts_node_child_by_field_name(pair, "value", sizeof("value") - SKIP_ONE);
        }
    }
    return (TSNode){0};
}

static void an_edge(an_t *a, const cbm_gbuf_node_t *tgt, const char *kind, TSNode pair) {
    if (!tgt || a->from <= 0 || tgt->id == a->from) {
        return;
    }
    char props[CBM_SZ_128];
    snprintf(props, sizeof(props), "{\"local_name\":\"%s\",\"via\":\"ansible\",\"line\":%d}", kind,
             (int)ts_node_start_point(pair).row + SKIP_ONE);
    cbm_gbuf_insert_edge(a->ctx->gbuf, a->from, tgt->id, "IMPORTS", props);
    a->edges++;
}

/* A file `v` from `base` (repository-relative), its Module; NULL when none. */
static const cbm_gbuf_node_t *an_file(const an_t *a, const char *base, const char *v) {
    char path[CBM_SZ_1K];
    if (!cbm_repo_rel_join(base, v, path, sizeof(path))) {
        return NULL;
    }
    return cbm_ht_get(a->modules, path);
}

/* Role `name`'s Folder: a path ("./", "../") from the file's directory, else
 * roles/<name> in that directory or above. */
static const cbm_gbuf_node_t *an_role(const an_t *a, const char *name) {
    char path[CBM_SZ_1K];
    if (name[0] == '.' || name[0] == '/') {
        return cbm_repo_rel_join(a->dir, name, path, sizeof(path)) ? cbm_ht_get(a->folders, path)
                                                                   : NULL;
    }
    char d[CBM_SZ_1K];
    snprintf(d, sizeof(d), "%s", a->dir);
    for (;;) {
        snprintf(path, sizeof(path), "%s%sroles/%s", d, d[0] ? "/" : "", name);
        const cbm_gbuf_node_t *f = cbm_ht_get(a->folders, path);
        if (f || !d[0]) {
            return f;
        }
        char *s = strrchr(d, '/');
        if (s) {
            *s = '\0';
        } else {
            d[0] = '\0';
        }
    }
}

/* One mapping pair of a task or a play. */
static void an_pair(an_t *a, TSNode pair) {
    char key[CBM_SZ_64];
    char v[CBM_SZ_1K];
    if (!an_key(a, pair, key, sizeof(key))) {
        return;
    }
    TSNode value = ts_node_child_by_field_name(pair, "value", sizeof("value") - SKIP_ONE);
    if (strcmp(key, "import_playbook") == 0) {
        if (an_scalar(a, value, v, sizeof(v)) && !strstr(v, "{{")) {
            an_edge(a, an_file(a, a->dir, v), key, pair);
        }
    } else if (strcmp(key, "include_tasks") == 0 || strcmp(key, "import_tasks") == 0 ||
               strcmp(key, "include") == 0) {
        if ((an_scalar(a, value, v, sizeof(v)) ||
             an_scalar(a, an_get(a, value, "file"), v, sizeof(v))) &&
            !strstr(v, "{{")) {
            char tasks[CBM_SZ_1K];
            snprintf(tasks, sizeof(tasks), "%s/tasks", a->role);
            const cbm_gbuf_node_t *t = an_file(a, a->dir, v);
            an_edge(a, t ? t : a->role[0] ? an_file(a, tasks, v) : NULL, key, pair);
        }
    } else if (strcmp(key, "include_role") == 0 || strcmp(key, "import_role") == 0) {
        if (an_scalar(a, an_get(a, value, "name"), v, sizeof(v)) && !strstr(v, "{{")) {
            an_edge(a, an_role(a, v), key, pair);
        }
    } else if (strcmp(key, "roles") == 0) {
        while (an_type(value, "block_node") && ts_node_named_child_count(value) == SKIP_ONE) {
            value = ts_node_named_child(value, 0);
        }
        for (uint32_t i = 0;
             an_type(value, "block_sequence") && i < ts_node_named_child_count(value); i++) {
            TSNode item = ts_node_named_child(ts_node_named_child(value, i), 0);
            if ((an_scalar(a, item, v, sizeof(v)) ||
                 an_scalar(a, an_get(a, item, "role"), v, sizeof(v)) ||
                 an_scalar(a, an_get(a, item, "name"), v, sizeof(v))) &&
                !strstr(v, "{{")) {
                an_edge(a, an_role(a, v), key, ts_node_named_child(value, i));
            }
        }
    }
}

/* Every mapping that is a sequence item (a play or a task, also one nested in
 * block: / tasks: / handlers: ...): its pairs. */
static void an_walk(an_t *a, TSNode root) {
    TSTreeCursor cur = ts_tree_cursor_new(root);
    bool more = true;
    while (more) {
        TSNode c = ts_tree_cursor_current_node(&cur);
        if (an_type(c, "block_mapping")) {
            TSNode up = ts_node_parent(ts_node_parent(c));
            for (uint32_t i = 0;
                 an_type(up, "block_sequence_item") && i < ts_node_named_child_count(c); i++) {
                if (an_type(ts_node_named_child(c, i), "block_mapping_pair")) {
                    an_pair(a, ts_node_named_child(c, i));
                }
            }
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

/* The first content line of `src` starts a sequence item: Ansible content
 * (a playbook, a task list), not a mapping (manifest, values, CI, compose). */
static bool an_is_sequence(const char *src) {
    for (const char *p = src; *p;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        size_t s = 0;
        while (s < n && (p[s] == ' ' || p[s] == '\t' || p[s] == '\r')) {
            s++;
        }
        bool skip = s == n || p[s] == '#' ||
                    (n - s >= sizeof("---") - SKIP_ONE &&
                     strncmp(p + s, "---", sizeof("---") - SKIP_ONE) == 0);
        if (!skip) {
            return s == 0 && n >= PAIR_LEN && p[0] == '-' && p[SKIP_ONE] == ' ';
        }
        p = nl ? nl + SKIP_ONE : p + n;
    }
    return false;
}

/* The role holding `rel`: roles/<name> of the deepest "roles" component with
 * a name after it, or "". */
static void an_role_of(const char *rel, char *out, size_t sz) {
    out[0] = '\0';
    for (const char *p = rel; (p = strstr(p, "roles/")) != NULL; p++) {
        if (p != rel && p[-1] != '/') {
            continue;
        }
        const char *name = p + sizeof("roles/") - SKIP_ONE;
        const char *end = strchr(name, '/');
        if (end && strchr(end + SKIP_ONE, '/')) {
            snprintf(out, sz, "%.*s", (int)(end - rel), rel);
        }
    }
}

static char *an_read(const char *path, size_t *len) {
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
    enum { AN_TS_PAD = 16 }; /* tree-sitter's lexer reads past the end */
    char *buf = cbm_alloc(CBM_MEM_CLASS_OTHER, (size_t)size + AN_TS_PAD);
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }
    size_t got = fread(buf, SKIP_ONE, (size_t)size, f);
    (void)fclose(f);
    memset(buf + got, 0, AN_TS_PAD);
    *len = got;
    return buf;
}

/* path -> node index of one label's nodes. */
static CBMHashTable *an_index(cbm_pipeline_ctx_t *ctx, const char *label) {
    CBMHashTable *ix = cbm_ht_create(0);
    const cbm_gbuf_node_t **nodes = NULL;
    int n = 0;
    if (ix && cbm_gbuf_find_by_label(ctx->gbuf, label, &nodes, &n) == 0) {
        for (int i = 0; i < n; i++) {
            if (nodes[i]->file_path) {
                cbm_ht_set(ix, nodes[i]->file_path, (void *)nodes[i]);
            }
        }
    }
    return ix;
}

static bool an_is_yaml(const char *rel) {
    const char *dot = strrchr(rel, '.');
    return dot && (strcmp(dot, ".yml") == 0 || strcmp(dot, ".yaml") == 0);
}

void cbm_pipeline_pass_ansible(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                               int file_count) {
    an_t a = {.ctx = ctx};
    TSParser *parser = NULL;
    CBMHashTable *file_nodes = NULL;
    for (int i = 0; i < file_count; i++) {
        if (!an_is_yaml(files[i].rel_path)) {
            continue;
        }
        size_t len = 0;
        char *src = an_read(files[i].path, &len);
        if (!src || !an_is_sequence(src)) {
            cbm_free(CBM_MEM_CLASS_OTHER, src);
            continue;
        }
        if (!parser) {
            parser = ts_parser_new();
            if (!parser || !ts_parser_set_language(parser, cbm_ts_language(CBM_LANG_YAML))) {
                cbm_free(CBM_MEM_CLASS_OTHER, src);
                break;
            }
            a.modules = an_index(ctx, "Module");
            a.folders = an_index(ctx, "Folder");
            file_nodes = an_index(ctx, "File");
        }
        const cbm_gbuf_node_t *fnode =
            file_nodes ? cbm_ht_get(file_nodes, files[i].rel_path) : NULL;
        TSTree *tree = fnode ? ts_parser_parse_string(parser, NULL, src, (uint32_t)len) : NULL;
        if (tree) {
            const char *rel = files[i].rel_path;
            const char *slash = strrchr(rel, '/');
            a.src = src;
            a.file = rel;
            a.from = fnode->id;
            snprintf(a.dir, sizeof(a.dir), "%.*s", slash ? (int)(slash - rel) : 0, rel);
            an_role_of(rel, a.role, sizeof(a.role));
            an_walk(&a, ts_tree_root_node(tree));
            ts_tree_delete(tree);
        }
        cbm_free(CBM_MEM_CLASS_OTHER, src);
    }
    if (parser) {
        ts_parser_delete(parser);
    }
    if (a.modules) {
        cbm_ht_free(a.modules);
    }
    if (a.folders) {
        cbm_ht_free(a.folders);
    }
    if (file_nodes) {
        cbm_ht_free(file_nodes);
    }
    if (a.edges > 0) {
        char buf[CBM_SZ_32];
        snprintf(buf, sizeof(buf), "%d", a.edges);
        cbm_log_info("pass.ansible.edges", "imports", buf);
    }
}
