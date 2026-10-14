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
 *
 * PHASE 7 P7.2: tasks. A top-level sequence is not Ansible by itself (JSON
 * patches, image maps and service lists are sequences too): a file is
 * Ansible when it is a playbook (an item with hosts: / import_playbook:), a
 * role's tasks/ or handlers/ file, or -- to a fixpoint -- a task file an
 * Ansible file includes. Each of its tasks (a playbook's pre_tasks / tasks /
 * post_tasks, its handlers; a block's block / rescue / always, never the
 * block) is a Function named by its `name:`, else its module, QN
 * <file>::task/<n> or ::handler/<n> (document order), {source: ansible,
 * kind, module}, which the file DEFINES. A notify CALLS {via: notify, line}
 * every handler of that name or listen topic in the task's own role (the
 * directory before its tasks/), else in its file (a play's handlers). The
 * incremental repair declines on any change to Ansible content
 * (closure_ansible_decline): a notify joins two files.
 */
#include "foundation/constants.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
#include "foundation/hash_table.h"
#include "foundation/limits.h"
#include "foundation/log.h"
#include "foundation/mem_core.h"
#include "foundation/str_util.h" /* cbm_json_escape */
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

enum { AN_GROW_MIN = 16 };

/* A notify waiting for every handler: the task, its role and file, the name. */
typedef struct {
    int64_t task;
    char *scope_role; /* "" outside a role */
    char *scope_file;
    char *name;
    int line;
} an_notify_t;

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
    char **incs; /* pass 1: the task files includes name, in file order */
    int inc_n;
    int inc_cap;
    char base[CBM_SZ_1K];     /* pass 2: its File QN without `.__file__` */
    char role_dir[CBM_SZ_1K]; /* the role of its tasks / handlers, or "" */
    int ordinal[PAIR_LEN];    /* tasks, handlers so far in the file */
    CBMHashTable *handlers;   /* "<role or F:file>\x1f<name>" -> an_ids_t */
    an_notify_t *notes;
    int note_n;
    int note_cap;
    int tasks;
    int calls;
} an_t;

static bool an_type(TSNode n, const char *t) {
    return !ts_node_is_null(n) && strcmp(ts_node_type(n), t) == 0;
}

/* A quoted scalar's escapes decoded in place: `''` in single quotes;
 * `\"`, `\\`, `\n`, `\t` (any other `\x`: x) in double quotes. */
static void an_unescape(char *s, bool dq) {
    char *w = s;
    for (const char *r = s; *r; r++) {
        if (dq && r[0] == '\\' && r[SKIP_ONE]) {
            r++;
            *w++ = *r == 'n' ? '\n' : *r == 't' ? '\t' : *r;
        } else if (!dq && r[0] == '\'' && r[SKIP_ONE] == '\'') {
            r++;
            *w++ = '\'';
        } else {
            *w++ = *r;
        }
    }
    *w = '\0';
}

/* A scalar's text (quotes stripped, escapes decoded) into out; false for
 * anything else. */
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
    bool dq = an_type(n, "double_quote_scalar");
    bool sq = an_type(n, "single_quote_scalar");
    if (dq || sq) {
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
    if (dq || sq) {
        an_unescape(out, dq);
    }
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

/* Pass 1 keeps the task files an include names: they are Ansible content
 * even outside a role (an_mark_ansible). */
static void an_include(an_t *a, const cbm_gbuf_node_t *target) {
    if (!target || !target->file_path) {
        return;
    }
    if (a->inc_n == a->inc_cap) {
        int cap = a->inc_cap ? a->inc_cap * PAIR_LEN : AN_GROW_MIN;
        char **grown = cbm_realloc(CBM_MEM_CLASS_OTHER, a->incs, (size_t)cap * sizeof(*grown));
        if (!grown) {
            return;
        }
        a->incs = grown;
        a->inc_cap = cap;
    }
    a->incs[a->inc_n++] = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, target->file_path);
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
            const cbm_gbuf_node_t *target = t ? t : a->role[0] ? an_file(a, tasks, v) : NULL;
            an_edge(a, target, key, pair);
            an_include(a, target);
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

/* ── Tasks (P7.2) ─────────────────────────────────────────────────── */

/* Task keywords: every other key of a task is its module. */
static const char *const AN_KEYWORDS[] = {"name",
                                          "when",
                                          "tags",
                                          "become",
                                          "become_user",
                                          "become_method",
                                          "register",
                                          "loop",
                                          "with_items",
                                          "with_dict",
                                          "with_list",
                                          "with_fileglob",
                                          "with_nested",
                                          "with_together",
                                          "with_sequence",
                                          "with_subelements",
                                          "with_first_found",
                                          "loop_control",
                                          "notify",
                                          "listen",
                                          "ignore_errors",
                                          "changed_when",
                                          "failed_when",
                                          "delegate_to",
                                          "run_once",
                                          "vars",
                                          "environment",
                                          "until",
                                          "retries",
                                          "delay",
                                          "no_log",
                                          "check_mode",
                                          "diff",
                                          "any_errors_fatal",
                                          "throttle",
                                          "timeout",
                                          "args",
                                          "action",
                                          "local_action",
                                          "async",
                                          "poll",
                                          "debugger",
                                          "collections",
                                          "module_defaults",
                                          "remote_user",
                                          "connection",
                                          "port",
                                          "ignore_unreachable",
                                          "block",
                                          "rescue",
                                          "always",
                                          "delegate_facts"};

static bool an_keyword(const char *k) {
    for (size_t i = 0; i < sizeof(AN_KEYWORDS) / sizeof(AN_KEYWORDS[0]); i++) {
        if (strcmp(k, AN_KEYWORDS[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* The first named child of `n` of type `t`, or a null node. */
static TSNode an_child(TSNode n, const char *t) {
    for (uint32_t i = 0; !ts_node_is_null(n) && i < ts_node_named_child_count(n); i++) {
        if (an_type(ts_node_named_child(n, i), t)) {
            return ts_node_named_child(n, i);
        }
    }
    return (TSNode){0};
}

/* A value as a block sequence (under its block_node), or a null node. */
static TSNode an_seq(TSNode v) {
    while (an_type(v, "block_node") && ts_node_named_child_count(v) == SKIP_ONE) {
        v = ts_node_named_child(v, 0);
    }
    return an_type(v, "block_sequence") ? v : (TSNode){0};
}

/* The top-level block sequence of a parsed file, or a null node. */
static TSNode an_top(TSNode root) {
    return an_seq(an_child(an_child(root, "document"), "block_node"));
}

/* Item `i` of block sequence `seq` as a block mapping, or a null node. */
static TSNode an_item(TSNode seq, uint32_t i) {
    TSNode node = ts_node_named_child(ts_node_named_child(seq, i), 0);
    return an_type(node, "block_node") ? an_child(node, "block_mapping") : (TSNode){0};
}

/* Does block mapping `m` hold key `key` (the ansible.builtin. prefix allowed)? */
static bool an_has(const an_t *a, TSNode m, const char *key) {
    for (uint32_t i = 0; an_type(m, "block_mapping") && i < ts_node_named_child_count(m); i++) {
        char k[CBM_SZ_64];
        if (an_key(a, ts_node_named_child(m, i), k, sizeof(k)) && strcmp(k, key) == 0) {
            return true;
        }
    }
    return false;
}

/* A playbook: a top-level item is a play (hosts:) or imports one. */
static bool an_is_playbook(const an_t *a, TSNode top) {
    for (uint32_t i = 0; !ts_node_is_null(top) && i < ts_node_named_child_count(top); i++) {
        TSNode m = an_item(top, i);
        if (an_has(a, m, "hosts") || an_has(a, m, "import_playbook")) {
            return true;
        }
    }
    return false;
}

/* The role a task or handler file belongs to: the directory before the first
 * tasks/ or handlers/ under the last roles/ component that has one
 * (roles/kubernetes-apps/csi_driver/cinder for .../cinder/tasks/main.yml);
 * "" outside a role's tasks / handlers. */
static void an_role_dir(const char *rel, char *out, size_t sz) {
    out[0] = '\0';
    for (const char *p = rel; (p = strstr(p, "roles/")) != NULL; p++) {
        if (p != rel && p[-1] != '/') {
            continue;
        }
        /* the role's name: one character at least, then its tasks/ or handlers/ */
        const char *from = p + sizeof("roles/");
        if (from > p + strlen(p)) {
            break;
        }
        const char *t = strstr(from, "/tasks/");
        const char *h = strstr(from, "/handlers/");
        const char *end = t && (!h || t < h) ? t : h;
        if (end) {
            snprintf(out, sz, "%.*s", (int)(end - rel), rel);
        }
    }
}

/* Ids by key ("<scope>\x1f<name>"). */
typedef struct {
    int64_t *items;
    int count;
    int cap;
} an_ids_t;

static void an_ids_add(CBMHashTable *ix, const char *key, int64_t id) {
    an_ids_t *v = cbm_ht_get(ix, key);
    if (!v) {
        v = cbm_calloc(CBM_MEM_CLASS_OTHER, sizeof(*v));
        char *owned = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, key);
        if (!v || !owned) {
            cbm_free(CBM_MEM_CLASS_OTHER, v);
            cbm_free(CBM_MEM_CLASS_OTHER, owned);
            return;
        }
        cbm_ht_set(ix, owned, v);
    }
    if (v->count > 0 && v->items[v->count - SKIP_ONE] == id) {
        return; /* a handler named and listening alike */
    }
    if (v->count == v->cap) {
        int cap = v->cap ? v->cap * PAIR_LEN : AN_GROW_MIN;
        int64_t *grown = cbm_realloc(CBM_MEM_CLASS_OTHER, v->items, (size_t)cap * sizeof(int64_t));
        if (!grown) {
            return;
        }
        v->items = grown;
        v->cap = cap;
    }
    v->items[v->count++] = id;
}

/* A task list being walked: its sequence, the next item, handlers or not. */
typedef struct {
    TSNode seq;
    uint32_t next;
    bool handler;
} an_frame_t;

/* How many names a notify / listen value gives (a scalar: one; a block or
 * flow list: its items), its list node into `*list` (null for a scalar). */
static uint32_t an_name_count(const an_t *a, TSNode v, TSNode *list) {
    char probe[CBM_SZ_256];
    *list = (TSNode){0};
    if (an_scalar(a, v, probe, sizeof(probe))) {
        return SKIP_ONE;
    }
    while ((an_type(v, "block_node") || an_type(v, "flow_node")) &&
           ts_node_named_child_count(v) == SKIP_ONE) {
        v = ts_node_named_child(v, 0);
    }
    if (!an_type(v, "block_sequence") && !an_type(v, "flow_sequence")) {
        return 0;
    }
    *list = v;
    return ts_node_named_child_count(v);
}

/* Name `i` of a notify / listen value (see an_name_count). */
static bool an_name_at(const an_t *a, TSNode v, TSNode list, uint32_t i, char *out, size_t sz) {
    if (ts_node_is_null(list)) {
        return i == 0 && an_scalar(a, v, out, sz);
    }
    TSNode item = ts_node_named_child(list, i);
    if (an_type(list, "block_sequence")) {
        item = ts_node_named_child(item, 0);
    }
    return an_scalar(a, item, out, sz);
}

static void an_index_handler(an_t *a, const char *name, int64_t id) {
    char key[CBM_SZ_2K];
    if (a->role_dir[0]) {
        snprintf(key, sizeof(key), "%s\x1f%s", a->role_dir, name);
        an_ids_add(a->handlers, key, id);
    }
    snprintf(key, sizeof(key), "F:%s\x1f%s", a->file, name);
    an_ids_add(a->handlers, key, id);
}

static void an_note(an_t *a, int64_t task, const char *name, int line) {
    if (a->note_n == a->note_cap) {
        int cap = a->note_cap ? a->note_cap * PAIR_LEN : AN_GROW_MIN;
        an_notify_t *grown =
            cbm_realloc(CBM_MEM_CLASS_OTHER, a->notes, (size_t)cap * sizeof(*grown));
        if (!grown) {
            return;
        }
        a->notes = grown;
        a->note_cap = cap;
    }
    a->notes[a->note_n++] =
        (an_notify_t){.task = task,
                      .scope_role = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, a->role_dir),
                      .scope_file = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, a->file),
                      .name = cbm_mem_strdup(CBM_MEM_CLASS_OTHER, name),
                      .line = line};
}

/* Task (or handler) `m`: a Function named by its `name:` (else its module),
 * QN <file>::task/<n> (handler/<n>), {source: ansible, kind, module}; the
 * file DEFINES it. A handler is indexed by its name and listen topics; a
 * notify waits for every handler (an_link_notifies). */
static void an_task(an_t *a, TSNode m, bool handler) {
    char module[CBM_SZ_128] = "";
    for (uint32_t i = 0; !module[0] && i < ts_node_named_child_count(m); i++) {
        char k[CBM_SZ_128];
        if (an_key(a, ts_node_named_child(m, i), k, sizeof(k)) && !an_keyword(k)) {
            snprintf(module, sizeof(module), "%s", k);
        }
    }
    char action[CBM_SZ_256];
    if (!module[0] && (an_scalar(a, an_get(a, m, "action"), action, sizeof(action)) ||
                       an_scalar(a, an_get(a, m, "local_action"), action, sizeof(action)))) {
        snprintf(module, sizeof(module), "%.*s", (int)strcspn(action, " \t"), action);
    }
    char name[CBM_SZ_512];
    bool named = an_scalar(a, an_get(a, m, "name"), name, sizeof(name));
    if (!named) {
        snprintf(name, sizeof(name), "%s", module[0] ? module : "task");
    }
    const char *kind = handler ? "handler" : "task";
    int ord = ++a->ordinal[handler ? SKIP_ONE : 0];
    char qn[CBM_SZ_2K + CBM_SZ_64];
    char em[CBM_SZ_512];
    char props[CBM_SZ_1K];
    snprintf(qn, sizeof(qn), "%s::%s/%d", a->base, kind, ord);
    cbm_json_escape(em, (int)sizeof(em), module);
    snprintf(props, sizeof(props), "{\"source\":\"ansible\",\"kind\":\"%s\",\"module\":\"%s\"}",
             kind, em);
    int64_t id = cbm_gbuf_upsert_node(a->ctx->gbuf, "Function", name, qn, a->file,
                                      (int)ts_node_start_point(m).row + SKIP_ONE,
                                      (int)ts_node_end_point(m).row + SKIP_ONE, props);
    if (id <= 0) {
        return;
    }
    cbm_gbuf_insert_edge(a->ctx->gbuf, a->from, id, "DEFINES", "{}");
    a->tasks++;
    TSNode list;
    char n[CBM_SZ_256];
    if (handler) {
        if (named) {
            an_index_handler(a, name, id);
        }
        TSNode listen = an_get(a, m, "listen");
        uint32_t ln = an_name_count(a, listen, &list);
        for (uint32_t i = 0; i < ln; i++) {
            if (an_name_at(a, listen, list, i, n, sizeof(n))) {
                an_index_handler(a, n, id);
            }
        }
    }
    for (uint32_t i = 0; i < ts_node_named_child_count(m); i++) {
        TSNode pair = ts_node_named_child(m, i);
        char k[CBM_SZ_64];
        if (!an_key(a, pair, k, sizeof(k)) || strcmp(k, "notify") != 0) {
            continue;
        }
        TSNode v = ts_node_child_by_field_name(pair, "value", sizeof("value") - SKIP_ONE);
        uint32_t nn = an_name_count(a, v, &list);
        for (uint32_t j = 0; j < nn; j++) {
            if (an_name_at(a, v, list, j, n, sizeof(n)) && !strstr(n, "{{")) {
                an_note(a, id, n, (int)ts_node_start_point(pair).row + SKIP_ONE);
            }
        }
    }
}

/* The tasks of a task list, depth first: a `block:` item walks its block,
 * rescue and always lists before the next item (Ansible's order). */
static void an_task_list(an_t *a, TSNode seq, bool handler) {
    static const char *const PARTS[] = {"always", "rescue", "block"}; /* pushed last-first */
    an_frame_t *stack = NULL;
    int depth = 0;
    int cap = 0;
    TSNode push[sizeof(PARTS) / sizeof(PARTS[0]) + SKIP_ONE];
    int pn = 0;
    push[pn++] = seq;
    for (;;) {
        for (int p = 0; p < pn; p++) {
            if (ts_node_is_null(push[p])) {
                continue;
            }
            if (depth == cap) {
                int ncap = cap ? cap * PAIR_LEN : AN_GROW_MIN;
                an_frame_t *grown =
                    cbm_realloc(CBM_MEM_CLASS_OTHER, stack, (size_t)ncap * sizeof(*grown));
                if (!grown) {
                    cbm_free(CBM_MEM_CLASS_OTHER, stack);
                    return;
                }
                stack = grown;
                cap = ncap;
            }
            stack[depth++] = (an_frame_t){.seq = push[p], .next = 0, .handler = handler};
        }
        pn = 0;
        if (depth == 0) {
            break;
        }
        an_frame_t *f = &stack[depth - SKIP_ONE];
        if (f->next >= ts_node_named_child_count(f->seq)) {
            depth--;
            continue;
        }
        TSNode m = an_item(f->seq, f->next++);
        TSNode block = an_seq(an_get(a, m, "block"));
        if (ts_node_is_null(m)) {
            continue;
        }
        if (ts_node_is_null(block)) {
            an_task(a, m, f->handler);
            continue;
        }
        for (size_t p = 0; p < sizeof(PARTS) / sizeof(PARTS[0]); p++) {
            push[pn++] = an_seq(an_get(a, m, PARTS[p]));
        }
    }
    cbm_free(CBM_MEM_CLASS_OTHER, stack);
}

/* The tasks of an Ansible file: a playbook's plays (pre_tasks, tasks,
 * post_tasks, handlers), else its own items -- handlers under a handlers/
 * directory. */
static void an_file_tasks(an_t *a, TSNode top, bool playbook) {
    static const char *const SECTIONS[] = {"pre_tasks", "tasks", "post_tasks", "handlers"};
    if (!playbook) {
        bool handlers = strncmp(a->file, "handlers/", sizeof("handlers/") - SKIP_ONE) == 0 ||
                        strstr(a->file, "/handlers/") != NULL;
        an_task_list(a, top, handlers);
        return;
    }
    for (uint32_t i = 0; i < ts_node_named_child_count(top); i++) {
        TSNode play = an_item(top, i);
        for (size_t s = 0; !ts_node_is_null(play) && s < sizeof(SECTIONS) / sizeof(SECTIONS[0]);
             s++) {
            an_task_list(a, an_seq(an_get(a, play, SECTIONS[s])),
                         strcmp(SECTIONS[s], "handlers") == 0);
        }
    }
}

/* notify -> CALLS {via: notify, line} each handler of that name or listen
 * topic in the task's role, else in its file (a play's handlers). */
static void an_link_notifies(an_t *a) {
    for (int i = 0; i < a->note_n; i++) {
        const an_notify_t *n = &a->notes[i];
        char key[CBM_SZ_2K];
        const an_ids_t *ids = NULL;
        if (n->scope_role && n->scope_role[0]) {
            snprintf(key, sizeof(key), "%s\x1f%s", n->scope_role, n->name);
            ids = cbm_ht_get(a->handlers, key);
        }
        if (!ids) {
            snprintf(key, sizeof(key), "F:%s\x1f%s", n->scope_file, n->name);
            ids = cbm_ht_get(a->handlers, key);
        }
        char props[CBM_SZ_64];
        snprintf(props, sizeof(props), "{\"via\":\"notify\",\"line\":%d}", n->line);
        for (int j = 0; ids && j < ids->count; j++) {
            if (ids->items[j] != n->task) {
                cbm_gbuf_insert_edge(a->ctx->gbuf, n->task, ids->items[j], "CALLS", props);
                a->calls++;
            }
        }
    }
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

bool cbm_ansible_is_sequence(const char *src) {
    return an_is_sequence(src);
}

/* A YAML file whose top level is a sequence: Ansible when it is a playbook,
 * a role's tasks / handlers file, or included by an Ansible file. */
typedef struct {
    int file; /* index into files[] */
    bool playbook;
    bool ansible;
    int inc_lo; /* the task files it includes: incs[inc_lo, inc_hi) */
    int inc_hi;
} an_cand_t;

typedef struct {
    an_cand_t *items;
    int count;
    int cap;
} an_cands_t;

static an_cand_t *an_cand_push(an_cands_t *c, int file, int inc_lo) {
    if (c->count == c->cap) {
        int cap = c->cap ? c->cap * PAIR_LEN : AN_GROW_MIN;
        an_cand_t *grown = cbm_realloc(CBM_MEM_CLASS_OTHER, c->items, (size_t)cap * sizeof(*grown));
        if (!grown) {
            return NULL;
        }
        c->items = grown;
        c->cap = cap;
    }
    c->items[c->count] = (an_cand_t){.file = file, .inc_lo = inc_lo, .inc_hi = inc_lo};
    return &c->items[c->count++];
}

/* The per-file state both passes start from. */
static void an_begin_file(an_t *a, const char *rel, const cbm_gbuf_node_t *fnode, const char *src) {
    static const char FILE_SUFFIX[] = ".__file__";
    const char *slash = strrchr(rel, '/');
    a->src = src;
    a->file = rel;
    a->from = fnode->id;
    snprintf(a->dir, sizeof(a->dir), "%.*s", slash ? (int)(slash - rel) : 0, rel);
    an_role_of(rel, a->role, sizeof(a->role));
    an_role_dir(rel, a->role_dir, sizeof(a->role_dir));
    const char *qn = fnode->qualified_name ? fnode->qualified_name : "";
    size_t ql = strlen(qn);
    size_t sl = sizeof(FILE_SUFFIX) - SKIP_ONE;
    bool suffixed = ql > sl && strcmp(qn + ql - sl, FILE_SUFFIX) == 0;
    snprintf(a->base, sizeof(a->base), "%.*s", (int)(suffixed ? ql - sl : ql), qn);
    a->ordinal[0] = 0;
    a->ordinal[SKIP_ONE] = 0;
}

/* Which candidates are Ansible: playbooks and role tasks / handlers files,
 * then -- to a fixpoint, by a worklist -- what an Ansible file includes. */
static void an_mark_ansible(const an_t *a, an_cands_t *c, const cbm_file_info_t *files) {
    CBMHashTable *by_path = cbm_ht_create(0);
    int *work = cbm_calloc(CBM_MEM_CLASS_OTHER, ((size_t)c->count + SKIP_ONE) * sizeof(int));
    if (!by_path || !work) {
        cbm_free(CBM_MEM_CLASS_OTHER, work);
        if (by_path) {
            cbm_ht_free(by_path);
        }
        return;
    }
    int top = 0;
    for (int i = 0; i < c->count; i++) {
        const char *rel = files[c->items[i].file].rel_path;
        char role[CBM_SZ_1K];
        an_role_dir(rel, role, sizeof(role));
        cbm_ht_set(by_path, rel, (void *)(intptr_t)(i + SKIP_ONE));
        if (c->items[i].playbook || role[0]) {
            c->items[i].ansible = true;
            work[top++] = i;
        }
    }
    while (top > 0) {
        const an_cand_t *from = &c->items[work[--top]];
        for (int k = from->inc_lo; k < from->inc_hi; k++) {
            int j =
                a->incs[k] ? (int)(intptr_t)cbm_ht_get(by_path, a->incs[k]) - SKIP_ONE : -SKIP_ONE;
            if (j >= 0 && !c->items[j].ansible) {
                c->items[j].ansible = true;
                work[top++] = j;
            }
        }
    }
    cbm_free(CBM_MEM_CLASS_OTHER, work);
    cbm_ht_free(by_path);
}

static void an_free_ids_entry(const char *key, void *value, void *ud) {
    (void)ud;
    an_ids_t *v = value;
    if (v) {
        cbm_free(CBM_MEM_CLASS_OTHER, v->items);
        cbm_free(CBM_MEM_CLASS_OTHER, v);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, (void *)key);
}

static void an_free(an_t *a) {
    if (a->modules) {
        cbm_ht_free(a->modules);
    }
    if (a->folders) {
        cbm_ht_free(a->folders);
    }
    for (int i = 0; i < a->inc_n; i++) {
        cbm_free(CBM_MEM_CLASS_OTHER, a->incs[i]);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, a->incs);
    for (int i = 0; i < a->note_n; i++) {
        cbm_free(CBM_MEM_CLASS_OTHER, a->notes[i].scope_role);
        cbm_free(CBM_MEM_CLASS_OTHER, a->notes[i].scope_file);
        cbm_free(CBM_MEM_CLASS_OTHER, a->notes[i].name);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, a->notes);
    if (a->handlers) {
        cbm_ht_foreach(a->handlers, an_free_ids_entry, NULL);
        cbm_ht_free(a->handlers);
    }
}

/* Parse `files[i]` when it is a YAML file whose top level is a sequence;
 * NULL otherwise. The text stays in `*src` (the caller frees it). */
static TSTree *an_parse(TSParser *parser, const cbm_file_info_t *f, char **src) {
    size_t len = 0;
    *src = an_is_yaml(f->rel_path) ? an_read(f->path, &len) : NULL;
    if (!*src || !an_is_sequence(*src)) {
        return NULL;
    }
    return ts_parser_parse_string(parser, NULL, *src, (uint32_t)len);
}

void cbm_pipeline_pass_ansible(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                               int file_count) {
    an_t a = {.ctx = ctx};
    an_cands_t cands = {0};
    TSParser *parser = ts_parser_new();
    CBMHashTable *file_nodes = NULL;
    if (!parser || !ts_parser_set_language(parser, cbm_ts_language(CBM_LANG_YAML))) {
        if (parser) {
            ts_parser_delete(parser);
        }
        return;
    }
    /* pass 1: composition (IMPORTS); which files are playbooks, what each includes */
    for (int i = 0; i < file_count; i++) {
        char *src = NULL;
        TSTree *tree = an_parse(parser, &files[i], &src);
        if (tree && !file_nodes) {
            a.modules = an_index(ctx, "Module");
            a.folders = an_index(ctx, "Folder");
            file_nodes = an_index(ctx, "File");
        }
        const cbm_gbuf_node_t *fnode =
            tree && file_nodes ? cbm_ht_get(file_nodes, files[i].rel_path) : NULL;
        an_cand_t *c = fnode ? an_cand_push(&cands, i, a.inc_n) : NULL;
        if (c) {
            an_begin_file(&a, files[i].rel_path, fnode, src);
            an_walk(&a, ts_tree_root_node(tree));
            c->playbook = an_is_playbook(&a, an_top(ts_tree_root_node(tree)));
            c->inc_hi = a.inc_n;
        }
        if (tree) {
            ts_tree_delete(tree);
        }
        cbm_free(CBM_MEM_CLASS_OTHER, src);
    }
    /* pass 2: the tasks of the Ansible files, then their notifies */
    an_mark_ansible(&a, &cands, files);
    a.handlers = cands.count > 0 ? cbm_ht_create(0) : NULL;
    for (int c = 0; a.handlers && c < cands.count; c++) {
        const cbm_file_info_t *f = &files[cands.items[c].file];
        char *src = NULL;
        TSTree *tree = cands.items[c].ansible ? an_parse(parser, f, &src) : NULL;
        const cbm_gbuf_node_t *fnode = tree ? cbm_ht_get(file_nodes, f->rel_path) : NULL;
        if (fnode) {
            an_begin_file(&a, f->rel_path, fnode, src);
            an_file_tasks(&a, an_top(ts_tree_root_node(tree)), cands.items[c].playbook);
        }
        if (tree) {
            ts_tree_delete(tree);
        }
        cbm_free(CBM_MEM_CLASS_OTHER, src);
    }
    if (a.handlers) {
        an_link_notifies(&a);
    }
    ts_parser_delete(parser);
    if (file_nodes) {
        cbm_ht_free(file_nodes);
    }
    cbm_free(CBM_MEM_CLASS_OTHER, cands.items);
    an_free(&a);
    if (a.edges > 0 || a.tasks > 0) {
        char e[CBM_SZ_32];
        char t[CBM_SZ_32];
        char n[CBM_SZ_32];
        snprintf(e, sizeof(e), "%d", a.edges);
        snprintf(t, sizeof(t), "%d", a.tasks);
        snprintf(n, sizeof(n), "%d", a.calls);
        cbm_log_info("pass.ansible", "imports", e, "tasks", t, "notifies", n);
    }
}
