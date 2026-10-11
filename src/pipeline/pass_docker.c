/*
 * pass_docker.c — the container build layer.
 *
 * PHASE 4 P4.1a: what a Dockerfile builds on. Each base it names DEPENDS_ON
 * an Image node -- an edge from the Dockerfile's Module:
 *   FROM <image> [AS <stage>]          {via:from}
 *   COPY --from=<image> ...            {via:copy-from}
 * A stage of the same file is no image (FROM builder, COPY --from=builder or
 * --from=0), nor is `scratch`. ${ARG} references are expanded from the ARG
 * defaults in scope (global ARGs before the first FROM; a stage's own ARG and
 * ENV); a reference without a value leaves the image unknown, and an unknown
 * image is no edge.
 *
 * Image identity is the normalised repository: docker.io for an image
 * without a registry host, library/ for an official one-segment image;
 * tag and digest stay on the edge. Run at the end of the K8s pass.
 */
#include "foundation/constants.h"
#include "foundation/compat.h"
#include "foundation/compat_fs.h"
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

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { DK_MAX_STAGES = 64 };

typedef struct dk_var {
    const char *name;
    const char *value; /* NULL: declared without a value */
    struct dk_var *next;
} dk_var_t;

typedef struct {
    cbm_pipeline_ctx_t *ctx;
    CBMArena *a;
    const char *src;
    const char *file;
    int64_t module;
    dk_var_t *global;                  /* ARGs before the first FROM */
    dk_var_t *local;                   /* the current stage's ARG / ENV */
    const char *stages[DK_MAX_STAGES]; /* stage names; NULL: unnamed */
    int stage;                         /* index of the current stage; -1 before FROM */
    int edges;
} dk_t;

static bool dk_type(TSNode n, const char *t) {
    return !ts_node_is_null(n) && strcmp(ts_node_type(n), t) == 0;
}

static const char *dk_text(const dk_t *d, TSNode n) {
    uint32_t b = ts_node_start_byte(n);
    uint32_t e = ts_node_end_byte(n);
    char *s = cbm_arena_alloc(d->a, (size_t)(e - b) + SKIP_ONE);
    if (s) {
        memcpy(s, d->src + b, e - b);
        s[e - b] = '\0';
    }
    return s;
}

/* A value as written: quotes of a quoted string removed. */
static const char *dk_value(const dk_t *d, TSNode n) {
    const char *s = dk_text(d, n);
    size_t l = s ? strlen(s) : 0;
    if (l >= PAIR_LEN && (s[0] == '"' || s[0] == '\'') && s[l - SKIP_ONE] == s[0]) {
        char *v = cbm_arena_alloc(d->a, l - SKIP_ONE);
        if (v) {
            memcpy(v, s + SKIP_ONE, l - PAIR_LEN);
            v[l - PAIR_LEN] = '\0';
        }
        return v;
    }
    return s;
}

static const dk_var_t *dk_find(const dk_var_t *v, const char *name, size_t nl) {
    for (; v; v = v->next) {
        if (strlen(v->name) == nl && strncmp(v->name, name, nl) == 0) {
            return v;
        }
    }
    return NULL;
}

static void dk_set(dk_t *d, dk_var_t **list, const char *name, const char *value) {
    dk_var_t *v = cbm_arena_alloc(d->a, sizeof(*v));
    if (v) {
        *v = (dk_var_t){.name = name, .value = value, .next = *list};
        *list = v;
    }
}

/* ASCII case-insensitive equality (stage names, `scratch`). */
static bool dk_ieq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return false;
        }
    }
    return *a == *b;
}

static bool dk_name_char(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

/* `text` with $X / ${X} / ${X:-d} / ${X-d} expanded from `vars`; NULL when a
 * reference has no value. */
static const char *dk_expand(dk_t *d, const dk_var_t *vars, const char *text) {
    size_t cap = strlen(text) + SKIP_ONE;
    size_t len = 0;
    char *out = cbm_arena_alloc(d->a, cap);
    for (const char *p = text; out && *p;) {
        if (*p != '$') {
            if (len + PAIR_LEN > cap) {
                char *grown = cbm_arena_alloc(d->a, cap * PAIR_LEN);
                if (!grown) {
                    return NULL;
                }
                memcpy(grown, out, len);
                out = grown;
                cap *= PAIR_LEN;
            }
            out[len++] = *p++;
            continue;
        }
        const char *name = p + SKIP_ONE;
        bool braced = *name == '{';
        if (braced) {
            name++;
        }
        size_t nl = 0;
        while (dk_name_char(name[nl])) {
            nl++;
        }
        if (nl == 0) {
            return NULL;
        }
        const char *after = name + nl;
        const char *dflt = NULL;
        size_t dl = 0;
        if (braced) {
            const char *close = strchr(after, '}');
            if (!close) {
                return NULL;
            }
            if ((after[0] == ':' && after[SKIP_ONE] == '-') || after[0] == '-') {
                dflt = after + (after[0] == ':' ? PAIR_LEN : SKIP_ONE);
                dl = (size_t)(close - dflt);
            } else if (after != close) {
                return NULL; /* ${X:+y} and other forms: unknown */
            }
            after = close + SKIP_ONE;
        }
        const dk_var_t *v = dk_find(vars, name, nl);
        const char *val = v && v->value ? v->value : NULL;
        size_t vl = val ? strlen(val) : dl;
        if (!val && !dflt) {
            return NULL;
        }
        const char *from = val ? val : dflt;
        if (len + vl + SKIP_ONE > cap) {
            size_t ncap = (len + vl + SKIP_ONE) * PAIR_LEN;
            char *grown = cbm_arena_alloc(d->a, ncap);
            if (!grown) {
                return NULL;
            }
            memcpy(grown, out, len);
            out = grown;
            cap = ncap;
        }
        memcpy(out + len, from, vl);
        len += vl;
        p = after;
    }
    if (out) {
        out[len] = '\0';
    }
    return out;
}

/* The repository identity of image reference `ref` into out. */
static bool dk_normalize(const char *ref, char *out, size_t sz) {
    char r[CBM_SZ_512];
    snprintf(r, sizeof(r), "%s", ref);
    char *at = strchr(r, '@');
    if (at) {
        *at = '\0';
    }
    char *slash = strrchr(r, '/');
    char *colon = strchr(slash ? slash : r, ':');
    if (colon) {
        *colon = '\0';
    }
    if (!r[0] || strchr(r, ' ') || strchr(r, '$')) {
        return false;
    }
    char *first_end = strchr(r, '/');
    if (!first_end) {
        snprintf(out, sz, "docker.io/library/%s", r);
        return true;
    }
    size_t fl = (size_t)(first_end - r);
    bool host = memchr(r, '.', fl) || memchr(r, ':', fl) ||
                (fl == strlen("localhost") && strncmp(r, "localhost", fl) == 0);
    if (!host) {
        snprintf(out, sz, "docker.io/%s", r);
        return true;
    }
    const char *rest = first_end + SKIP_ONE;
    bool hub =
        (fl == strlen("docker.io") && strncmp(r, "docker.io", fl) == 0) ||
        (fl == strlen("index.docker.io") && strncmp(r, "index.docker.io", fl) == 0) ||
        (fl == strlen("registry-1.docker.io") && strncmp(r, "registry-1.docker.io", fl) == 0);
    if (hub) {
        snprintf(out, sz, "docker.io/%s%s", strchr(rest, '/') ? "" : "library/", rest);
    } else {
        snprintf(out, sz, "%.*s/%s", (int)fl, r, rest);
    }
    return true;
}

/* An earlier stage of this file: its name, or a stage index. */
static bool dk_is_stage(const dk_t *d, const char *ref) {
    bool digits = ref[0] != '\0';
    for (const char *p = ref; *p; p++) {
        digits = digits && isdigit((unsigned char)*p);
    }
    if (digits) {
        return true;
    }
    for (int i = 0; i < d->stage && i < DK_MAX_STAGES; i++) {
        if (d->stages[i] && dk_ieq(d->stages[i], ref)) {
            return true;
        }
    }
    return false;
}

/* DEPENDS_ON from the Dockerfile to the Image of resolved reference `ref`. */
static void dk_link(dk_t *d, const char *ref, const char *via, int line) {
    char repo[CBM_SZ_512];
    if (dk_ieq(ref, "scratch") || !dk_normalize(ref, repo, sizeof(repo))) {
        return;
    }
    char qn[CBM_SZ_1K];
    snprintf(qn, sizeof(qn), "__image__%s", repo);
    char esc_repo[CBM_SZ_1K];
    cbm_json_escape(esc_repo, (int)sizeof(esc_repo), repo);
    char node_props[CBM_SZ_2K];
    snprintf(node_props, sizeof(node_props), "{\"repository\":\"%s\"}", esc_repo);
    int64_t img = cbm_gbuf_upsert_node(d->ctx->gbuf, "Image", repo, qn, "", 0, 0, node_props);
    if (img <= 0) {
        return;
    }
    char esc_ref[CBM_SZ_1K];
    cbm_json_escape(esc_ref, (int)sizeof(esc_ref), ref);
    char props[CBM_SZ_2K];
    snprintf(props, sizeof(props), "{\"via\":\"%s\",\"image\":\"%s\",\"stage\":%d,\"line\":%d}",
             via, esc_ref, d->stage, line);
    cbm_gbuf_insert_edge(d->ctx->gbuf, d->module, img, "DEPENDS_ON", props);
    d->edges++;
}

static int dk_line(TSNode n) {
    return (int)ts_node_start_point(n).row + SKIP_ONE;
}

static void dk_arg(dk_t *d, TSNode ins) {
    TSNode nm = ts_node_child_by_field_name(ins, "name", (uint32_t)strlen("name"));
    TSNode df = ts_node_child_by_field_name(ins, "default", (uint32_t)strlen("default"));
    if (ts_node_is_null(nm)) {
        return;
    }
    const char *name = dk_text(d, nm);
    if (!name) {
        return;
    }
    if (d->stage < 0) {
        dk_set(d, &d->global, name, ts_node_is_null(df) ? NULL : dk_value(d, df));
        return;
    }
    const char *value = NULL;
    if (!ts_node_is_null(df)) {
        const char *raw = dk_value(d, df);
        value = raw ? dk_expand(d, d->local, raw) : NULL;
    } else {
        const dk_var_t *g = dk_find(d->global, name, strlen(name));
        value = g ? g->value : NULL;
    }
    dk_set(d, &d->local, name, value);
}

static void dk_env(dk_t *d, TSNode ins) {
    if (d->stage < 0) {
        return;
    }
    for (uint32_t i = 0; i < ts_node_named_child_count(ins); i++) {
        TSNode pair = ts_node_named_child(ins, i);
        if (!dk_type(pair, "env_pair")) {
            continue;
        }
        TSNode nm = ts_node_child_by_field_name(pair, "name", (uint32_t)strlen("name"));
        TSNode vl = ts_node_child_by_field_name(pair, "value", (uint32_t)strlen("value"));
        if (ts_node_is_null(nm)) {
            continue;
        }
        const char *raw = ts_node_is_null(vl) ? NULL : dk_value(d, vl);
        dk_set(d, &d->local, dk_text(d, nm), raw ? dk_expand(d, d->local, raw) : NULL);
    }
}

static void dk_from(dk_t *d, TSNode ins) {
    TSNode spec = {0};
    TSNode alias = ts_node_child_by_field_name(ins, "as", (uint32_t)strlen("as"));
    for (uint32_t i = 0; i < ts_node_named_child_count(ins); i++) {
        if (dk_type(ts_node_named_child(ins, i), "image_spec")) {
            spec = ts_node_named_child(ins, i);
        }
    }
    const char *ref = ts_node_is_null(spec) ? NULL : dk_expand(d, d->global, dk_text(d, spec));
    d->stage++;
    d->local = NULL;
    if (ref && !dk_is_stage(d, ref)) {
        dk_link(d, ref, "from", dk_line(ins));
    }
    if (d->stage < DK_MAX_STAGES) {
        d->stages[d->stage] = ts_node_is_null(alias) ? NULL : dk_text(d, alias);
    }
}

static void dk_copy(dk_t *d, TSNode ins) {
    static const char FROM[] = "--from=";
    for (uint32_t i = 0; i < ts_node_named_child_count(ins); i++) {
        TSNode p = ts_node_named_child(ins, i);
        if (!dk_type(p, "param")) {
            continue;
        }
        const char *t = dk_text(d, p);
        if (!t || strncmp(t, FROM, sizeof(FROM) - SKIP_ONE) != 0) {
            continue;
        }
        const char *ref = dk_expand(d, d->local, t + sizeof(FROM) - SKIP_ONE);
        if (ref && ref[0] && !dk_is_stage(d, ref)) {
            dk_link(d, ref, "copy-from", dk_line(ins));
        }
    }
}

static void dk_file(dk_t *d, TSNode root) {
    for (uint32_t i = 0; i < ts_node_named_child_count(root); i++) {
        TSNode ins = ts_node_named_child(root, i);
        if (dk_type(ins, "arg_instruction")) {
            dk_arg(d, ins);
        } else if (dk_type(ins, "env_instruction")) {
            dk_env(d, ins);
        } else if (dk_type(ins, "from_instruction")) {
            dk_from(d, ins);
        } else if (dk_type(ins, "copy_instruction") && d->stage >= 0) {
            dk_copy(d, ins);
        }
    }
}

static char *dk_read(const char *path, size_t *len) {
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
    enum { DK_TS_PAD = 16 }; /* tree-sitter's lexer reads past the end */
    char *buf = cbm_alloc(CBM_MEM_CLASS_OTHER, (size_t)size + DK_TS_PAD);
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }
    size_t got = fread(buf, SKIP_ONE, (size_t)size, f);
    (void)fclose(f);
    memset(buf + got, 0, DK_TS_PAD);
    *len = got;
    return buf;
}

void cbm_pipeline_pass_docker(cbm_pipeline_ctx_t *ctx, const cbm_file_info_t *files,
                              int file_count) {
    TSParser *parser = NULL;
    CBMArena arena;
    cbm_arena_init_lazy(&arena, CBM_SZ_4K);
    int edges = 0;
    for (int i = 0; i < file_count; i++) {
        if (files[i].language != CBM_LANG_DOCKERFILE) {
            continue;
        }
        const char *mqn = cbm_fqn_module(&arena, ctx->project_name, files[i].rel_path);
        const cbm_gbuf_node_t *mod = mqn ? cbm_gbuf_find_by_qn(ctx->gbuf, mqn) : NULL;
        if (!mod) {
            continue;
        }
        size_t len = 0;
        char *src = dk_read(files[i].path, &len);
        if (!src) {
            continue;
        }
        if (!parser) {
            parser = ts_parser_new();
        }
        TSTree *tree = NULL;
        if (parser && ts_parser_set_language(parser, cbm_ts_language(CBM_LANG_DOCKERFILE))) {
            tree = ts_parser_parse_string(parser, NULL, src, (uint32_t)len);
        }
        if (tree) {
            dk_t d = {.ctx = ctx,
                      .a = &arena,
                      .src = src,
                      .file = files[i].rel_path,
                      .module = mod->id,
                      .stage = -1};
            dk_file(&d, ts_tree_root_node(tree));
            edges += d.edges;
            ts_tree_delete(tree);
        }
        cbm_free(CBM_MEM_CLASS_OTHER, src);
    }
    if (parser) {
        ts_parser_delete(parser);
    }
    cbm_arena_destroy(&arena);
    if (edges > 0) {
        char buf[CBM_SZ_32];
        snprintf(buf, sizeof(buf), "%d", edges);
        cbm_log_info("pass.docker.images", "edges", buf);
    }
}
