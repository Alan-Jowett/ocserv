/*
 * Copyright (C) 2013-2015 Nikos Mavrogiannopoulos
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * This file is part of ocserv.
 *
 * ocserv is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * ocserv is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#ifndef _XOPEN_SOURCE
# define _XOPEN_SOURCE
#endif
#include <unistd.h>
#include <vpn.h>
#include <c-ctype.h>
#include "plain.h"
#include "common-config.h"
#include "auth/common.h"

#ifdef SUPPORT_CUSTOM_AUTH
#include <dlfcn.h>


typedef struct plugin_vctx_st {
	char * module_name;
	void * dl_handle;
	string_tuple *config;

	int (*load_configuration)(const string_tuple config_value[]);
	int (*verify_bearer_token)(const char * token, unsigned token_length, char username[MAX_USERNAME_SIZE], int * access_state);
} plugin_vctx_st;

typedef struct plugin_ctx_st {
	char username[MAX_USERNAME_SIZE];
	const plugin_vctx_st * vctx_st;
	int token_verified;
	int access_state;
} plugin_ctx_st;

static void plugin_vhost_init(void **vctx, void *pool, void *additional)
{
	string_tuple *config = additional;
	struct plugin_vctx_st * vc;
	unsigned i;
	int retval;

	vc = talloc(pool, struct plugin_vctx_st);
	if (vc == NULL) {
		syslog(LOG_ERR, "ocserv-plugin allocation failure!\n");
		exit(1);
	}


	if (config == NULL) {
		syslog(LOG_ERR, "ocserv-plugin: no configuration passed!\n");
		exit(1);
	}

	vc->config = config;
	vc->module_name = NULL;

	for (i = 0; vc->config[i][0] != NULL; i ++) {
		if (strcmp(vc->config[i][0], "module") == 0) {
			vc->module_name = vc->config[i][1];
			break;
		}
	}

	if (vc->module_name == NULL) {
		syslog(LOG_ERR, "ocserv-plugin: module not present in config\n");
		exit(1);
	}

	// Clear last error
	dlerror();
	vc->dl_handle = dlopen(vc->module_name, RTLD_LAZY);
	if (vc->dl_handle == NULL) {
		syslog(LOG_ERR, "ocserv-plugin: failed to load plugin %s - %s\n", vc->module_name, dlerror());
		exit(1);
	}

	*(void**)&(vc->verify_bearer_token) = dlsym(vc->dl_handle, "verify_bearer_token");
	if (vc->verify_bearer_token == NULL) {
		syslog(LOG_ERR, "ocserv-plugin: failed to find verify_bearer_token in plugin %s - %s\n", vc->module_name, dlerror());
		exit(1);
	}

	*(void**)&(vc->load_configuration) = dlsym(vc->dl_handle, "load_configuration");
	if (vc->verify_bearer_token == NULL) {
		syslog(LOG_ERR, "ocserv-plugin: failed to find load_configuration in plugin %s - %s\n", vc->module_name, dlerror());
		exit(1);
	}
	
	retval = vc->load_configuration(config);
	if (retval != 0) {
		syslog(LOG_ERR, "ocserv-plugin: load_configuration in plugin %s  failed - %d\n", vc->module_name, retval);
		exit(1);
	}

	*vctx = (void*)vc;

	return;
}

static int plugin_auth_init(void **ctx, void *pool, void *vctx, const common_auth_init_st *info)
{
	plugin_vctx_st * vt = (plugin_vctx_st*)vctx;
	plugin_ctx_st * ct;
	ct = talloc_zero(pool, struct plugin_ctx_st);
	ct->vctx_st = vt;
	*ctx = (void*)ct;
	return ERR_AUTH_CONTINUE;
}

static int plugin_auth_user(void *ctx, char *username, int username_size)
{
	plugin_ctx_st * ct  = (plugin_ctx_st *)ctx;

	if (ct->token_verified) {
		strncpy(username, ct->username, username_size);
		return 0;
	}
	return ERR_AUTH_FAIL;
}

static int plugin_auth_pass(void *ctx, const char *pass, unsigned pass_len)
{
	int retval;
	plugin_ctx_st * ct  = (plugin_ctx_st *)ctx;
	
	retval = ct->vctx_st->verify_bearer_token(pass, pass_len, ct->username, &ct->access_state);
	
	ct->token_verified = 1;

	if (retval == 0 && ct->access_state != 0) {
		return 0;
	} else {
		return ERR_AUTH_FAIL;
	}
}

static int plugin_auth_msg(void *ctx, void *pool, passwd_msg_st *pst)
{
	pst->counter = 0; /* we support a single password */

	/* use the default prompt */
	return 0;
}

static void plugin_auth_deinit(void *ctx)
{
	talloc_free(ctx);
}

const struct auth_mod_st plugin_auth_funcs = {
	.type = AUTH_TYPE_PLUGIN,
	.allows_retries = 1,
	.vhost_init = plugin_vhost_init,
	.auth_init = plugin_auth_init,
	.auth_deinit = plugin_auth_deinit,
	.auth_msg = plugin_auth_msg,
	.auth_pass = plugin_auth_pass,
	.auth_user = plugin_auth_user,
	.auth_group = NULL,
	.group_list = NULL
};
#endif