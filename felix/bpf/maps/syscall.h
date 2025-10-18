// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf.h>

#include "libbpf.h"

union bpf_attr *bpf_maps_attr_alloc() {
   union bpf_attr *attr = malloc(sizeof(union bpf_attr));
   memset(attr, 0, sizeof(union bpf_attr));
   return attr;
}

// bpf_attr_setup_obj_get sets up the bpf_attr union for use with BPF_OBJ_GET.
// A C function makes this easier because unions aren't easy to access from Go.
void bpf_maps_attr_setup_obj_get(union bpf_attr *attr, char *path, __u32 flags) {
const size_t attr_sz = offsetof(union bpf_attr, path_fd) + sizeof(((union bpf_attr *)0)->path_fd);
   memset(attr, 0, attr_sz);
   attr->pathname = (__u64)(unsigned long)(void*)path;
   attr->bpf_fd = 0;
   attr->file_flags = 0;
}


int get_size(union bpf_attr *attr) {
   return offsetof(union bpf_attr, path_fd) + sizeof(((union bpf_attr *)0)->path_fd);
}

static void set_errno(int ret) {
	errno = ret >= 0 ? ret : -ret;
}

int bpf_get_map_fd_by_id(__u32 id)
{
	int fd = bpf_map_get_fd_by_id(id);
	set_errno(fd);
	return fd;
}

int bpf_get_map_fd_by_pin(const char *path)
{
	printf("bpf_get_map_fd_by_pin: path=%s\n", path);
	int fd = bpf_obj_get(path);
	set_errno(fd);
	return fd;
}

int bpf_map_elem_update(int map_fd, void *key, void *value, __u64 flags)
{
	int ret = bpf_map_update_elem(map_fd, key, value, flags);
	set_errno(ret);
	return ret;
}

int bpf_map_elem_lookup(int map_fd, void *key, void *value)
{
	int ret = bpf_map_lookup_elem(map_fd, key, value);
	set_errno(ret);
	return ret;
}

int bpf_map_elem_delete(int map_fd, void *key)
{
	int ret = bpf_map_delete_elem(map_fd, key);
	set_errno(ret);
	return ret;
}
void bpf_map_batch_lookup(int fd, void *in_batch, void *out_batch, void *keys,
			  void *values, __u32 *count, __u64 flags)
{
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.flags = flags);

	set_errno(bpf_map_lookup_batch(fd, in_batch, out_batch, keys, values, count, &opts));
}


