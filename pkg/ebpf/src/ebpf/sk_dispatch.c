/*
Copyright © 2022 Francisco de Borja Aranda Castillejo me@fbac.dev

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * BPF socket lookup program that dispatches connections destined to a
 * configured set of open ports.
 *
 * Program expects the target socket to be in the `target_socket` BPF map.
 * Port is considered open when an entry for that port number exists in the
 * `add_ports` BPF hashmap.
 *
 */

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Declare BPF maps */

/* List of additional service ports. 
Key is the port number. */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, __u8);
	__uint(max_entries, 1024);
} add_ports SEC(".maps");

/* Target socket */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} target_socket SEC(".maps");

/* Dispatcher program for the echo service */
SEC("sk_lookup/sk_dispatch")
int sk_dispatch(struct bpf_sk_lookup *ctx)
{
	const __u32 zero = 0;
	struct bpf_sock *sk;
	__u16 port;
	__u8 *open;
	long err;

	/* Is echo service enabled on packets destination port? */
	port = ctx->local_port;
	open = bpf_map_lookup_elem(&add_ports, &port);
	if (!open)
		return SK_PASS;

	/* Get echo server socket */
	sk = bpf_map_lookup_elem(&target_socket, &zero);
	if (!sk)
		return SK_DROP;

	/* Dispatch the packet to echo server socket */
	err = bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);
	return err ? SK_DROP : SK_PASS;
}

SEC("license") const char __license[] = "Dual BSD/GPL";