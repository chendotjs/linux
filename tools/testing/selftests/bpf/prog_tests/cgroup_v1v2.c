// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#include "connect4_dropper.skel.h"

#include "cgroup_helpers.h"
#include "network_helpers.h"

static int run_test(int cgroup_fd, int server_fd, bool classid)
{
	struct network_helper_opts opts = {
		.must_fail = true,
	};
	struct connect4_dropper *skel;
	int fd, err = 0;

	skel = connect4_dropper__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return -1;

	skel->links.connect_v4_dropper =
		bpf_program__attach_cgroup(skel->progs.connect_v4_dropper,
					   cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.connect_v4_dropper, "prog_attach")) {
		err = -1;
		goto out;
	}

	if (classid && !ASSERT_OK(join_classid(), "join_classid")) {
		err = -1;
		goto out;
	}

	fd = connect_to_fd_opts(server_fd, &opts);
	printf("run_test fd: %d\n", fd);
	if (fd < 0)
		err = -1;
	else
		close(fd);
out:
	connect4_dropper__destroy(skel);
	printf("run_test err: %d\n", err);
	return err;
}

static void prompt(const char* step) {
	printf("%s ....\n", step);
	fgetc(stdin);
}


// Background:
// [1] https://lore.kernel.org/bpf/20210913230759.2313-1-daniel@iogearbox.net/
// [2] https://lpc.events/event/11/contributions/953/
void test_cgroup_v1v2(void)
{
	struct network_helper_opts opts = {};
	int server_fd, client_fd, cgroup_fd;
	static const int port = 60120;

	/* Step 1: Check base connectivity works without any BPF. */
	printf("====> Step 1 <====\n");
	server_fd = start_server(AF_INET, SOCK_STREAM, NULL, port, 0);
	if (!ASSERT_GE(server_fd, 0, "server_fd"))
		return;
	client_fd = connect_to_fd_opts(server_fd, &opts);
	if (!ASSERT_GE(client_fd, 0, "client_fd")) {
		close(server_fd);
		return;
	}
	close(client_fd);
	close(server_fd);

	printf("====> Step 2 <====\n");
	/* Step 2: Check BPF policy prog attached to cgroups drops connectivity. */
	cgroup_fd = test__join_cgroup("/connect_dropper");
	if (!ASSERT_GE(cgroup_fd, 0, "cgroup_fd"))
		return;
	server_fd = start_server(AF_INET, SOCK_STREAM, NULL, port, 0);
	if (!ASSERT_GE(server_fd, 0, "server_fd")) {
		close(cgroup_fd);
		return;
	}

	prompt("");

	printf("====> Step 2.1 <====\n");
	ASSERT_OK(run_test(cgroup_fd, server_fd, false), "cgroup-v2-only");

	printf("====> Step 2.2 <====\n");
	setup_classid_environment();
	set_classid(42);
	prompt("set classid env done");
	ASSERT_OK(run_test(cgroup_fd, server_fd, true), "cgroup-v1v2");

	printf("====> Step 2.3 <====\n");
	cleanup_classid_environment();
	close(server_fd);
	close(cgroup_fd);
}


/**
 *
 * After setup_classid_environment() and set_classid(42), we can see:
 *
☁  linux [bpf-selftest-v5.18.5] ⚡  lsns -t mnt
        NS TYPE NPROCS   PID USER            COMMAND
4026531841 mnt     193     1 root            /sbin/init
4026532478 mnt       1   342 root            ├─/usr/lib/systemd/systemd-udevd
4026532480 mnt       1   368 systemd-network ├─/usr/lib/systemd/systemd-networkd
4026532482 mnt       1   396 root            └─/usr/lib/systemd/systemd-logind
4026531862 mnt       1    39 root            kdevtmpfs
4026532491 mnt       2 12760 root            sleep inf
4026532555 mnt       1 54973 root            ./test_progs -t cgroup_v1v2 -v
☁  linux [bpf-selftest-v5.18.5] ⚡  nsenter -m -t 54973
☁  /  mount | grep cgroup
cgroup2 on /sys/fs/cgroup type cgroup2 (rw,nosuid,nodev,noexec,relatime)
none on /mnt type cgroup2 (rw,relatime)
tmpfs on /sys/fs/cgroup type tmpfs (rw,relatime,inode64)
net_cls on /sys/fs/cgroup/net_cls type cgroup (rw,relatime,net_cls)
☁  /  cat /sys/fs/cgroup/net_cls/cgroup-test-work-dir/net_cls.classid
42
☁  /
☁  /
☁  /
 *
 */