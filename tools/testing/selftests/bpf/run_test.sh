#!/bin/bash

# prepare
make -C ../../../../ defconfig
make -C ../../../../ headers_install && make -C ../../../../  prepare && make -C ../../../../ modules_prepare

# build test progs
make -j4

# run tests built before
#make run_tests



# we can only run specific progs or specific test case.  eg ./test_progs -l and then ./test_progs -t netns_cookie -v


# test progs listed below:
# get_cgroup_id_user   test_dev_cgroup  test_lru_map  test_progs           test_sock     test_sysctl  test_tcpnotify_user  test_verifier_log
# test_cgroup_storage  test_lpm_map     test_maps     test_progs-no_alu32  test_sockmap  test_tag     test_verifier
