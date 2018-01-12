#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import pytest
import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_hosts_file(host):
    f = host.file('/etc/hosts')

    assert f.exists
    assert f.user == 'root'
    assert f.group == 'root'

# https://www.cyberciti.biz/faq/linux-kernel-etcsysctl-conf-security-hardening/
# Limit network - transmitted configuration for IPv4
# Limit network - transmitted configuration for IPv6
# Turn on execshield protection
# Prevent against the common ‘syn flood attack’
# Turn on source IP address verification
# Prevents a cracker from using a spoofing attack against the IP address of the server.
# Logs several types of suspicious packets, such as spoofed packets, source - routed packets, and redirects.


# FIXME: Finish rest of these tests
@pytest.mark.parametrize('test_input,expected',
                         [('net.ipv4.conf.all.send_redirects','0'),
                          ('net.ipv4.conf.default.send_redirects','0'),
                          ('net.ipv4.conf.all.accept_source_route', '0')])
def test_systcl_hardening_settings(host, test_input, expected):

    cmd = 'sysctl -n {}'.format(test_input)
    out = host.command.check_output(cmd)

    assert out == expected

