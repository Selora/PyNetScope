from PyNetScope import Scope

from unittest import TestCase
import netaddr


class TestScope(TestCase):
    def test_get_expanded_ip_list(self):
        self.fail()

    def test_read_scope_from_args(self):
        self.fail()

    def test_read_scope_from_file(self):
        scope = Scope.read_scope_from_file("tests/test_scope.txt")

        ip_list = scope.get_expanded_ip_list()
        ip_golden_list = [str(ip) for ip in netaddr.IPNetwork('10.0.0.0/24')]
        ip_golden_list += [str(ip) for ip in netaddr.IPNetwork('192.168.1.0/25')] + ['192.168.1.128']
        ip_golden_list += ['1.1.1.1']

        ip_list.sort(reverse=True)
        ip_golden_list.sort(reverse=True)
        self.assertEqual(len(ip_list), len(ip_golden_list), msg="Problem importing netblocks or IP addresses")
        self.assertEqual(ip_list, ip_golden_list, msg="Problem importing netblocks or IP addresses")

    def test__parse_scope_entry(self):
        hostname_list = []
        ip_list = []
        netblock_list = []
        netrange_list = []
        unknown_list = []

        golden_fqdn = [
            ' this.is.a901923.fqdn',
            ' a901923.09123fqdn       '
        ]
        golden_ip = [
            ' 0.1.2.3 ',
            ' 99.255.255.255 '
        ]

        golden_netblocks = [
            ' 10.1.0.1/16 ',
            '12.11.2/30 '
        ]

        golden_netranges = [
            '192.168.5.1-5',
            '2.8.5.1-5'
        ]

        # Some wierd or funky hostnames, etc
        golden_unknowns = [
            'asdf.123-123.mm:23',
            'http://test.com'
        ]

        scope_entry_list = golden_fqdn + golden_ip  + golden_netblocks + golden_netranges + golden_unknowns

        for entry in scope_entry_list:
            Scope._parse_scope_entry(entry, hostname_list, ip_list, netblock_list, netrange_list, unknown_list)

        self.assertEqual(set(hostname_list), set([x.strip() for x in golden_fqdn]), "Problem with FQDN parsing!")
        self.assertEqual(len(hostname_list), len([x.strip() for x in golden_fqdn]), "Problem with FQDN parsing!")

        self.assertEqual(set(ip_list), set([x.strip() for x in golden_ip]), "Problem with IP parsing!")
        self.assertEqual(len(ip_list), len([x.strip() for x in golden_ip]), "Problem with IP parsing!")

        self.assertEqual(set(netblock_list), set([x.strip() for x in golden_netblocks]), "Problem with netblocks parsing!")
        self.assertEqual(len(netblock_list), len([x.strip() for x in golden_netblocks]), "Problem with netblocks parsing!")

        self.assertEqual(set(netrange_list), set([x.strip() for x in golden_netranges]), "Problem with netranges parsing!")
        self.assertEqual(len(netrange_list), len([x.strip() for x in golden_netranges]), "Problem with netranges parsing!")

        self.assertEqual(set(unknown_list), set([x.strip() for x in golden_unknowns]), "Problem with netranges parsing!")
        self.assertEqual(len(unknown_list), len([x.strip() for x in golden_unknowns]), "Problem with netranges parsing!")



    def test_is_ip(self):
        self.fail()

    def test_is_hostname(self):
        self.fail()

    def test_is_netblock(self):
        self.fail()

    def test_is_netrange(self):
        self.fail()

    def test_expend_netblock(self):
        self.fail()

    def test_expend_netrange(self):
        self.fail()
