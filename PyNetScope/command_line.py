import PyNetScope.PyNetScope as PyNetScope
import argparse
import sys

def get_argparser():
    parser = argparse.ArgumentParser()
    scope_input_group = parser.add_mutually_exclusive_group()
    scope_input_group.add_argument(
        '-f',
        '--scope-file',
        type=argparse.FileType('r')
    )
    scope_input_group.add_argument(
        '-s',
        '--scope',
        type=str,
        help='Scope, comma-separated. Hostname, ip list, netblocs (CIDR) and netranges.'
    )
    parser.add_argument(
        'ipv4',
        type=str,
        help='IPv4'
    )

    return parser

def main():
    args = get_argparser().parse_args()
    if args.scope:
        scope = PyNetScope.Scope.read_scope_from_args(args.scope)
    else:
        scope = PyNetScope.Scope.read_scope_from_file(args.scope_file)

    if scope.is_ip_in_scope(args.ipv4):
        print("{} in scope".format(args.ipv4))
    else:
        print("{} not in scope".format(args.ipv4))
