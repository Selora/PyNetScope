import PyNetScope
import argparse

def get_argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-f',
        '--scope-file',
        type=argparse.FileType('r')
    )
    parser.add_argument(
        '-s',
        '--scope',
        type=str,
        help='Scope, comma-separated. Hostname, ip list, netblocs (CIDR) and netranges.'
    )
    parser.add_argument(
        'Host-To-Validate',
        type=str,
        help='FQDN or IP'
    )

    return parser

def __main__():

    args = get_argparser().parse_args()
    
    print("Hello!")