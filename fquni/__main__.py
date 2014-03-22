import argparse
import logging
import logging.handlers
import sys

import gevent
import gevent.monkey

from . import server
from . import nfqueue_client
from . import pystun


LOGGER = logging.getLogger(__name__)


def main():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument('--log-file')
    argument_parser.add_argument('--log-level', choices=['INFO', 'DEBUG'], default='INFO')
    sub_parsers = argument_parser.add_subparsers()
    server_parser = sub_parsers.add_parser('server-up', help='start as server')
    server_parser.set_defaults(handler=server.main)
    stun_parser = sub_parsers.add_parser('stun', help='debug stun protocol')
    stun_parser.set_defaults(handler=pystun.main)
    nfqueue_client_parser = sub_parsers.add_parser('nfqueue-client-up', help='start as client')
    nfqueue_client_parser.set_defaults(handler=nfqueue_client.main)
    args = argument_parser.parse_args()
    log_level = getattr(logging, args.log_level)
    logging.basicConfig(stream=sys.stdout, level=log_level, format='%(asctime)s %(levelname)s %(message)s')
    if args.log_file:
        handler = logging.handlers.RotatingFileHandler(
            args.log_file, maxBytes=1024 * 256, backupCount=0)
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        handler.setLevel(log_level)
        logging.getLogger('fqdns').addHandler(handler)
    args.handler(**{k: getattr(args, k) for k in vars(args) \
                    if k not in {'handler', 'log_file', 'log_level'}})


main()