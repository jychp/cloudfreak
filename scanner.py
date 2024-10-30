import argparse
import asyncio
import aiohttp

from loguru import logger
import netaddr


async def scan(
    worker_url: str, 
    session: aiohttp.ClientSession, 
    semaphore: asyncio.Semaphore,
    targets: list[dict[str: str]]):
    payload = {"targets": targets}
    async with semaphore:
        async with session.post(worker_url, json=payload) as response:
            result = await response.text()
            return result, response.status


def split_list(lst: list[any], n: int):
    k, m = divmod(len(lst), n)
    return [lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]


async def main(worker_url: str, targets: list[dict[str: str]], parallelism: int):
    # SCAN
    scan_semaphore = asyncio.Semaphore(parallelism)
    async with aiohttp.ClientSession() as session:
        tasks = [scan(args.worker, session, scan_semaphore, payload) for payload in split_list(targets, parallelism)]
        results = await asyncio.gather(*tasks)
        for result, status in results:
            print(result, status)


if __name__ == '__main__':
    # ARGS PARSING
    parser = argparse.ArgumentParser("cf-scanner")
    '''
    parser.add_argument(
        '-v',
        '--verbose',
        help="Display debug level messsages",
        action='store_true',
    )
    '''
    # TODO: -iL (include list)
    # TODO: --exlude (comma separated)
    # TODO: --excludefile
    # TODO: -F (fast scan with default ports)
    # -sV: service version detection
    # -O: OS detection
    # --host-timeout
    # TODO: add a secret key
    # add: --ssl
    # add: --data
    parser.add_argument(
        '-p',
        type=str,
        metavar='ports',
        help='ports to scan',
    )
    parser.add_argument(
        "-w",
        "--worker",
        type=str,
        required=True,
        help="URL of the Cloudflare Worker"
    )
    parser.add_argument(
        '--parallelism',
        type=int,
        default=5,
        help='Number of parallel workers',
    )
    parser.add_argument(
        '--ssl',
        action='store_true',
        help='Enable SSL connection',
    )
    parser.add_argument(
        'target',
        metavar='target',
        type=str,
        nargs='+',
        help='hostnames, IPs, CIDRs to scan',
    )
    args = parser.parse_args()

    # HOSTS
    hosts: list[str] = []
    for raw_target in args.target:
        try:
            for ip in netaddr.IPNetwork(raw_target):
                logger.debug(f"Adding {ip} to hosts")
                hosts.append(str(ip))
        except netaddr.core.AddrFormatError:
            logger.debug(f"Adding {raw_target} to hosts")
            hosts.append(raw_target)

    # PORTS
    ports: list[int] = []
    if args.p and '-' in args.p:
        start_port, end_port = args.p.split('-', 1)
        ports = list(range(int(start_port), int(end_port) + 1))
    elif args.p and ',' in args.p:
        ports = [int(port) for port in args.p.split(',')]
    elif args.p:
        ports = [int(args.p)]

    # BUILD TARGETS list
    targets: list[dict[str: str]] = []
    if len(hosts) == 0:
        logger.error("No valid targets provided")
        exit(1)
    if len(ports) == 0:
        logger.error("No valid ports provided")
        exit(1)
    for host in hosts:
        for port in ports:
            target = {
                'host': host,
                'port': port,
                'data': '',
                'ssl': args.ssl,
            }
            logger.debug(f"Adding {target} to targets")
            targets.append(target)

    concurrency = min(args.parallelism, len(targets))
    asyncio.run(main(args.worker, targets, concurrency))
