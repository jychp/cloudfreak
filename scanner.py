import argparse
import asyncio
import json
import os
import xml.etree.ElementTree as ET
import requests
import re

import aiohttp
import netaddr
from loguru import logger

INCLUDED_FILES = {
    'ssh-banners': ['https://raw.githubusercontent.com/rapid7/recog/master/xml/ssh_banners.xml'],
    'http-servers': ['https://raw.githubusercontent.com/rapid7/recog/master/xml/http_servers.xml'],
    'ftp-banners': ['https://raw.githubusercontent.com/rapid7/recog/master/xml/ftp_banners.xml'],
}

DATA_DIR = './data'


class Rapid7Recog:
    def __init__(self):
        self._regex: dict = {}

        self._load()

    def _filter_match(self, data: str, re_filter: dict):
        params = {}
        test = re_filter['regex'].match(data)
        if test:
            if len(re_filter['positional']) > 0:
                for param in re_filter['positional']:
                    params[param['name']] = test.groups()[int(param['pos']) - 1]
            for r in re_filter['params']:
                params[r['name']] = r['value']
            return params
        return None

    def check(self, data: str):
        # Check for SSH banners
        if data.startswith('SSH-'):
            logger.debug('Detected SSH banner')
            stripped_banner = data.strip()
            _ ,__ ,stripped_banner = stripped_banner.split('-', 2)
            print(stripped_banner)
            for regex in self._regex['ssh-banners']:
                result = self._filter_match(stripped_banner, regex)
                if result:
                    return result
            return {'service.product': 'generic-ssh'}
        # Check for HTTP responses
        if data.startswith('HTTP/'):
            logger.debug('Detected HTTP response')
            # Try server header
            test = re.findall(r'^Server:\S?(.*)$', data, flags=re.MULTILINE)
            if len(test) > 0:
                stripped_server = test[0].strip()
                for regex in self._regex['http-servers']:
                    result = self._filter_match(stripped_server, regex)
                    if result:
                        return result
        # Check for FTP banners
        if data.startswith('220 '):
            logger.debug('Detected FTP banner')
            stripped_banner = data[4:].strip()
            for regex in self._regex['ftp-banners']:
                result = self._filter_match(stripped_banner, regex)
                if result:
                    return result

    def _load(self):
        for category, files in INCLUDED_FILES.items():
            self._regex[category] = []
            for file in files:
                if file.startswith('https://'):
                    short_name = file.split('/')[-1]
                    if not os.path.isfile(os.path.join(DATA_DIR, short_name)):
                        self._download(short_name, file, os.path.join(DATA_DIR, short_name))
                    self._regex[category] = self._parse(os.path.join(DATA_DIR, short_name))
                logger.info(f"Loaded {len(self._regex[category])} regexes for {category}")

    def _download(self, short_name, url, path):
        logger.info(f"Downloading banner data: {url} to {path}")
        req = requests.get(url, timeout=10)
        with open(path, 'wb') as f:
            f.write(req.content)

    def _parse(self, path) -> list[dict]:
        tree = ET.parse(path)
        root = tree.getroot()
        results = []
        for pattern in root:
            pattern_value = pattern.attrib['pattern']
            if '(?i)' in pattern_value:
                pattern_value = pattern_value.replace('(?i)', '')
                pattern_regex = re.compile(pattern_value, flags=re.IGNORECASE)
            else:
                pattern_regex = re.compile(pattern_value)
            result = {
                'regex': pattern_regex,
                'params': [],
                'positional': []
            }
            for child in pattern:
                if child.tag != 'param':
                    continue
                if child.attrib['pos'] == '0':
                    result['params'].append(child.attrib)
                else:
                    result['positional'].append(child.attrib)
            results.append(result)
        return results


async def scan(
        worker_url: str,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        targets: list[dict[str, str]],
):
    payload = {"targets": targets}
    async with semaphore:
        async with session.post(worker_url, json=payload) as response:
            result = await response.text()
            logger.debug(f"Response: {result}")
            return result, response.status


def split_list(lst: list, n: int):
    k, m = divmod(len(lst), n)
    return [lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]


async def main(
    worker_url: str,
    targets: list[dict[str, str]],
    parallelism: int,
):
    r7recog = Rapid7Recog()

    open_ports_per_host: dict[str, dict[int, str]] = {}

    # Do scans
    scan_semaphore = asyncio.Semaphore(parallelism)
    async with aiohttp.ClientSession() as session:
        tasks = [scan(args.worker, session, scan_semaphore, payload) for payload in split_list(targets, parallelism)]
        results = await asyncio.gather(*tasks)
        for raw_result, status in results:
            json_result = json.loads(raw_result)
            for line in json_result['scan_results']:
                if not line['open']:
                    continue
                params = r7recog.check(line['data'])
                try:
                    open_ports_per_host[line['host']][int(line['port'])] = {'data': line['data'], 'params': params}
                except KeyError:
                    open_ports_per_host[line['host']] = {int(line['port']): {'data': line['data'], 'params': params}}

    # Display results
    for host, ports in open_ports_per_host.items():
        logger.info(f"Host: {host}")
        for port, data in ports.items():
            logger.info(f"  Port: {port}")
            logger.info(f"  Params: {data['params']}")


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
    # --host-timeout
    # TODO: add a secret key

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
        help="URL of the Cloudflare Worker",
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
        '--data',
        type=str,
        help='Data to send to the server',
        default='GET / HTTP/1.1\r\n\r\n',
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
    targets: list[dict[str, str]] = []
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
                'data': args.data,
                'ssl': args.ssl,
            }
            logger.debug(f"Adding {target} to targets")
            targets.append(target)

    concurrency = min(args.parallelism, len(targets))
    asyncio.run(main(args.worker, targets, concurrency))