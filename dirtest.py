import socket
import aiohttp
import asyncio
from datetime import date

RED = '\033[31m'  # red
GREEN = '\033[32m'  # green
CYAN = '\033[36m'  # cyan
WHITE = '\033[0m'  # white
YELLOW = '\033[33m'  # yellow

headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0'}
count = 0
found = []
responses = []
current_year = date.today().year


async def fetch_url(session, url, allow_redirects):
    try:
        async with session.get(url, headers=headers, allow_redirects=allow_redirects) as response:
            responses.append((url, response.status))
            return response.status
    except Exception as e:
        print(f'{RED}[-] {CYAN}Exception : {WHITE}' + str(e).strip('\n'))


async def insert_url(queue, file_extensions, target, wordlist, allow_redirects):
    url_template = target + '/{}'
    if file_extensions:
        file_extensions = [ext.strip() for ext in file_extensions.split(',')]
    with open(wordlist, 'r') as wordlist_file:
        for line in wordlist_file:
            word = line.strip()
            for ext in (file_extensions or ['']):
                url = url_template.format(f'{word}.{ext}' if ext else word)
                await queue.put(url)


async def consume_url(queue, target, session, allow_redirects, total_num_words):
    global count
    while True:
        url = await queue.get()
        status = await fetch_url(session, url, allow_redirects)
        await filter_output(target, url, status)
        queue.task_done()
        count += 1
        print(f'{YELLOW}[~] {CYAN}Requests : {WHITE}{count}/{total_num_words}', end='\r')


async def run_scan(target, num_threads, timeout, wordlist, allow_redirects, ssl_verification, dns_servers, file_extensions,
                   total_num_words):
    queue = asyncio.Queue(maxsize=num_threads)

    resolver = aiohttp.AsyncResolver(nameservers=dns_servers.split(', '))
    conn = aiohttp.TCPConnector(limit=num_threads, resolver=resolver, family=socket.AF_INET,
                                verify_ssl=ssl_verification)
    timeout_config = aiohttp.ClientTimeout(total=None, sock_connect=timeout, sock_read=timeout)

    async with aiohttp.ClientSession(connector=conn, timeout=timeout_config) as session:
        distribute_urls = asyncio.create_task(insert_url(queue, file_extensions, target, wordlist, allow_redirects))
        workers = [
            asyncio.create_task(
                consume_url(queue, target, session, allow_redirects, total_num_words)
            ) for _ in range(num_threads)]

        await asyncio.gather(distribute_urls)
        await queue.join()

        for worker in workers:
            worker.cancel()


async def filter_output(target, url, status):
    global found
    if status in {200} and str(url) != target + '/':
        found.append(url)
        print(f'{GREEN}{status} {CYAN}|{WHITE} {url}')
    elif status in {301, 302, 303, 307, 308}:
        found.append(url)
        print(f'{YELLOW}{status} {CYAN}|{WHITE} {url}')
    elif status in {403}:
        found.append(url)
        print(f'{RED}{status} {CYAN}|{WHITE} {url}')


def print_directory_output(output, data):
    global responses, found
    result = {}

    for entry in responses:
        if entry is not None:
            if entry[1] in {200}:
                if output != 'None':
                    result.setdefault('Status 200', []).append(f'200, {entry[0]}')
            elif entry[1] in {301, 302, 303, 307, 308}:
                if output != 'None':
                    result.setdefault(f'Status {entry[1]}', []).append(f'{entry[1]}, {entry[0]}')
            elif entry[1] in {403}:
                if output != 'None':
                    result.setdefault('Status 403', []).append(f'{entry[1]}, {entry[0]}')

    print(f'\n\n{GREEN}[+] {CYAN}Directories Found   : {WHITE}{len(found)}')


def start_scan(target, num_threads, timeout, wordlist, allow_redirects, ssl_verification, dns_servers, output, data,
               file_extensions):
    print(f'\n{YELLOW}[~] Starting Directory Enum...{WHITE}\n')
    print(f'{GREEN}[+] {CYAN}Threads          : {WHITE}{num_threads}')
    print(f'{GREEN}[+] {CYAN}Timeout          : {WHITE}{timeout}')
    print(f'{GREEN}[+] {CYAN}Wordlist         : {WHITE}{wordlist}')
    print(f'{GREEN}[+] {CYAN}Allow Redirects  : {WHITE}{allow_redirects}')
    print(f'{GREEN}[+] {CYAN}SSL Verification : {WHITE}{ssl_verification}')
    print(f'{GREEN}[+] {CYAN}DNS Servers      : {WHITE}{dns_servers}')

    with open(wordlist, 'r') as wordlist_file:
        num_words = sum(1 for _ in wordlist_file)

    print(f'{GREEN}[+] {CYAN}Wordlist Size    : {WHITE}{num_words}')
    print(f'{GREEN}[+] {CYAN}File Extensions  : {WHITE}{file_extensions}\n')

    if file_extensions:
        total_num_words = num_words * (len(file_extensions.split(',')) + 1)
    else:
        total_num_words = num_words

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(
        run_scan(target, num_threads, timeout, wordlist, allow_redirects, ssl_verification, dns_servers,
                 file_extensions, total_num_words))
    print_directory_output(output, data)
    loop.close()

'''
if __name__ == "__main__":
    target_url = "https://spyboy.in"  # Set your target URL here
    num_threads = 10  # Set the number of threads here
    timeout_duration = 10  # Set the timeout duration here
    wordlist_file = "dirlist.txt"  # Set the wordlist file path here
    allow_redirects_flag = False
    ssl_verification_flag = True
    dns_servers_list = "1.1.1.1"  # Comma-separated DNS servers
    file_extensions_list = "txt,php,html"  # Comma-separated list of file extensions
    start_scan(target_url, num_threads, timeout_duration, wordlist_file, allow_redirects_flag, ssl_verification_flag,
               dns_servers_list, None, None, file_extensions_list)
'''
