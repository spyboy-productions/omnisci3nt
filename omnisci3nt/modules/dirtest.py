import socket
import aiohttp
import asyncio
from datetime import date
import sys
from tqdm import tqdm

RED = "\033[31m"
GREEN = "\033[32m"
CYAN = "\033[36m"
WHITE = "\033[0m"
YELLOW = "\033[33m"

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"
}
found = []
responses = []
current_year = date.today().year

# Fix for Windows aiodns issue
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


async def fetch_url(session, url, allow_redirects, progress):
    try:
        async with session.get(
            url, headers=headers, allow_redirects=allow_redirects
        ) as response:
            responses.append((url, response.status))
            await filter_output(url, response.status)
            progress.update(1)  # Update progress bar
            return response.status
    except Exception as e:
        tqdm.write(f"{RED}[-] {CYAN}Exception : {WHITE}" + str(e).strip("\n"))


async def insert_url(queue, file_extensions, target, wordlist, allow_redirects):
    url_template = target + "/{}"
    if file_extensions:
        file_extensions = [ext.strip() for ext in file_extensions.split(",")]
    with open(wordlist, "r") as wordlist_file:
        for line in wordlist_file:
            word = line.strip()
            for ext in file_extensions or [""]:
                url = url_template.format(f"{word}.{ext}" if ext else word)
                await queue.put(url)


async def consume_url(queue, session, allow_redirects, progress):
    while True:
        url = await queue.get()
        await fetch_url(session, url, allow_redirects, progress)
        queue.task_done()


async def run_scan(
    target,
    num_threads,
    timeout,
    wordlist,
    allow_redirects,
    ssl_verification,
    dns_servers,
    file_extensions,
    total_num_words,
):
    queue = asyncio.Queue(maxsize=num_threads)

    resolver = aiohttp.AsyncResolver(nameservers=dns_servers.split(", "))
    conn = aiohttp.TCPConnector(
        limit=num_threads,
        resolver=resolver,
        family=socket.AF_INET,
        verify_ssl=ssl_verification,
    )
    timeout_config = aiohttp.ClientTimeout(
        total=None, sock_connect=timeout, sock_read=timeout
    )

    async with aiohttp.ClientSession(connector=conn, timeout=timeout_config) as session:
        with tqdm(total=total_num_words, desc="Scanning", unit="req") as progress:
            insert_task = asyncio.create_task(
                insert_url(queue, file_extensions, target, wordlist, allow_redirects)
            )
            workers = [
                asyncio.create_task(
                    consume_url(queue, session, allow_redirects, progress)
                )
                for _ in range(num_threads)
            ]

            await insert_task
            await queue.join()

            for worker in workers:
                worker.cancel()


async def filter_output(url, status):
    """Store found URLs separately and use tqdm.write() for clean printing."""
    if status in {200}:
        found.append(url)
        tqdm.write(f"{GREEN}{status} {CYAN}|{WHITE} {url}")
    elif status in {301, 302, 303, 307, 308}:
        found.append(url)
        tqdm.write(f"{YELLOW}{status} {CYAN}|{WHITE} {url}")
    elif status in {403}:
        found.append(url)
        tqdm.write(f"{RED}{status} {CYAN}|{WHITE} {url}")


def print_found_urls():
    """Print all found URLs at the end, separately."""
    if found:
        print(f"\n{GREEN}[+] {CYAN}Found URLs:{WHITE}")
        for url in found:
            print(f"{WHITE} - {url}")
    else:
        print(f"\n{RED}[-] No URLs found.{WHITE}")


def start_scan(
    target,
    num_threads,
    timeout,
    wordlist,
    allow_redirects,
    ssl_verification,
    dns_servers,
    output,
    data,
    file_extensions,
):
    print(f"\n{YELLOW}[~] Starting Directory Enumeration...{WHITE}\n")
    print(f"{GREEN}[+] {CYAN}Threads          : {WHITE}{num_threads}")
    print(f"{GREEN}[+] {CYAN}Timeout          : {WHITE}{timeout}")
    print(f"{GREEN}[+] {CYAN}Wordlist         : {WHITE}{wordlist}")
    print(f"{GREEN}[+] {CYAN}Allow Redirects  : {WHITE}{allow_redirects}")
    print(f"{GREEN}[+] {CYAN}SSL Verification : {WHITE}{ssl_verification}")
    print(f"{GREEN}[+] {CYAN}DNS Servers      : {WHITE}{dns_servers}")

    with open(wordlist, "r") as wordlist_file:
        num_words = sum(1 for _ in wordlist_file)

    print(f"{GREEN}[+] {CYAN}Wordlist Size    : {WHITE}{num_words}")
    print(f"{GREEN}[+] {CYAN}File Extensions  : {WHITE}{file_extensions}\n")

    if file_extensions:
        total_num_words = num_words * (len(file_extensions.split(",")) + 1)
    else:
        total_num_words = num_words

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(
        run_scan(
            target,
            num_threads,
            timeout,
            wordlist,
            allow_redirects,
            ssl_verification,
            dns_servers,
            file_extensions,
            total_num_words,
        )
    )
    print_found_urls()
    loop.close()
