import asyncio

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

# List of ports to scan (top 1000 ports)
port_list = [1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000]

async def sock_conn(ip, port, result, semaphore):
    """Silent connection attempt to specified ports on the target IP address."""
    async with semaphore:
        try:
            connector = asyncio.open_connection(ip, port)
            await asyncio.wait_for(connector, timeout=1)
            result['ports'].append(port)
            print(f'\x1b[K{G}[+] {C}{port}{W}')
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass

async def run(ip, threads):
    """Run the port scanner with a limited number of concurrent connections defined within the defined funcion threads."""
    result = {'ports': []}
    semaphore = asyncio.Semaphore(threads)  # Limit concurrent tasks
    tasks = [sock_conn(ip, port, result, semaphore) for port in port_list]

    await asyncio.gather(*tasks, return_exceptions=True)

    print(f'\n{Y}[~] {G}Scanning completed! Open ports: {result["ports"]}{W}\n')

def ps(ip, threads=100):
    print(f'\n{Y}[~] Starting Port Scan...{W}\n')

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run(ip, threads))
    except asyncio.TimeoutError:
        print(f'{R}[~] {C}Connection timeout.{W}\n')
    finally:
        loop.close()
