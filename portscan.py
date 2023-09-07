import asyncio

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'  # white
Y = '\033[33m'  # yellow

# List of ports to scan (top 1000 ports)
port_list = list(range(1, 1001))

async def sock_conn(ip, port, result):
    try:
        connector = asyncio.open_connection(ip, port)
        await asyncio.wait_for(connector, timeout=1)
        result['ports'].append(port)
        print(f'\x1b[K{G}╰➤ {C}{port}{W}')
    except (TimeoutError, ConnectionRefusedError):
        pass

async def run(ip, threads):
    result = {'ports': []}
    tasks = [sock_conn(ip, port, result) for port in port_list]

    await asyncio.gather(*tasks, return_exceptions=True)  # Added return_exceptions=True

    print(f'\n{Y}[~] {G}Scanning completed! Open ports: {result["ports"]}{W}\n')

def ps(ip, threads=100):
    print(f'\n{Y}[~] Starting Port Scan...{W}\n')
    #print(f'{G}[+] {C}Scanning Top 1000 Ports With {threads} Threads...{W}\n')

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run(ip, threads))
    except asyncio.TimeoutError:
        print(f'{R}[~] {C}Connection timeout.{W}\n')
    finally:
        loop.close()

#ps(ip='x.com')
