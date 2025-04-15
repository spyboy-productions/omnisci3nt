import asyncio
import socket
from tqdm import tqdm

# Color codes
R = "\033[31m"  # red
G = "\033[32m"  # green
C = "\033[36m"  # cyan
W = "\033[0m"  # reset
Y = "\033[33m"  # yellow

port_list = range(1, 65536)
SEM_LIMIT = 500  # limit of concurrent tasks


# Get service name from port
def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"


# Single port connection task
async def sock_conn(semaphore, ip, port, open_ports, progress_bar):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=1
            )
            writer.close()
            await writer.wait_closed()
            open_ports.append(port)
        except:
            pass
        finally:
            progress_bar.update(1)


# Main async scanner
async def run(ip, threads):
    open_ports = []
    semaphore = asyncio.Semaphore(SEM_LIMIT)

    print(f"\n{Y}PORT     STATE   SERVICE{W}")
    print(f"{Y}-----    ------  --------{W}")

    with tqdm(
        total=len(port_list), desc="Scanning Ports", unit="port", leave=False
    ) as progress_bar:
        tasks = [
            sock_conn(semaphore, ip, port, open_ports, progress_bar)
            for port in port_list
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    # Print open ports in formatted style
    for port in sorted(open_ports):
        service = get_service_name(port)
        print(f"{C}{str(port).ljust(5)}/tcp  {G}open    {W}{service}")

    print(f"\n{G}[✓] Scan completed! {C}Open ports: {len(open_ports)}{W}\n")


# Entry function
def ps(ip, threads=100):
    print(f"\n{Y}[~] Starting Port Scan on {ip}...{W}")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run(ip, threads))
    except asyncio.TimeoutError:
        print(f"{R}[~] Connection timeout.{W}")
    finally:
        loop.close()
