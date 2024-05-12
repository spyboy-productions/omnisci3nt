import requests

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def fetch_headers(url):
    result = {}
    try:
        response = requests.get(url, verify=True, timeout=10)  # Enable certificate verification
        headers = response.headers
        print(f'\n{Y}[~] Headers :{W}\n')
        for key, value in headers.items():
            result[key] = value
            print(f'{G}[+] {C}{key}:{W} {value}')
    except requests.exceptions.RequestException as e:
        print(f'\n{R}[-] {C}Exception :{W} {e}\n')
        result['Exception'] = str(e)
    result['exported'] = bool(result)
    return result

if __name__ == "__main__":
    target_url = input("Enter the URL to fetch headers from: ")
    headers_data = fetch_headers(target_url)
    print(headers_data)
