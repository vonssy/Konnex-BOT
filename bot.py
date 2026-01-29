from aiohttp import (
    ClientResponseError,
    ClientSession,
    ClientTimeout,
    BasicAuth,
    CookieJar
)
from aiohttp_socks import ProxyConnector
from yarl import URL
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import to_hex
from datetime import datetime, timezone
from colorama import *
import asyncio, random, json, re, os, pytz

wib = pytz.timezone('Asia/Jakarta')

class Konnex:
    def __init__(self) -> None:
        self.API_URL = {
            "hub": "https://hub.konnex.world",
            "testnet": "https://konnex-ai.xyz"
        }
        self.WEB_ID = "7857ae2c-2ebf-4871-a775-349bcdc416ce"
        self.ORG_ID = "dbe51e03-92cc-4a5a-8d57-61c10753246b"
        self.RULES_ID = "0b0dacb4-9b51-4b3d-b42e-700959c47bf9"
        self.REF_CODE = "VONSSY" # U can change it with yours.
        self.HEADERS = {}
        self.proxies = []
        self.proxy_index = 0
        self.account_proxies = {}
        self.sessions = {}
        self.ua_index = 0
        
        self.USER_AGENTS = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/117.0.0.0"
        ]

    def clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def log(self, message):
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().astimezone(wib).strftime('%x %X %Z')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}{message}",
            flush=True
        )

    def welcome(self):
        print(
            f"""
        {Fore.GREEN + Style.BRIGHT}Konnex {Fore.BLUE + Style.BRIGHT}Auto BOT
            """
            f"""
        {Fore.GREEN + Style.BRIGHT}Rey? {Fore.YELLOW + Style.BRIGHT}<INI WATERMARK>
            """
        )

    def format_seconds(self, seconds):
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
    
    def load_accounts(self):
        filename = "accounts.txt"
        try:
            with open(filename, 'r') as file:
                accounts = [line.strip() for line in file if line.strip()]
            return accounts
        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}Failed To Load Accounts: {e}{Style.RESET_ALL}")
            return None

    def load_proxies(self):
        filename = "proxy.txt"
        try:
            if not os.path.exists(filename):
                self.log(f"{Fore.RED + Style.BRIGHT}File {filename} Not Found.{Style.RESET_ALL}")
                return
            with open(filename, 'r') as f:
                self.proxies = [line.strip() for line in f.read().splitlines() if line.strip()]
            
            if not self.proxies:
                self.log(f"{Fore.RED + Style.BRIGHT}No Proxies Found.{Style.RESET_ALL}")
                return

            self.log(
                f"{Fore.GREEN + Style.BRIGHT}Proxies Total  : {Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT}{len(self.proxies)}{Style.RESET_ALL}"
            )
        
        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}Failed To Load Proxies: {e}{Style.RESET_ALL}")
            self.proxies = []

    def check_proxy_schemes(self, proxies):
        schemes = ["http://", "https://", "socks4://", "socks5://"]
        if any(proxies.startswith(scheme) for scheme in schemes):
            return proxies
        return f"http://{proxies}"
    
    def get_next_proxy_for_account(self, account):
        if account not in self.account_proxies:
            if not self.proxies:
                return None
            proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
            self.account_proxies[account] = proxy
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return self.account_proxies[account]

    def rotate_proxy_for_account(self, account):
        if not self.proxies:
            return None
        proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
        self.account_proxies[account] = proxy
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return proxy
    
    def build_proxy_config(self, proxy=None):
        if not proxy:
            return None, None, None

        if proxy.startswith("socks"):
            connector = ProxyConnector.from_url(proxy)
            return connector, None, None

        elif proxy.startswith("http"):
            match = re.match(r"http://(.*?):(.*?)@(.*)", proxy)
            if match:
                username, password, host_port = match.groups()
                clean_url = f"http://{host_port}"
                auth = BasicAuth(username, password)
                return None, clean_url, auth
            else:
                return None, proxy, None

        raise Exception("Unsupported Proxy Type.")
    
    def display_proxy(self, proxy_url=None):
        if not proxy_url: return "No Proxy"

        proxy_url = re.sub(r"^(http|https|socks4|socks5)://", "", proxy_url)

        if "@" in proxy_url:
            proxy_url = proxy_url.split("@", 1)[1]

        return proxy_url
    
    def get_next_user_agent(self):
        ua = self.USER_AGENTS[self.ua_index]
        self.ua_index = (self.ua_index + 1) % len(self.USER_AGENTS)
        return ua
    
    def initialize_headers(self, email: str, header_type: str):
        if email not in self.HEADERS:
            self.HEADERS[email] = {}

        if "ua" not in self.HEADERS[email]:
            self.HEADERS[email]["ua"] = self.get_next_user_agent()

        ua = self.HEADERS[email]["ua"]

        if header_type not in self.HEADERS[email]:

            base_headers = {
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "User-Agent": ua
            }

            if header_type == "hub":
                headers = {
                    **base_headers,
                    "Accept": "*/*",
                    "Origin": "https://hub.konnex.world",
                    "Referer": "https://hub.konnex.world/points",
                    "Sec-Fetch-Site": "same-origin",
                }

            elif header_type == "testnet":
                headers = {
                    **base_headers,
                    "Accept": "application/json, text/plain, */*",
                    "Origin": "https://testnet.konnex.world",
                    "Referer": "https://testnet.konnex.world/",
                    "Sec-Fetch-Site": "cross-site",
                }

            self.HEADERS[email][header_type] = headers

        return self.HEADERS[email][header_type].copy()
    
    def get_session(self, address: str, proxy_url=None, timeout=60):
        if address not in self.sessions:
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            
            cookie_jar = CookieJar(unsafe=True)
            
            cookie_jar.update_cookies(
                {'referral_code': self.REF_CODE}, 
                URL(self.API_URL['hub'])
            )
            
            session = ClientSession(
                connector=connector,
                timeout=ClientTimeout(total=timeout),
                cookie_jar=cookie_jar,
            )
            
            self.sessions[address] = {
                'session': session,
                'proxy': proxy,
                'proxy_auth': proxy_auth
            }
        
        return self.sessions[address]
    
    def generate_address(self, account: str):
        try:
            account = Account.from_key(account)
            address = account.address
            return address
        except Exception as e:
            return None
        
    def generate_payload(self, account: str, address: str, csrf_token: str):
        try:
            issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            raw_message = json.dumps({
                "domain": "hub.konnex.world",
                "address": address,
                "statement": "Sign in to the app. Powered by Snag Solutions.",
                "uri": "https://hub.konnex.world",
                "version": "1",
                "chainId": 1,
                "nonce": csrf_token,
                "issuedAt": issued_at
            }, separators=(',', ':'))

            message = (
                "hub.konnex.world wants you to sign in with your Ethereum account:\n"
                f"{address}\n\n"
                "Sign in to the app. Powered by Snag Solutions.\n\n"
                "URI: https://hub.konnex.world\n"
                "Version: 1\n"
                "Chain ID: 1\n"
                f"Nonce: {csrf_token}\n"
                f"Issued At: {issued_at}"
            )

            encoded_message = encode_defunct(text=message)
            signed_message = Account.sign_message(encoded_message, private_key=account)
            signature = to_hex(signed_message.signature)

            payload = {
                "message": raw_message,
                "accessToken": signature,
                "signature": signature,
                "walletConnectorName": "MetaMask",
                "walletAddress": address,
                "redirect": "false",
                "callbackUrl": "/protected",
                "chainType": "evm",
                "walletProvider": "undefined",
                "csrfToken": csrf_token,
                "json": "true"
            }

            return payload
        except Exception as e:
            raise Exception(f"Generate Req Payload Failed: {str(e)}")

    def mask_account(self, account):
        try:
            mask_account = account[:6] + '*' * 6 + account[-6:]
            return mask_account
        except Exception as e:
            return None

    def print_question(self):
        while True:
            try:
                print(f"{Fore.WHITE + Style.BRIGHT}1. Run With Proxy{Style.RESET_ALL}")
                print(f"{Fore.WHITE + Style.BRIGHT}2. Run Without Proxy{Style.RESET_ALL}")
                proxy_choice = int(input(f"{Fore.BLUE + Style.BRIGHT}Choose [1/2] -> {Style.RESET_ALL}").strip())

                if proxy_choice in [1, 2]:
                    proxy_type = (
                        "With" if proxy_choice == 1 else 
                        "Without"
                    )
                    print(f"{Fore.GREEN + Style.BRIGHT}Run {proxy_type} Proxy Selected.{Style.RESET_ALL}")
                    self.USE_PROXY = True if proxy_choice == 1 else False
                    break
                else:
                    print(f"{Fore.RED + Style.BRIGHT}Please enter either 1  or 2.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED + Style.BRIGHT}Invalid input. Enter a number (1  or 2).{Style.RESET_ALL}")

        if self.USE_PROXY:
            while True:
                rotate_proxy = input(f"{Fore.BLUE + Style.BRIGHT}Rotate Invalid Proxy? [y/n] -> {Style.RESET_ALL}").strip()
                if rotate_proxy in ["y", "n"]:
                    self.ROTATE_PROXY = True if rotate_proxy == "y" else False
                    break
                else:
                    print(f"{Fore.RED + Style.BRIGHT}Invalid input. Enter 'y' or 'n'.{Style.RESET_ALL}")
    
    async def ensure_ok(self, response):
        if response.status >= 400:
            error_text = await response.text()
            raise Exception(f"HTTP {response.status}: {error_text}")
    
    async def check_connection(self, address: str, proxy_url=None):
        url = "https://api.ipify.org?format=json"

        try:
            session_info = self.get_session(address, proxy_url, 15)
            session = session_info['session']
            proxy = session_info['proxy']
            proxy_auth = session_info['proxy_auth']
            
            async with session.get(
                url=url, proxy=proxy, proxy_auth=proxy_auth
            ) as response:
                await self.ensure_ok(response)
                return True
        except (Exception, ClientResponseError) as e:
            self.log(
                f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                f"{Fore.RED+Style.BRIGHT} Connection Not 200 OK {Style.RESET_ALL}"
                f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
            )
        
        return None
    
    async def auth_csrf(self, address: str, proxy_url=None, retries=5):
        url = f"{self.API_URL['hub']}/api/auth/csrf"
        headers = self.initialize_headers(address, "hub")
        headers["Content-Type"] = "application/json"
        
        for attempt in range(retries):
            try:
                session_info = self.get_session(address, proxy_url)
                session = session_info['session']
                proxy = session_info['proxy']
                proxy_auth = session_info['proxy_auth']
                
                async with session.get(
                    url=url, headers=headers, proxy=proxy, proxy_auth=proxy_auth
                ) as response:
                    await self.ensure_ok(response)
                    result = await response.json()
                    return result
                    
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Fetch Nonce Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def auth_credentials(self, account: str, address: str, csrf_token: str, proxy_url=None, retries=5):
        url = f"{self.API_URL['hub']}/api/auth/callback/credentials"
        headers = self.initialize_headers(address, "hub")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        payload = self.generate_payload(account, address, csrf_token)
        
        for attempt in range(retries):
            try:
                session_info = self.get_session(address, proxy_url)
                session = session_info['session']
                proxy = session_info['proxy']
                proxy_auth = session_info['proxy_auth']
                
                async with session.post(
                    url=url, headers=headers, data=payload, proxy=proxy, proxy_auth=proxy_auth, allow_redirects=False
                ) as response:
                    cookies = session.cookie_jar.filter_cookies(URL(url))
                    if any('session-token' in str(cookie.key) for cookie in cookies.values()):
                        return True
                        
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Login Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None

    async def loyality_account(self, address: str, proxy_url=None, retries=5):
        url = f"{self.API_URL['hub']}/api/loyalty/accounts"
        headers = self.initialize_headers(address, "hub")
        params = {
            "websiteId": self.WEB_ID, 
            "organizationId": self.ORG_ID, 
            "walletAddress": address
        }
        
        for attempt in range(retries):
            try:
                session_info = self.get_session(address, proxy_url)
                session = session_info['session']
                proxy = session_info['proxy']
                proxy_auth = session_info['proxy_auth']
                
                async with session.get(
                    url=url, headers=headers, params=params, proxy=proxy, proxy_auth=proxy_auth
                ) as response:
                    await self.ensure_ok(response)
                    return await response.json()
                    
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Balance :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Fetch Points Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def complete_checkin(self, address: str, proxy_url=None, retries=5):
        url = f"{self.API_URL['hub']}/api/loyalty/rules/{self.RULES_ID}/complete"
        headers = self.initialize_headers(address, "hub")
        headers["Content-Type"] = "application/json"
        
        for attempt in range(retries):
            try:
                session_info = self.get_session(address, proxy_url)
                session = session_info['session']
                proxy = session_info['proxy']
                proxy_auth = session_info['proxy_auth']
                
                async with session.post(
                    url=url, headers=headers, json={}, proxy=proxy, proxy_auth=proxy_auth
                ) as response:
                    result = await response.json()

                    if response.status == 400:
                        err_msg = result.get("message")
                        self.log(
                            f"{Fore.CYAN+Style.BRIGHT}Check-In:{Style.RESET_ALL}"
                            f"{Fore.YELLOW+Style.BRIGHT} {err_msg} {Style.RESET_ALL}"
                        )
                        return None
                    
                    await self.ensure_ok(response)
                    return result
                    
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Check-In:{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def list_tasks(self, address: str, proxy_url=None, retries=5):
        url = f"{self.API_URL['testnet']}/api/v1/list_tasks"
        headers = self.initialize_headers(address, "testnet")
        
        for attempt in range(retries):
            try:
                session_info = self.get_session(address, proxy_url)
                session = session_info['session']
                proxy = session_info['proxy']
                proxy_auth = session_info['proxy_auth']
                
                async with session.get(
                    url=url, headers=headers, proxy=proxy, proxy_auth=proxy_auth
                ) as response:
                    await self.ensure_ok(response)
                    return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}   Task    :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Fetch Available Tasks {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def send_request(self, address: str, task_name: str, proxy_url=None, retries=5):
        url = f"{self.API_URL['testnet']}/api/v1/send_request"
        headers = self.initialize_headers(address, "testnet")
        headers["Content-Type"] = "application/json"
        payload = {
            "task": task_name
        }
        
        for attempt in range(retries):
            try:
                session_info = self.get_session(address, proxy_url)
                session = session_info['session']
                proxy = session_info['proxy']
                proxy_auth = session_info['proxy_auth']
                
                async with session.post(
                    url=url, headers=headers, json=payload, proxy=proxy, proxy_auth=proxy_auth
                ) as response:
                    await self.ensure_ok(response)
                    return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}   Submit  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Send Request {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def request_status(self, address: str, request_id: str, proxy_url=None, retries=5):
        url = f"{self.API_URL['testnet']}/api/v1/request_status"
        headers = self.initialize_headers(address, "testnet")
        params = {
            "id": request_id
        }
        
        for attempt in range(retries):
            try:
                session_info = self.get_session(address, proxy_url)
                session = session_info['session']
                proxy = session_info['proxy']
                proxy_auth = session_info['proxy_auth']
                
                async with session.get(
                    url=url, headers=headers, params=params, proxy=proxy, proxy_auth=proxy_auth
                ) as response:
                    await self.ensure_ok(response)
                    return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}   Status  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Fetch Request Status {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def request_feedback(self, address: str, request_id: str, proxy_url=None, retries=5):
        url = f"{self.API_URL['testnet']}/api/v1/request_feedback"
        headers = self.initialize_headers(address, "testnet")
        headers["Content-Type"] = "application/json"
        params = {
            "request_id": request_id
        }
        payload = {
            "score": 8,
            "wallet": address
        }
        
        for attempt in range(retries):
            try:
                session_info = self.get_session(address, proxy_url)
                session = session_info['session']
                proxy = session_info['proxy']
                proxy_auth = session_info['proxy_auth']
                
                async with session.post(
                    url=url, headers=headers, params=params, json=payload, proxy=proxy, proxy_auth=proxy_auth
                ) as response:
                    await self.ensure_ok(response)
                    return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}   Feedback:{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Save Feedback {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def process_check_connection(self, address: str, proxy_url: None):
        while True:
            self.log(
                f"{Fore.CYAN+Style.BRIGHT}Proxy   :{Style.RESET_ALL}"
                f"{Fore.WHITE+Style.BRIGHT} {self.display_proxy(proxy_url)} {Style.RESET_ALL}"
            )

            is_valid = await self.check_connection(address, proxy_url)
            if is_valid: return True

            if self.ROTATE_PROXY:
                self.rotate_proxy_for_account(address)
                await asyncio.sleep(1)
                continue

            return False
    
    async def process_user_login(self, account: str, address: str, proxy_url=None):
        is_valid = await self.process_check_connection(address, proxy_url)
        if not is_valid: return False

        auth_csrf = await self.auth_csrf(address, proxy_url)
        if not auth_csrf: return False

        csrf_token = auth_csrf.get("csrfToken")

        credentials = await self.auth_credentials(account, address, csrf_token, proxy_url)
        if not credentials: return False

        self.log(
            f"{Fore.CYAN + Style.BRIGHT}Status  :{Style.RESET_ALL}"
            f"{Fore.GREEN + Style.BRIGHT} Login Success {Style.RESET_ALL}"
        )

        return True

    async def process_accounts(self, account: str, address: str, proxy_url=None):
        if self.USE_PROXY:
            proxy_url = self.get_next_proxy_for_account(address)

        logined = await self.process_user_login(account, address, proxy_url)
        if not logined: return False

        loyality = await self.loyality_account(address, proxy_url)
        if loyality:
            loyality_data = loyality.get("data", [])

            if loyality_data:
                amount = loyality_data[0].get("amount", 0)
            else:
                amount = 0

            self.log(
                f"{Fore.CYAN+Style.BRIGHT}Balance :{Style.RESET_ALL}"
                f"{Fore.WHITE+Style.BRIGHT} {amount} Points {Style.RESET_ALL}"
            )

        checkin = await self.complete_checkin(address, proxy_url)
        if checkin:
            self.log(
                f"{Fore.CYAN+Style.BRIGHT}Check-In:{Style.RESET_ALL}"
                f"{Fore.GREEN+Style.BRIGHT} Success {Style.RESET_ALL}"
            )

        self.log(f"{Fore.CYAN+Style.BRIGHT}Testnet :{Style.RESET_ALL}")

        tasks = await self.list_tasks(address)
        if tasks:
            task = random.choice(tasks)
            task_name = task["name"]
            description = task["description"]

            self.log(
                f"{Fore.BLUE+Style.BRIGHT}   Task    :{Style.RESET_ALL}"
                f"{Fore.WHITE+Style.BRIGHT} {description} {Style.RESET_ALL}"
            )

            send_req = await self.send_request(address, task_name, proxy_url)
            if send_req:
                request_id = send_req.get("id")

                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}   Submit  :{Style.RESET_ALL}"
                    f"{Fore.GREEN+Style.BRIGHT} Success {Style.RESET_ALL}"
                )
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}   Task Id :{Style.RESET_ALL}"
                    f"{Fore.WHITE+Style.BRIGHT} {request_id} {Style.RESET_ALL}"
                )

                is_done = False

                for i in range(10):
                    await asyncio.sleep(3)

                    req_status = await self.request_status(address, request_id, proxy_url)
                    if not req_status: continue

                    status = req_status.get("status")
                    if status == "done":
                        is_done = True
                        self.log(
                            f"{Fore.BLUE+Style.BRIGHT}   Status  :{Style.RESET_ALL}"
                            f"{Fore.GREEN+Style.BRIGHT} Done {Style.RESET_ALL}"
                        )
                        break

                    self.log(
                        f"{Fore.BLUE+Style.BRIGHT}   Status  :{Style.RESET_ALL}"
                        f"{Fore.YELLOW+Style.BRIGHT} {status} ({i+1}/{10}) {Style.RESET_ALL}"
                    )

                if is_done:
                    feedback = await self.request_feedback(address, request_id, proxy_url)
                    if feedback:
                        message = feedback.get("message")
                        feedback_id = feedback.get("id")

                        self.log(
                            f"{Fore.BLUE+Style.BRIGHT}   Feedback:{Style.RESET_ALL}"
                            f"{Fore.GREEN+Style.BRIGHT} {message} {Style.RESET_ALL}"
                            f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                            f"{Fore.BLUE+Style.BRIGHT} Id: {Style.RESET_ALL}"
                            f"{Fore.WHITE+Style.BRIGHT}{feedback_id}{Style.RESET_ALL}"
                        )
                else:
                    self.log(
                        f"{Fore.BLUE+Style.BRIGHT}   Status  :{Style.RESET_ALL}"
                        f"{Fore.YELLOW+Style.BRIGHT} Cannot Save Feedback {Style.RESET_ALL}"
                    )

    async def main(self):
        try:
            accounts = self.load_accounts()
            if not accounts: return

            self.print_question()

            while True:
                self.clear_terminal()
                self.welcome()
                self.log(
                    f"{Fore.GREEN + Style.BRIGHT}Account's Total: {Style.RESET_ALL}"
                    f"{Fore.WHITE + Style.BRIGHT}{len(accounts)}{Style.RESET_ALL}"
                )

                if self.USE_PROXY: self.load_proxies()

                separator = "=" * 25
                for account in accounts:
                    address = self.generate_address(account)
                    self.log(
                        f"{Fore.CYAN + Style.BRIGHT}{separator}[{Style.RESET_ALL}"
                        f"{Fore.WHITE + Style.BRIGHT} {self.mask_account(address)} {Style.RESET_ALL}"
                        f"{Fore.CYAN + Style.BRIGHT}]{separator}{Style.RESET_ALL}"
                    )

                    if not address:
                        self.log(
                            f"{Fore.CYAN + Style.BRIGHT}Status  :{Style.RESET_ALL}"
                            f"{Fore.RED + Style.BRIGHT} Invalid Private Key or Library Version Not Supported {Style.RESET_ALL}"
                        )
                        continue

                    await self.process_accounts(account, address)
                    await asyncio.sleep(random.uniform(2.0, 3.0))

                self.log(f"{Fore.CYAN + Style.BRIGHT}={Style.RESET_ALL}"*72)
                
                delay = 24 * 60 * 60
                while delay > 0:
                    formatted_time = self.format_seconds(delay)
                    print(
                        f"{Fore.CYAN+Style.BRIGHT}[ Wait for{Style.RESET_ALL}"
                        f"{Fore.WHITE+Style.BRIGHT} {formatted_time} {Style.RESET_ALL}"
                        f"{Fore.CYAN+Style.BRIGHT}... ]{Style.RESET_ALL}"
                        f"{Fore.WHITE+Style.BRIGHT} | {Style.RESET_ALL}"
                        f"{Fore.BLUE+Style.BRIGHT}All Accounts Have Been Processed...{Style.RESET_ALL}",
                        end="\r",
                        flush=True
                    )
                    await asyncio.sleep(1)
                    delay -= 1

        except Exception as e:
            self.log(f"{Fore.RED+Style.BRIGHT}Error: {e}{Style.RESET_ALL}")
            raise e
        finally:
            for s in self.sessions.values():
                if not s["session"].closed:
                    await s["session"].close()

if __name__ == "__main__":
    try:
        bot = Konnex()
        asyncio.run(bot.main())
    except KeyboardInterrupt:
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().astimezone(wib).strftime('%x %X %Z')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}"
            f"{Fore.RED + Style.BRIGHT}[ EXIT ] Konnex - BOT{Style.RESET_ALL}                                       "                              
        )