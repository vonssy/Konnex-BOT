from aiohttp import (
    ClientResponseError,
    ClientSession,
    ClientTimeout,
    BasicAuth
)
from aiohttp_socks import ProxyConnector
from http.cookies import SimpleCookie
from hashlib import sha256
from eth_utils import to_hex
from eth_account import Account
from eth_account.messages import encode_defunct
from substrateinterface import Keypair, SubstrateInterface
from datetime import datetime, timedelta, timezone
from colorama import *
import asyncio, random, time, json, ssl, sys, re, os

class Konnex:
    def __init__(self) -> None:
        self.API_URL = {
            "hub": "https://hub.konnex.world",
            "testnet": "https://testnet-rpc2.konnex.world:30443",
            "rpc_ws": "wss://testnet-rpc1.konnex.world:39944"
        }
        
        self.USE_PROXY = False
        self.ROTATE_PROXY = False
        
        self.proxies = []
        self.proxy_index = 0
        self.account_proxies = {}
        self.accounts = {}
        self.props = {}
        
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
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().strftime('%x %X')} ]{Style.RESET_ALL}"
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
        filename = "accounts.json"
        try:
            if not os.path.exists(filename):
                self.log(f"{Fore.RED}File {filename} Not Found.{Style.RESET_ALL}")
                return

            with open(filename, 'r') as file:
                data = json.load(file)
                if isinstance(data, list):
                    return data
                return []
        except json.JSONDecodeError:
            return []

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
    
    def get_next_run_time(self, anchor_minute=1):
        now = datetime.now(timezone.utc)
        today_target = now.replace(hour=0, minute=anchor_minute, second=0, microsecond=0)

        if today_target > now:
            return today_target
        else:
            return today_target + timedelta(days=1)
    
    def extract_cookies(self, account: str, response: object):
        existing = self.accounts[account].get("cookies", {})
        
        jar = SimpleCookie()
        
        for k, v in existing.items():
            jar[k] = v
        
        for h in response.headers.getall("Set-Cookie", []):
            jar.load(h)
        
        self.accounts[account]["cookies"] = {
            k: m.value for k, m in jar.items()
        }

        return self.accounts[account]["cookies"]
    
    def initialize_headers(self, idx: int, type: str = "hub"):
        if type == "testnet":
            headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Host": "testnet-rpc2.konnex.world:30443",
                "Origin": "https://subnets.testnet.konnex.world",
                "Pragma": "no-cache",
                "Referer": "https://subnets.testnet.konnex.world/",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-site",
                "User-Agent": self.accounts[idx]["user_agent"]
            }

        else:
            headers = {
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
                "Cache-Control": "no-cache",
                "Origin": "https://hub.konnex.world",
                "Pragma": "no-cache",
                "Referer": "https://hub.konnex.world/points",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                "User-Agent": self.accounts[idx]["user_agent"]
            }
            

        return headers.copy()
    
    def generate_wallet(self, idx: int):
        try:
            if self.accounts[idx].get("evm_wallet_private_key"):
                private_key = self.accounts[idx]["evm_wallet_private_key"]
                evm_keypair = Account.from_key(private_key)
                evm_address = evm_keypair.address
                self.accounts[idx]["evm_keypair"] = evm_keypair
                self.accounts[idx]["evm_address"] = evm_address
            
            if self.accounts[idx].get("konnex_wallet_mnemonic"):
                mnemonic = self.accounts[idx]["konnex_wallet_mnemonic"]
                knx_keypair =  Keypair.create_from_mnemonic(mnemonic, ss58_format=42)
                knx_address = knx_keypair.ss58_address
                self.accounts[idx]["knx_keypair"] = knx_keypair
                self.accounts[idx]["knx_address"] = knx_address
            
            return True
        except Exception as e:
            self.log(
                f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                f"{Fore.RED+Style.BRIGHT} Generate Wallet Failed {Style.RESET_ALL}"
                f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
            )
            return None
        
    def generate_hub_payload(self, idx: int, csrf_token: str):
        try:
            keypair = self.accounts[idx]["evm_keypair"]
            address = self.accounts[idx]["evm_address"]

            dt_now = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            issued_at = dt_now.replace("+00:00", "Z")

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
            signed_message = keypair.sign_message(encoded_message)
            signature = to_hex(signed_message.signature)

            return {
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
        except Exception as e:
            raise Exception(f"Generate Req Payload Failed: {str(e)}")
        
    def generate_testnet_payload(self, idx: int):
        try:
            keypair = self.accounts[idx]["evm_keypair"]
            
            nonce = str(int(time.time()))
            message = f"Konnex.world asks you to sign this text message to verify this wallet ownership. Nonce: {nonce}"
            
            encoded_message = encode_defunct(text=message)
            signed_message = keypair.sign_message(encoded_message)
            signature = to_hex(signed_message.signature)

            return {
                "signature": signature,
                "message": message,
                "nonce": nonce
            }
        except Exception as e:
            raise Exception(f"Generate Req Payload Failed: {str(e)}")
        
    def generate_drone_nav_params(self):
        locactions = ["parking", "tall-buildings", "river"]
        tasks = ["inspect", "patrol"]

        return {
            "location": random.choice(locactions),
            "task": random.choice(tasks),
        }
    
    def submit_drone_remark(self, idx: int, substrate: SubstrateInterface, nav_params: dict) -> str:
        task_description = f"quest-drone-v1:{nav_params['location'].strip()}:{nav_params['task'].strip()}"
        task_hash = sha256(task_description.strip().encode("utf-8")).hexdigest()
        remark_payload = f"konnex-job:v1:4:0x{task_hash}"

        call = substrate.compose_call(
            call_module="System",
            call_function="remark",
            call_params={"remark": remark_payload}
        )

        keypair = self.accounts[idx]["knx_keypair"]

        extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair)

        receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        if not receipt.is_success: return None

        return receipt.extrinsic_hash
    
    def find_add_stake_call(self, substrate: SubstrateInterface):
        substrate.init_runtime()

        candidates = [
            ("SubtensorModule", "add_stake"),
            ("SubtensorModule", "addStake"),
            ("Subtensor", "add_stake"),
            ("Subtensor", "addStake"),
        ]
        for module_name, call_name in candidates:
            call_meta = substrate.get_metadata_call_function(module_name, call_name)
            if call_meta is not None:
                return module_name, call_name, call_meta

        found = [
            (pallet.name, call.name)
            for pallet in substrate.metadata.pallets if pallet.calls
            for call in pallet.calls if "stake" in str(call.name).lower()
        ]
        if not found: return None

        module_name, call_name = found[0]

        return module_name, call_name, substrate.get_metadata_call_function(module_name, call_name)

    def compute_stake_amount(self, idx: int, substrate: SubstrateInterface) -> int:
        decimals = substrate.token_decimals

        if decimals and decimals > 0:
            max_stake = 0.01 * (10 ** decimals)
            reserve_buffer = 10 ** max(decimals - 2, 0)
        else:
            max_stake = 0.01 * 1_000_000_000
            reserve_buffer = 1_000_000

        address = self.accounts[idx]["knx_address"]
        account_info = substrate.query("System", "Account", [address])
        free_balance = int(account_info.value["data"]["free"])

        existential_deposit = substrate.get_constant("Balances", "ExistentialDeposit")
        existential_deposit = int(existential_deposit.value) if existential_deposit is not None else 0
        reserve = existential_deposit + reserve_buffer

        if free_balance <= reserve: return None

        amount = min(free_balance - reserve, max_stake)
        return amount

    def submit_alpha_stake(self, idx: int, substrate: SubstrateInterface, hotkey: str) -> str:
        module_name, call_name, call_meta = self.find_add_stake_call(substrate)

        arg_names = [str(arg.name) for arg in call_meta.args]
        if len(arg_names) != 3: return None

        amount = self.compute_stake_amount(idx, substrate)
        if not amount: return None

        call_params = dict(zip(arg_names, [hotkey, 4, amount]))

        call = substrate.compose_call(call_module=module_name, call_function=call_name, call_params=call_params)
        
        keypair = self.accounts[idx]["knx_keypair"]
        
        extrinsic = substrate.create_signed_extrinsic(call=call, keypair=keypair)

        receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

        if not receipt.is_success: return None

        return receipt.extrinsic_hash

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
                    print(f"{Fore.RED + Style.BRIGHT}Please enter either 1 or 2.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED + Style.BRIGHT}Invalid input. Enter a number (1 or 2).{Style.RESET_ALL}")

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
    
    async def check_connection(self, proxy_url=None):
        url = "https://api.ipify.org?format=json"

        connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
        try:
            async with ClientSession(connector=connector, timeout=ClientTimeout(total=30)) as session:
                async with session.get(url=url, proxy=proxy, proxy_auth=proxy_auth) as response:
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
    
    async def websites_props(self, idx: int, proxy_url=None, retries=5):
        url = f"{self.API_URL['hub']}/api/props/websites"
        
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                headers = self.initialize_headers(idx)
                cookies = self.accounts[idx].get("cookies", {})

                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.get(
                        url=url, headers=headers, cookies=cookies, proxy=proxy, proxy_auth=proxy_auth
                    ) as response:
                        await self.ensure_ok(response)
                        self.extract_cookies(idx, response)
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Fetch Web Props {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def auth_csrf(self, idx: int, proxy_url=None, retries=5):
        url = f"{self.API_URL['hub']}/api/auth/csrf"
        
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                headers = self.initialize_headers(idx)
                cookies = self.accounts[idx].get("cookies", {})

                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.get(
                        url=url, headers=headers, cookies=cookies, proxy=proxy, proxy_auth=proxy_auth
                    ) as response:
                        await self.ensure_ok(response)
                        self.extract_cookies(idx, response)
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Login   :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Fetch Csrf Token {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def auth_credentials(self, idx: int, csrf_token: str, proxy_url=None, retries=5):
        url = f"{self.API_URL['hub']}/api/auth/callback/credentials"
        
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                headers = self.initialize_headers(idx)
                headers["Content-Type"] = "application/json"
                headers["X-Requested-With"] = "XMLHttpRequest"
                cookies = self.accounts[idx].get("cookies", {})
                payload = self.generate_hub_payload(idx, csrf_token)

                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(
                        url=url, headers=headers, cookies=cookies, json=payload, proxy=proxy, proxy_auth=proxy_auth
                    ) as response:
                        await self.ensure_ok(response)
                        self.extract_cookies(idx, response)
                        return True
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Login   :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Fetch Session Token {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None

    async def loyality_accounts(self, idx: int, proxy_url=None, retries=5):
        url = f"{self.API_URL['hub']}/api/loyalty/accounts"
        
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                headers = self.initialize_headers(idx)
                cookies = self.accounts[idx].get("cookies", {})
                params = {
                    "websiteId": self.props["web_id"], 
                    "organizationId": self.props["org_id"], 
                    "walletAddress": self.accounts[idx]["evm_address"]
                }
                
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.get(
                        url=url, headers=headers, cookies=cookies, params=params, proxy=proxy, proxy_auth=proxy_auth
                    ) as response:
                        await self.ensure_ok(response)
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Balance :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Fetch Points {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None

    async def loyality_rules(self, idx: int, proxy_url=None, retries=5):
        url = f"{self.API_URL['hub']}/api/loyalty/rules"
        
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                headers = self.initialize_headers(idx)
                cookies = self.accounts[idx].get("cookies", {})
                params = {
                    "limit": "100",
                    "websiteId": self.props["web_id"], 
                    "organizationId": self.props["org_id"], 
                    "excludeHidden": "true",
                    "excludeExpired": "true",
                    "isActive": "true"
                }
                
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.get(
                        url=url, headers=headers, cookies=cookies, params=params, proxy=proxy, proxy_auth=proxy_auth
                    ) as response:
                        await self.ensure_ok(response)
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Check-In:{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Fetch Rules Id {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def complete_checkin(self, idx: int, rules_id: str, proxy_url=None, retries=5):
        url = f"{self.API_URL['hub']}/api/loyalty/rules/{rules_id}/complete"
        
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                headers = self.initialize_headers(idx)
                headers["Content-Type"] = "application/json"
                cookies = self.accounts[idx].get("cookies", {})
                
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(
                        url=url, headers=headers, cookies=cookies, json={}, proxy=proxy, proxy_auth=proxy_auth
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
    
    async def verify_wallet(self, idx: int, sign_data: dict, proxy_url=None, retries=5):
        url = f"{self.API_URL['testnet']}/api/v1/quest/snag/verify-wallet"
        
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                headers = self.initialize_headers(idx, "testnet")
                headers["Content-Type"] = "application/json"
                payload = {
                    "wallet": self.accounts[idx]["evm_address"],
                    "signature": sign_data["signature"],
                    "message": sign_data["message"],
                    "nonce": sign_data["nonce"]
                }

                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(
                        url=url, headers=headers, json=payload, proxy=proxy, proxy_auth=proxy_auth, ssl=False
                    ) as response:
                        await self.ensure_ok(response)
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}   Verify  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Verify EVM Wallet {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def claim_faucet(self, idx: int, sign_data: dict, proxy_url=None, retries=5):
        url = f"{self.API_URL['testnet']}/api/v1/quest/faucet"
        
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                headers = self.initialize_headers(idx, "testnet")
                headers["Content-Type"] = "application/json"
                payload = {
                    "evm_wallet": self.accounts[idx]["evm_address"],
                    "evm_signature": sign_data["signature"],
                    "knx_wallet": self.accounts[idx]["knx_address"],
                    "message": sign_data["message"],
                    "nonce": sign_data["nonce"]
                }

                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(
                        url=url, headers=headers, json=payload, proxy=proxy, proxy_auth=proxy_auth, ssl=False
                    ) as response:
                        await self.ensure_ok(response)
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}   Faucet  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Claim KNX Tokens {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def drone_request(self, idx: int, txid: str, nav_params: dict, proxy_url=None, retries=5):
        url = f"{self.API_URL['testnet']}/api/v1/quest/drone/request"
        
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                headers = self.initialize_headers(idx, "testnet")
                headers["Content-Type"] = "application/json"
                payload = {
                    "knx_wallet": self.accounts[idx]["knx_address"],
                    "txid": txid,
                    "params": nav_params
                }

                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(
                        url=url, headers=headers, json=payload, proxy=proxy, proxy_auth=proxy_auth, ssl=False
                    ) as response:
                        await self.ensure_ok(response)
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}   Drone   :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Sending Navigation Request {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def subnets_list(self, idx: int, proxy_url=None, retries=5):
        url = f"{self.API_URL['testnet']}/api/v1/quest/subnets"
        
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                headers = self.initialize_headers(idx, "testnet")

                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.get(
                        url=url, headers=headers, proxy=proxy, proxy_auth=proxy_auth, ssl=False
                    ) as response:
                        await self.ensure_ok(response)
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}   Alpha   :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Fetch Subnets {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def alpha_bought(self, idx: int, txid: str, proxy_url=None, retries=5):
        url = f"{self.API_URL['testnet']}/api/v1/quest/alpha-bought"
        
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                headers = self.initialize_headers(idx, "testnet")
                headers["Content-Type"] = "application/json"
                payload = {
                    "knx_wallet": self.accounts[idx]["knx_address"],
                    "txid": txid,
                    "netuid": 4
                }

                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(
                        url=url, headers=headers, json=payload, proxy=proxy, proxy_auth=proxy_auth, ssl=False
                    ) as response:
                        await self.ensure_ok(response)
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}   Alpha   :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed to Buy {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def process_check_connection(self, idx: int, proxy_url=None):
        while True:
            if self.USE_PROXY:
                proxy_url = self.get_next_proxy_for_account(idx)

            self.log(
                f"{Fore.CYAN+Style.BRIGHT}Proxy   :{Style.RESET_ALL}"
                f"{Fore.WHITE+Style.BRIGHT} {self.display_proxy(proxy_url)} {Style.RESET_ALL}"
            )

            is_valid = await self.check_connection(proxy_url)
            if is_valid: return True

            if self.ROTATE_PROXY:
                proxy_url = self.rotate_proxy_for_account(idx)
                await asyncio.sleep(1)
                continue

            return False
    
    async def process_user_login(self, idx: int, proxy_url=None):
        is_valid = await self.process_check_connection(idx, proxy_url)
        if not is_valid: return False

        if self.USE_PROXY:
            proxy_url = self.get_next_proxy_for_account(idx)

        props = await self.websites_props(idx, proxy_url)
        if not props: return False

        web_id = props.get("websiteId")
        org_id = props.get("organizationId")

        if not web_id or not org_id:
            self.log(
                f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                f"{Fore.YELLOW+Style.BRIGHT} Web/Org Id Not Found {Style.RESET_ALL}"
            )
            return False
        
        self.props["web_id"] = web_id
        self.props["org_id"] = org_id

        auth_csrf = await self.auth_csrf(idx, proxy_url)
        if not auth_csrf: return False

        csrf_token = auth_csrf.get("csrfToken")

        credentials = await self.auth_credentials(idx, csrf_token, proxy_url)
        if not credentials: return False

        self.log(
            f"{Fore.CYAN + Style.BRIGHT}Status  :{Style.RESET_ALL}"
            f"{Fore.GREEN + Style.BRIGHT} Login Success {Style.RESET_ALL}"
        )

        return True

    async def process_drone_request(self, idx: int, substrate: SubstrateInterface, proxy_url=None):
        nav_params = self.generate_drone_nav_params()

        txid = self.submit_drone_remark(idx, substrate, nav_params)
        if not txid:
            self.log(
                f"{Fore.BLUE+Style.BRIGHT}   Drone   :{Style.RESET_ALL}"
                f"{Fore.RED+Style.BRIGHT} Failed to Sign On-Chain {Style.RESET_ALL}"
            )
            return False
        
        drone = await self.drone_request(idx, txid, nav_params, proxy_url)
        if not drone: return False

        self.log(
            f"{Fore.BLUE+Style.BRIGHT}   Drone   :{Style.RESET_ALL}"
            f"{Fore.GREEN+Style.BRIGHT} Navigation Request Successfully Sent {Style.RESET_ALL}"
        )

        return True
    
    async def process_alpha_bought(self, idx: int, substrate: SubstrateInterface, proxy_url=None):
        subnets = await self.subnets_list(idx, proxy_url)
        if not subnets: return False

        hotkey = next(
            (str(item.get("alpha_target_hotkey", "")).strip()
            for item in subnets.get("items", [])
            if int(item.get("netuid", -1)) == 4),
            None
        )
        if not hotkey:
            self.log(
                f"{Fore.BLUE+Style.BRIGHT}   Alpha   :{Style.RESET_ALL}"
                f"{Fore.RED+Style.BRIGHT} Target Hotkey Not Found In Subnets {Style.RESET_ALL}"
            )
            return False
        
        txid = self.submit_alpha_stake(idx, substrate, hotkey)
        if not txid:
            self.log(
                f"{Fore.BLUE+Style.BRIGHT}   Alpha   :{Style.RESET_ALL}"
                f"{Fore.RED+Style.BRIGHT} Failed to Sign On-Chain {Style.RESET_ALL}"
            )
            return False
        
        alpha = await self.alpha_bought(idx, txid, proxy_url)
        if not alpha: return False

        self.log(
            f"{Fore.BLUE+Style.BRIGHT}   Alpha   :{Style.RESET_ALL}"
            f"{Fore.GREEN+Style.BRIGHT} Successfully Bought {Style.RESET_ALL}"
        )

        return True

    async def process_accounts(self, idx: int, proxy_url=None):
        logined = await self.process_user_login(idx, proxy_url)
        if not logined: return False

        if self.USE_PROXY:
            proxy_url = self.get_next_proxy_for_account(idx)

        accounts = await self.loyality_accounts(idx, proxy_url)
        if accounts:
            accounts_data = accounts.get("data") or []

            amount = (
                accounts_data[0].get("amount", 0)
                if accounts_data and isinstance(accounts_data[0], dict)
                else 0
            )

            self.log(
                f"{Fore.CYAN+Style.BRIGHT}Balance :{Style.RESET_ALL}"
                f"{Fore.WHITE+Style.BRIGHT} {amount} Points {Style.RESET_ALL}"
            )

        rules = await self.loyality_rules(idx, proxy_url)
        if rules:
            rules_data = rules.get("data") or []

            rules_id = next(
                (r.get("id") for r in rules_data if r.get("type") == "check_in" and r.get("claimType") == "manual"),
                None,
            )

            if rules_id:
                if await self.complete_checkin(idx, rules_id, proxy_url):
                    self.log(
                        f"{Fore.CYAN+Style.BRIGHT}Check-In:{Style.RESET_ALL}"
                        f"{Fore.GREEN+Style.BRIGHT} Success {Style.RESET_ALL}"
                    )
            else:
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Check-In:{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} Rules Id Not Found {Style.RESET_ALL}"
                )

        if not self.accounts[idx].get("konnex_wallet_mnemonic"):
            self.log(
                f"{Fore.CYAN+Style.BRIGHT}Testnet :{Style.RESET_ALL}"
                f"{Fore.YELLOW+Style.BRIGHT} Konnex Wallet No Set {Style.RESET_ALL}"
            )
            return False
        
        self.log(f"{Fore.CYAN+Style.BRIGHT}Testnet :{Style.RESET_ALL}")

        sign_data = self.generate_testnet_payload(idx)

        verify = await self.verify_wallet(idx, sign_data, proxy_url)
        if not verify: return False

        snag_uid = verify.get("snag_user_id")

        self.log(
            f"{Fore.BLUE+Style.BRIGHT}   Verify  :{Style.RESET_ALL}"
            f"{Fore.GREEN+Style.BRIGHT} Success {Style.RESET_ALL}"
        )
        self.log(
            f"{Fore.BLUE+Style.BRIGHT}   User Id :{Style.RESET_ALL}"
            f"{Fore.WHITE+Style.BRIGHT} {snag_uid} {Style.RESET_ALL}"
        )

        faucet = await self.claim_faucet(idx, sign_data, proxy_url)
        if faucet:

            if not faucet.get("already_claimed"):
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}   Faucet  :{Style.RESET_ALL}"
                    f"{Fore.GREEN+Style.BRIGHT} KNX Tokens Claimed {Style.RESET_ALL}"
                )
            else:
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}   Faucet  :{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} KNX Tokens Already Claimed {Style.RESET_ALL}"
                )

        try:
            substrate = SubstrateInterface(
                url=self.API_URL["rpc_ws"],
                ws_options={"sslopt": {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}}
            )
        except Exception as e:
            self.log(
                f"{Fore.BLUE+Style.BRIGHT}   Status  :{Style.RESET_ALL}"
                f"{Fore.RED+Style.BRIGHT} Substrate Not Connected: {e} {Style.RESET_ALL}"
            )
            return False
        
        await self.process_drone_request(idx, substrate, proxy_url)

        await self.process_alpha_bought(idx, substrate, proxy_url)
        
    async def main(self):
        try:
            accounts = self.load_accounts()
            if not accounts:
                print(f"{Fore.RED+Style.BRIGHT}No Accounts Loaded.{Style.RESET_ALL}") 
                return

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
                for idx, account in enumerate(accounts, start=1):
                    self.log(
                        f"{Fore.CYAN + Style.BRIGHT}{separator}[{Style.RESET_ALL}"
                        f"{Fore.WHITE + Style.BRIGHT} {idx} {Style.RESET_ALL}"
                        f"{Fore.CYAN + Style.BRIGHT}-{Style.RESET_ALL}"
                        f"{Fore.WHITE + Style.BRIGHT} {len(accounts)} {Style.RESET_ALL}"
                        f"{Fore.CYAN + Style.BRIGHT}]{separator}{Style.RESET_ALL}"
                    )

                    if idx not in self.accounts:
                        self.accounts[idx] = {
                            "user_agent": random.choice(self.USER_AGENTS)
                        }

                    evm_wallet_private_key = account.get("evm_wallet_private_key")
                    konnex_wallet_mnemonic = account.get("konnex_wallet_mnemonic")

                    self.accounts[idx]["evm_wallet_private_key"] = evm_wallet_private_key
                    self.accounts[idx]["konnex_wallet_mnemonic"] = konnex_wallet_mnemonic

                    if not self.generate_wallet(idx): continue

                    self.log(
                        f"{Fore.CYAN+Style.BRIGHT}Address :{Style.RESET_ALL}"
                        f"{Fore.WHITE+Style.BRIGHT} {self.mask_account(self.accounts[idx]['evm_address'])} {Style.RESET_ALL}"
                    )
                        
                    await self.process_accounts(idx)
                    await asyncio.sleep(random.uniform(2.0, 3.0))

                self.log(f"{Fore.CYAN + Style.BRIGHT}={Style.RESET_ALL}"*60)
                
                next_run = self.get_next_run_time(anchor_minute=1)

                while True:
                    now = datetime.now(timezone.utc)
                    remaining = (next_run - now).total_seconds()

                    if remaining <= 0:
                        break

                    formatted_time = self.format_seconds(remaining)

                    print(
                        f"{Fore.CYAN+Style.BRIGHT}[ Wait for{Style.RESET_ALL}"
                        f"{Fore.WHITE+Style.BRIGHT} {formatted_time} {Style.RESET_ALL}"
                        f"{Fore.CYAN+Style.BRIGHT}]{Style.RESET_ALL}"
                        f"{Fore.WHITE+Style.BRIGHT} | {Style.RESET_ALL}"
                        f"{Fore.BLUE+Style.BRIGHT}All Accounts Have Been Processed...{Style.RESET_ALL}",
                        end="\r",
                        flush=True
                    )
                    await asyncio.sleep(1)

        except Exception as e:
            self.log(f"{Fore.RED+Style.BRIGHT}Error: {e}{Style.RESET_ALL}")
            raise e
        except asyncio.CancelledError:
            raise

if __name__ == "__main__":
    try:
        bot = Konnex()
        asyncio.run(bot.main())
    except KeyboardInterrupt:
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().strftime('%x %X')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}"
            f"{Fore.RED + Style.BRIGHT}[ EXIT ] Konnex - BOT{Style.RESET_ALL}                                       "                              
        )
    finally:
        sys.exit(0)