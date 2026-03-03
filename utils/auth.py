#!/usr/bin/env python3
"""
认证管理模块 - 处理用户名密码登录、session 缓存和自动续期
"""

import json
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from playwright.async_api import async_playwright

from utils.config import AccountConfig, ProviderConfig, parse_cookies

SESSION_CACHE_DIR = Path('.session_cache')

# session 缓存过期时间（25 天，session 有效期 30 天，留 5 天余量）
SESSION_CACHE_MAX_AGE = 25 * 24 * 3600


def log(level: str, msg: str, account: str = ''):
	"""统一日志输出"""
	prefix = f'{account} > ' if account else ''
	print(f'[{level}] {prefix}{msg}')


@dataclass
class AuthResult:
	"""认证结果"""

	session: str
	api_user: str
	waf_cookies: dict
	success: bool = True
	error: str | None = None


def _get_cache_path(username: str, provider: str) -> Path:
	"""获取某账号的 session 缓存文件路径"""
	safe_name = f'{provider}_{username}'.replace('@', '_at_').replace('.', '_')
	return SESSION_CACHE_DIR / f'{safe_name}.json'


def save_session_cache(username: str, provider: str, session: str, api_user: str):
	"""保存 session 到本地缓存"""
	SESSION_CACHE_DIR.mkdir(exist_ok=True)
	cache_path = _get_cache_path(username, provider)
	cache_data = {
		'session': session,
		'api_user': api_user,
		'cached_at': time.time(),
	}
	try:
		with open(cache_path, 'w', encoding='utf-8') as f:
			json.dump(cache_data, f)
	except Exception as e:
		log('WARN', f'Failed to cache session: {e}')


def load_session_cache(username: str, provider: str) -> dict | None:
	"""从本地缓存加载 session"""
	cache_path = _get_cache_path(username, provider)
	if not cache_path.exists():
		return None
	try:
		with open(cache_path, 'r', encoding='utf-8') as f:
			data: dict = json.load(f)
		if time.time() - data.get('cached_at', 0) > SESSION_CACHE_MAX_AGE:
			return None
		return data
	except Exception:  # nosec B110
		return None


async def login(username: str, password: str, provider_config: ProviderConfig, account_name: str = '') -> AuthResult:
	"""使用 Playwright 通过用户名密码登录，获取 session、api_user 和 WAF cookies"""
	login_api_url = f'{provider_config.domain}{provider_config.login_api_path}'
	login_page_url = f'{provider_config.domain}{provider_config.login_path}'
	log('INFO', f'Logging in as {username} via Playwright...', account_name)

	try:
		async with async_playwright() as p:
			with tempfile.TemporaryDirectory() as temp_dir:
				context = await p.chromium.launch_persistent_context(
					user_data_dir=temp_dir,
					headless=True,
					user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
					viewport={'width': 1920, 'height': 1080},
					args=[
						'--disable-blink-features=AutomationControlled',
						'--disable-dev-shm-usage',
						'--disable-web-security',
						'--disable-features=VizDisplayCompositor',
						'--no-sandbox',
					],
				)

				page = await context.new_page()

				try:
					await page.goto(login_page_url, wait_until='networkidle')

					try:
						await page.wait_for_function('document.readyState === "complete"', timeout=5000)
					except Exception:
						await page.wait_for_timeout(3000)

					# 收集 WAF cookies
					waf_cookies = {}
					if provider_config.needs_waf_cookies() and provider_config.waf_cookie_names:
						cookies = await page.context.cookies()
						for cookie in cookies:
							cookie_name = cookie.get('name')
							cookie_value = cookie.get('value')
							if cookie_name in provider_config.waf_cookie_names and cookie_value is not None:
								waf_cookies[cookie_name] = cookie_value

					# 使用 Playwright 发送登录 API 请求
					response = await page.request.post(
						login_api_url,
						data={'username': username, 'password': password},
						headers={'Content-Type': 'application/json'},
					)

					status = response.status
					if status != 200:
						await context.close()
						return AuthResult(
							session='',
							api_user='',
							waf_cookies={},
							success=False,
							error=f'Login failed: HTTP {status}',
						)

					data = await response.json()
					if not data.get('success'):
						msg = data.get('message', 'Unknown error')
						await context.close()
						return AuthResult(
							session='', api_user='', waf_cookies={}, success=False, error=f'Login failed: {msg}'
						)

					# 从响应数据中获取 api_user (data.id)
					user_data = data.get('data', {})
					api_user = str(user_data.get('id', ''))
					if not api_user:
						await context.close()
						return AuthResult(
							session='',
							api_user='',
							waf_cookies={},
							success=False,
							error='Login succeeded but no user ID in response',
						)

					# 从浏览器 cookies 中获取 session
					all_cookies = await page.context.cookies()
					session_value = None
					for cookie in all_cookies:
						if cookie.get('name') == 'session':
							session_value = cookie.get('value')
							break

					if not session_value:
						# 尝试从响应头获取
						headers = response.headers
						set_cookie = headers.get('set-cookie', '')
						if 'session=' in set_cookie:
							for part in set_cookie.split(';'):
								part = part.strip()
								if part.startswith('session='):
									session_value = part.split('=', 1)[1]
									break

					if not session_value:
						await context.close()
						return AuthResult(
							session='',
							api_user='',
							waf_cookies={},
							success=False,
							error='Login succeeded but no session cookie in response',
						)

					log('OK', f'Login successful (user_id={api_user})', account_name)
					await context.close()
					return AuthResult(
						session=session_value,
						api_user=api_user,
						waf_cookies=waf_cookies,
					)

				except Exception as e:
					await context.close()
					return AuthResult(
						session='', api_user='', waf_cookies={}, success=False, error=f'Login error: {str(e)[:100]}'
					)

	except Exception as e:
		return AuthResult(
			session='', api_user='', waf_cookies={}, success=False, error=f'Browser launch error: {str(e)[:100]}'
		)


async def resolve_account_auth(
	account: AccountConfig, provider_config: ProviderConfig
) -> tuple[dict, str, dict] | None:
	"""解析账号的认证信息

	- cookies 方式：返回 (cookies_dict, api_user, {})
	- 用户名密码方式：先尝试缓存，再尝试 Playwright 登录
	返回 (user_cookies, api_user, waf_cookies) 或 None
	"""
	if not account.uses_credential_login():
		cookies = parse_cookies(account.cookies)
		if not cookies or not account.api_user:
			return None
		return (cookies, account.api_user, {})

	username = account.username
	password = account.password
	if not username or not password:
		return None

	# 先尝试缓存的 session
	cached = load_session_cache(username, account.provider)
	if cached:
		log('INFO', f'Using cached session for {username}')
		return ({'session': cached['session']}, cached['api_user'], {})

	# 缓存不可用，执行 Playwright 登录
	result = await login(username, password, provider_config)
	if not result.success:
		log('FAIL', f'{result.error}')
		return None

	save_session_cache(username, account.provider, result.session, result.api_user)
	return ({'session': result.session}, result.api_user, result.waf_cookies)


async def retry_with_relogin(
	account: AccountConfig, provider_config: ProviderConfig, account_name: str = ''
) -> tuple[dict, str, dict] | None:
	"""session 过期时强制重新登录，仅对用户名密码方式有效"""
	if not account.uses_credential_login():
		log('WARN', 'Session expired, static cookies cannot auto-relogin', account_name)
		return None

	username = account.username
	password = account.password
	if not username or not password:
		return None

	log('INFO', f'Session expired, re-logging in as {username}...', account_name)
	result = await login(username, password, provider_config, account_name)
	if not result.success:
		log('FAIL', f'Re-login failed: {result.error}', account_name)
		return None

	save_session_cache(username, account.provider, result.session, result.api_user)
	return ({'session': result.session}, result.api_user, result.waf_cookies)
