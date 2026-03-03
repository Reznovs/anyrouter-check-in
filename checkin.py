#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.auth import resolve_account_auth, retry_with_relogin
from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'
SUMMARY_FILE = 'checkin_summary.md'


def log(level: str, msg: str, account: str = ''):
	"""统一日志输出"""
	prefix = f'{account} > ' if account else ''
	print(f'[{level}] {prefix}{msg}')


def load_balance_hash():
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:  # nosec B110
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		log('WARN', f'Failed to save balance hash: {e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	# 将包含 quota 和 used 的结构转换为简单的 quota 值用于 hash 计算
	simple_balances = {k: v['quota'] for k, v in balances.items()} if balances else {}
	balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


async def get_waf_cookies_with_playwright(account_name: str, login_url: str, required_cookies: list[str]):
	"""使用 Playwright 获取 WAF cookies（隐私模式）"""
	log('INFO', 'Getting WAF cookies via browser...', account_name)

	async with async_playwright() as p:
		import tempfile

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
				await page.goto(login_url, wait_until='networkidle')

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)

				cookies = await page.context.cookies()

				waf_cookies = {}
				for cookie in cookies:
					cookie_name = cookie.get('name')
					cookie_value = cookie.get('value')
					if cookie_name in required_cookies and cookie_value is not None:
						waf_cookies[cookie_name] = cookie_value

				missing_cookies = [c for c in required_cookies if c not in waf_cookies]

				if missing_cookies:
					log('FAIL', f'Missing WAF cookies: {missing_cookies}', account_name)
					await context.close()
					return None

				log('OK', f'Got {len(waf_cookies)} WAF cookies', account_name)

				await context.close()

				return waf_cookies

			except Exception as e:
				log('FAIL', f'WAF cookie error: {e}', account_name)
				await context.close()
				return None


def get_user_info(client, headers, user_info_url: str):
	"""获取用户信息"""
	try:
		response = client.get(user_info_url, headers=headers, timeout=30)

		if response.status_code == 200:
			data = response.json()
			if data.get('success'):
				user_data = data.get('data', {})
				quota = round(user_data.get('quota', 0) / 500000, 2)
				used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
				return {
					'success': True,
					'quota': quota,
					'used_quota': used_quota,
				}
		return {'success': False, 'error': f'HTTP {response.status_code}'}
	except Exception as e:
		return {'success': False, 'error': f'{str(e)[:50]}'}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
	"""准备请求所需的 cookies（可能包含 WAF cookies）"""
	waf_cookies = {}

	if provider_config.needs_waf_cookies():
		login_url = f'{provider_config.domain}{provider_config.login_path}'
		waf_cookies = await get_waf_cookies_with_playwright(account_name, login_url, provider_config.waf_cookie_names)
		if not waf_cookies:
			return None

	return {**waf_cookies, **user_cookies}


def execute_check_in(client, account_name: str, provider_config, headers: dict):
	"""执行签到请求"""
	log('INFO', 'Sending check-in request...', account_name)

	checkin_headers = headers.copy()
	checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

	sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
	response = client.post(sign_in_url, headers=checkin_headers, timeout=30)

	if response.status_code == 200:
		try:
			result = response.json()
			if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
				log('OK', 'Check-in successful', account_name)
				return True
			else:
				error_msg = result.get('msg', result.get('message', 'Unknown error'))
				# 检查是否是"已经签到过"的情况，这种情况也算成功
				already_checked_keywords = ['已经签到', '已签到', '重复签到', 'already checked', 'already signed']
				if any(keyword in error_msg.lower() for keyword in already_checked_keywords):
					log('OK', 'Already checked in today', account_name)
					return True
				log('FAIL', f'Check-in failed: {error_msg}', account_name)
				return False
		except json.JSONDecodeError:
			# 非 JSON 响应通常是 WAF 拦截页面，视为失败
			log('FAIL', 'Non-JSON response (likely WAF block)', account_name)
			return False
	else:
		log('FAIL', f'Check-in failed: HTTP {response.status_code}', account_name)
		return False


def format_check_in_notification(detail: dict) -> str:
	"""格式化签到通知消息

	Args:
		detail: 包含签到详情的字典

	Returns:
		格式化后的通知消息
	"""
	lines = [
		f'[CHECK-IN] {detail["name"]}',
		'  ━━━━━━━━━━━━━━━━━━━━',
		'  📍 签到前',
		f'     💵 余额: ${detail["before_quota"]:.2f}  |  📊 累计消耗: ${detail["before_used"]:.2f}',
		'  📍 签到后',
		f'     💵 余额: ${detail["after_quota"]:.2f}  |  📊 累计消耗: ${detail["after_used"]:.2f}',
	]

	# 判断是否有变化
	has_reward = detail['check_in_reward'] != 0
	has_usage = detail['usage_increase'] != 0

	if has_reward or has_usage:
		lines.append('  ━━━━━━━━━━━━━━━━━━━━')

		# 已签到但期间有使用
		if not has_reward and has_usage:
			lines.append('  ℹ️  今日已签到（期间有使用）')

		# 签到获得
		if has_reward:
			lines.append(f'  🎁 签到获得: +${detail["check_in_reward"]:.2f}')

		# 期间消耗
		if has_usage:
			lines.append(f'  📉 期间消耗: ${detail["usage_increase"]:.2f}')

		# 余额变化
		if detail['balance_change'] != 0:
			change_symbol = '+' if detail['balance_change'] > 0 else ''
			change_emoji = '📈' if detail['balance_change'] > 0 else '📉'
			lines.append(f'  {change_emoji} 余额变化: {change_symbol}${detail["balance_change"]:.2f}')
	else:
		# 无任何变化
		lines.extend(['  ━━━━━━━━━━━━━━━━━━━━', '  ℹ️  今日已签到，无变化'])

	return '\n'.join(lines)


def generate_ci_summary(
	account_results: list[dict],
	account_check_in_details: dict,
	current_balances: dict,
	success_count: int,
	total_count: int,
):
	"""生成 CI Job Summary（Markdown 格式）"""
	if success_count == total_count:
		status_icon = ':white_check_mark:'
	elif success_count > 0:
		status_icon = ':warning:'
	else:
		status_icon = ':x:'

	lines = [
		f'## {status_icon} AnyRouter 签到结果 ({success_count}/{total_count})',
		'',
		f'> :alarm_clock: {datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")}',
		'',
		'| 账号 | 状态 | 余额 | 签到获得 | 余额变化 |',
		'|------|------|------|----------|----------|',
	]

	for i, result in enumerate(account_results):
		account_key = f'account_{i + 1}'
		name = result['name']
		status = ':white_check_mark: 成功' if result['success'] else ':x: 失败'

		if account_key in account_check_in_details:
			detail = account_check_in_details[account_key]
			balance = f'${detail["after_quota"]:.2f}'
			reward = f'+${detail["check_in_reward"]:.2f}' if detail['check_in_reward'] > 0 else '-'
			change_val = detail['balance_change']
			if change_val > 0:
				change = f'+${change_val:.2f}'
			elif change_val < 0:
				change = f'-${abs(change_val):.2f}'
			else:
				change = '-'
		elif account_key in current_balances:
			# 有签到后余额但没有前后对比数据
			balance = f'${current_balances[account_key]["quota"]:.2f}'
			reward = '-'
			change = '-'
		else:
			balance = '-'
			reward = '-'
			change = '-'

		lines.append(f'| {name} | {status} | {balance} | {reward} | {change} |')

	summary_md = '\n'.join(lines) + '\n'

	try:
		with open(SUMMARY_FILE, 'w', encoding='utf-8') as f:
			f.write(summary_md)
		log('INFO', f'CI summary written to {SUMMARY_FILE}')
	except Exception as e:
		log('WARN', f'Failed to write CI summary: {e}')


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
	"""为单个账号执行签到操作"""
	account_name = account.get_display_name(account_index)
	print(f'\n{"=" * 50}')
	log('INFO', f'Provider: {account.provider} ({app_config.get_provider(account.provider).domain if app_config.get_provider(account.provider) else "?"})', account_name)

	provider_config = app_config.get_provider(account.provider)
	if not provider_config:
		log('FAIL', f'Provider "{account.provider}" not found', account_name)
		return False, None, None

	# 解析认证信息（支持 cookies 方式和用户名密码方式）
	auth_result = await resolve_account_auth(account, provider_config)
	if not auth_result:
		log('FAIL', 'Authentication failed', account_name)
		return False, None, None

	user_cookies, api_user, login_waf_cookies = auth_result

	# 密码登录时 WAF cookies 已在登录过程中获取，无需重复获取
	all_cookies: dict | None = None
	if login_waf_cookies:
		all_cookies = {**login_waf_cookies, **user_cookies}
	else:
		all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
		if not all_cookies:
			return False, None, None

	client = httpx.Client(http2=True, timeout=30.0)

	try:
		client.cookies.update(all_cookies)

		headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
			'Accept': 'application/json, text/plain, */*',
			'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
			'Accept-Encoding': 'gzip, deflate, br, zstd',
			'Referer': provider_config.domain,
			'Origin': provider_config.domain,
			'Connection': 'keep-alive',
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
			provider_config.api_user_key: api_user,
		}

		user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
		user_info_before = get_user_info(client, headers, user_info_url)

		# 检查是否 session 过期（401/403），尝试自动重新登录
		if user_info_before and not user_info_before.get('success'):
			error_msg = user_info_before.get('error', '')
			if '401' in error_msg or '403' in error_msg:
				relogin_result = await retry_with_relogin(account, provider_config, account_name)
				if relogin_result:
					new_cookies, new_api_user, new_waf_cookies = relogin_result
					if new_waf_cookies:
						all_cookies = {**new_waf_cookies, **new_cookies}
					else:
						all_cookies = await prepare_cookies(account_name, provider_config, new_cookies)
					if all_cookies:
						client.cookies.clear()
						client.cookies.update(all_cookies)
						headers[provider_config.api_user_key] = new_api_user
						api_user = new_api_user
						user_info_before = get_user_info(client, headers, user_info_url)

		if user_info_before and user_info_before.get('success'):
			log('INFO', f'Balance: ${user_info_before["quota"]}, Used: ${user_info_before["used_quota"]}', account_name)
		elif user_info_before:
			error_msg = user_info_before.get('error', 'Unknown error')
			# 认证失败（401/403）且无法恢复，直接判定签到失败
			if '401' in error_msg or '403' in error_msg:
				log('FAIL', f'Unauthenticated ({error_msg}), skipping check-in', account_name)
				return False, None, None
			log('WARN', f'Failed to get user info: {error_msg}', account_name)

		if provider_config.needs_manual_check_in():
			success = execute_check_in(client, account_name, provider_config, headers)
			# 签到后再次获取用户信息，用于计算签到收益
			user_info_after = get_user_info(client, headers, user_info_url)
			return success, user_info_before, user_info_after
		else:
			log('OK', 'Auto check-in triggered by user info request', account_name)
			# 自动签到的情况，再次获取用户信息
			user_info_after = get_user_info(client, headers, user_info_url)
			return True, user_info_before, user_info_after

	except Exception as e:
		log('FAIL', f'Error: {str(e)[:80]}', account_name)
		return False, None, None
	finally:
		client.close()


async def main():
	"""主函数"""
	now = datetime.now(timezone(timedelta(hours=8))).strftime('%Y-%m-%d %H:%M:%S')
	print(f'AnyRouter Check-in | {now}')
	print('=' * 50)

	app_config = AppConfig.load_from_env()
	accounts = load_accounts_config()
	if not accounts:
		log('FAIL', 'No account configuration found, exiting')
		sys.exit(1)

	log('INFO', f'{len(accounts)} account(s), {len(app_config.providers)} provider(s)')

	last_balance_hash = load_balance_hash()

	success_count = 0
	total_count = len(accounts)
	notification_content = []
	current_balances = {}
	account_check_in_details = {}  # 存储每个账号的签到详情
	account_results: list[dict] = []  # 记录每个账号的结果，用于生成 summary
	need_notify = False  # 是否需要发送通知
	balance_changed = False  # 余额是否有变化

	for i, account in enumerate(accounts):
		account_key = f'account_{i + 1}'
		try:
			success, user_info_before, user_info_after = await check_in_account(account, i, app_config)
			if success:
				success_count += 1

			# 记录账号结果
			account_results.append(
				{
					'name': account.get_display_name(i),
					'success': success,
					'provider': account.provider,
				}
			)

			should_notify_this_account = False

			if not success:
				should_notify_this_account = True
				need_notify = True

			# 存储签到前后的余额信息
			if user_info_after and user_info_after.get('success'):
				current_quota = user_info_after['quota']
				current_used = user_info_after['used_quota']
				current_balances[account_key] = {'quota': current_quota, 'used': current_used}

				# 计算签到收益
				if user_info_before and user_info_before.get('success'):
					before_quota = user_info_before['quota']
					before_used = user_info_before['used_quota']
					after_quota = user_info_after['quota']
					after_used = user_info_after['used_quota']

					# 计算总额度（余额 + 历史消耗）
					total_before = before_quota + before_used
					total_after = after_quota + after_used

					# 签到获得的额度 = 总额度增加量
					check_in_reward = total_after - total_before

					# 本次消耗 = 历史消耗增加量
					usage_increase = after_used - before_used

					# 余额变化
					balance_change = after_quota - before_quota

					account_check_in_details[account_key] = {
						'name': account.get_display_name(i),
						'before_quota': before_quota,
						'before_used': before_used,
						'after_quota': after_quota,
						'after_used': after_used,
						'check_in_reward': check_in_reward,  # 签到获得
						'usage_increase': usage_increase,  # 本次消耗
						'balance_change': balance_change,  # 余额变化
						'success': success,
					}

			if should_notify_this_account:
				account_name = account.get_display_name(i)
				status = '[SUCCESS]' if success else '[FAIL]'
				account_result = f'{status} {account_name}'
				if user_info_after and user_info_after.get('success'):
					account_result += f'\n  Balance: ${user_info_after["quota"]}, Used: ${user_info_after["used_quota"]}'
				elif user_info_after:
					account_result += f'\n  {user_info_after.get("error", "Unknown error")}'
				notification_content.append(account_result)

		except Exception as e:
			account_name = account.get_display_name(i)
			log('FAIL', f'Exception: {str(e)[:80]}', account_name)
			need_notify = True  # 异常也需要通知
			notification_content.append(f'[FAIL] {account_name} exception: {str(e)[:50]}...')
			account_results.append(
				{
					'name': account_name,
					'success': False,
					'provider': account.provider,
					'error': str(e)[:50],
				}
			)

	# 汇总
	print(f'\n{"=" * 50}')
	log('INFO', f'Result: {success_count}/{total_count} succeeded')

	# 检查余额变化
	current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
	if current_balance_hash:
		if last_balance_hash is None:
			# 首次运行
			balance_changed = True
			need_notify = True
			log('INFO', 'First run, will notify with current balances')
		elif current_balance_hash != last_balance_hash:
			# 余额有变化
			balance_changed = True
			need_notify = True
			log('INFO', 'Balance changed, will notify')
		else:
			log('INFO', 'No balance changes')

	# 为有余额变化的情况添加所有成功账号到通知内容
	if balance_changed:
		for i, account in enumerate(accounts):
			account_key = f'account_{i + 1}'
			if account_key in account_check_in_details:
				detail = account_check_in_details[account_key]
				account_name = detail['name']

				# 使用格式化函数生成通知消息
				account_result = format_check_in_notification(detail)

				# 检查是否已经在通知内容中（避免重复）
				if not any(account_name in item for item in notification_content):
					notification_content.append(account_result)

	# 保存当前余额hash
	if current_balance_hash:
		save_balance_hash(current_balance_hash)

	if need_notify and notification_content:
		# 构建通知内容
		summary = [f'Result: {success_count}/{total_count} succeeded']
		if success_count == total_count:
			summary.append('All accounts check-in successful!')
		elif success_count > 0:
			summary.append('Some accounts failed')
		else:
			summary.append('All accounts failed')

		time_info = f'Time: {datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")}'

		notify_content = '\n\n'.join([time_info, '\n'.join(notification_content), '\n'.join(summary)])

		notify.push_message('AnyRouter Check-in Alert', notify_content, msg_type='text')
		log('INFO', 'Notification sent')
	else:
		log('INFO', 'All succeeded, no balance changes, notification skipped')

	# 生成 CI Summary
	generate_ci_summary(account_results, account_check_in_details, current_balances, success_count, total_count)

	# 设置退出码
	sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\nInterrupted')
		sys.exit(1)
	except Exception as e:
		log('FAIL', f'Unexpected error: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
