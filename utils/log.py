"""日志和脱敏工具"""


def mask(value: str) -> str:
	"""对用户名/邮箱脱敏，保留前几位，中间用 *** 替代"""
	if '@' in value:
		local, domain = value.rsplit('@', 1)
		masked_local = local[:3] + '***' if len(local) > 3 else local[0] + '***'
		return f'{masked_local}@{_mask_host(domain)}'

	# 普通用户名
	if len(value) > 5:
		return value[:3] + '***' + value[-2:]
	if len(value) > 1:
		return value[0] + '***'
	return '***'


def _mask_host(host: str) -> str:
	"""对邮箱域名脱敏，只 mask 主域名部分，保留后缀"""
	parts = host.split('.')
	if len(parts) <= 1:
		return host[0] + '***' if host else '***'

	# 识别后缀（.com, .org, .edu.cn, .co.jp 等）
	known_second_tlds = {'edu', 'com', 'co', 'org', 'net', 'gov', 'ac'}
	if len(parts) >= 3 and parts[-2] in known_second_tlds:
		suffix = '.' + '.'.join(parts[-2:])
		name_parts = parts[:-2]
	else:
		suffix = '.' + parts[-1]
		name_parts = parts[:-1]

	# mask 主域名（最后一个 name_part）
	if name_parts:
		main = name_parts[-1]
		masked_main = main[:3] + '***' if len(main) > 3 else main[0] + '***'
		name_parts[-1] = masked_main

	return '.'.join(name_parts) + suffix


def log(level: str, msg: str, account: str = ''):
	"""统一日志输出"""
	prefix = f'{account} > ' if account else ''
	print(f'[{level}] {prefix}{msg}')
