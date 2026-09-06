import re
import urllib.request

# 规则源列表
SOURCES = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt",
    "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/master/rule.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt"
]

def fetch_rules(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.read().decode('utf-8', errors='ignore').splitlines()
    except Exception as e:
        print(f"[!] 下载失败: {url}, 错误: {e}")
        return []

def parse_adguard_rules(lines):
    domain_exact = set()
    domain_suffix = set()
    domain_regex = set()

    for line in lines:
        line = line.strip()
        # 1. 忽略注释、空行、AdGuard 特有修饰符（如 $third-party, $important, ## 元素阻断等）
        if not line or line.startswith('!') or line.startswith('#') or '##' in line or '#@#' in line or '#?#' in line:
            continue

        # 剥离规则尾部的修饰符 (例如 $script,image,domain=...)
        if '$' in line:
            line = line.split('$')[0].strip()
            if not line:
                continue

        # 2. 处理纯正则匹配: /^admaster\./ -> DOMAIN-REGEX
        if line.startswith('/') and line.endswith('/'):
            regex_pattern = line[1:-1]
            if regex_pattern:
                domain_regex.add(regex_pattern)
            continue

        # 3. 处理 ||example.org^ 形式
        if line.startswith('||'):
            # 去除末尾的 ^ 或 /
            core = line[2:].rstrip('^/')
            
            # 排除带 * 等通配符的复杂域名 (例如 ||*-ad.a.yximgs.com^)
            if '*' in core or '?' in core:
                continue

            # 验证提取到的域名格式有效性
            if core and re.match(r'^[a-zA-Z0-9.\-_]+$', core):
                domain_suffix.add(core.lower())
            continue

        # 4. 处理 |https:// 或 |http:// 精确域名/地址
        if line.startswith('|http://') or line.startswith('|https://'):
            core = line.split('://')[-1].split('/')[0].rstrip('^')
            if '*' not in core and re.match(r'^[a-zA-Z0-9.\-_]+$', core):
                domain_exact.add(core.lower())
            continue

        # 5. 处理简单纯域名形式 (如 example.org)
        core = line.rstrip('^/')
        if '*' not in core and re.match(r'^[a-zA-Z0-9.\-_]+\.[a-zA-Z]{2,}$', core):
            domain_suffix.add(core.lower())

    # 去重处理：如果顶级域名已经在 suffix 中，移除多余的 exact 项
    final_exact = {d for d in domain_exact if not any(d.endswith('.' + s) or d == s for s in domain_suffix)}

    return sorted(domain_suffix), sorted(final_exact), sorted(domain_regex)

def main():
    all_lines = []
    for url in SOURCES:
        print(f"正在读取: {url}")
        all_lines.extend(fetch_rules(url))

    suffixes, exacts, regexes = parse_adguard_rules(all_lines)

    # 格式化导出为 Mihomo / Nikki 识别的标准 text 规则集文本
    output_lines = ["payload:"]
    for s in suffixes:
        output_lines.append(f"  - DOMAIN-SUFFIX,{s}")
    for e in exacts:
        output_lines.append(f"  - DOMAIN,{e}")
    for r in regexes:
        output_lines.append(f"  - DOMAIN-REGEX,{r}")

    with open("adblock_parsed.yaml", "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines))

    print(f"解析完成: 提取 DOMAIN-SUFFIX {len(suffixes)} 条, DOMAIN {len(exacts)} 条, DOMAIN-REGEX {len(regexes)} 条。")

if __name__ == "__main__":
    main()
