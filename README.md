# NOVA

NOVA 是一个轻量级、AI 辅助的 Web 安全审计 CLI。当前版本采用受控主动扫描的 MVP 设计：先探测目标，再在授权边界内爬取页面，随后由本地规则验证风险，并让 LLM 生成仅用于报告的候选 payload。

请只扫描你已经获得授权的目标。NOVA 不做爆破、不绕过登录、不提交未知业务状态变更表单，也不会把 LLM 候选 payload 自动发送到目标。

## 功能概览

- 目标探测：DNS、TLS、HTTP 状态码、最终 URL、跳转链、认证需求和登录页信号。
- 受控爬取：默认只扫描同源 URL，限制深度、页面数、速率和危险路径。
- 输入点识别：提取链接、表单、GET 参数、Cookie、响应头、页面标题和响应摘要。
- 本地审计：规则位于 `backend/helper/vuln_rules/`，证据构造位于 `backend/helper/evidence/`，便于继续扩展漏洞类型。
- 安全主动验证：仅对 GET 参数做轻量 SQLi、SQL 盲注、XSS、LFI/目录穿越和命令注入 echo 标记验证；对 DVWA `weak_id` 这类明确的 Generate 表单，会执行受限的同页空/Generate POST 来读取 `Set-Cookie` 证据。
- 信息泄露与配置：检测安全响应头缺失、Cookie 属性缺失、CSRF Token 缺失、Server/X-Powered-By、错误栈、调试页和绝对路径泄露。
- CSRF 识别：POST 状态变更表单缺 Token 记为疑似；GET 改密码/保存/更新类表单缺 Token 记为确认风险，适配 DVWA CSRF 页面。
- 扩展规则：默认检测开放重定向、CSP 弱配置、JavaScript 暴露、弱会话标识和被动密码学弱点。
- 高风险候选：SSRF、存储型 XSS、文件上传默认只做候选/疑似；显式开启后才做 callback、表单提交或 harmless 文件上传验证。
- 候选 payload：LLM 和本地上下文模板可生成建议 payload，但必须经过本地 Safety Filter，且只写入报告。
- 中文报告：每次扫描生成新的 Markdown/JSON 报告，文件名格式为 `漏洞名称_扫描日期.md/json`，例如 `命令注入_20260530_143000.md`。

## 工作流

```text
main.py
  -> TargetProbe Agent
  -> .Nova/TargetProbe_agent.json
  -> Webscanner Agent
  -> .Nova/Webscan_agent.json
  -> Auditor Agent
  -> .Nova/Auditor_agent.json
  -> reports/扫描日期/
      -> 漏洞名称_扫描日期.json
      -> 漏洞名称_扫描日期.md
```

## 安装

```bash
pip install -r requirements.txt
```

可选：配置 LLM。NOVA 使用 OpenAI-compatible `/chat/completions` 接口，默认模型名为 `deepseekV4-flash`。

在 `backend/helper/config/.env` 中配置：

```text
LLM_BASEURL=https://api.deepseek.com/chat/completions
LLM_APIKEY=your_api_key
LLM_MODEL=deepseekV4-flash
LLM_PROVIDER=deepseek
```

LLM 未配置或调用失败时，扫描和报告仍会继续完成。

## 使用

公开页面扫描：

```bash
python main.py --url https://example.com
```

携带登录态 Cookie：

```bash
python main.py --url http://127.0.0.1/DVWA/vulnerabilities/sqli/ --cookie "PHPSESSID=your_value; security=low"
```

携带 Authorization Header：

```bash
python main.py --url https://example.com/admin --header "Authorization: Bearer your_token"
```

HTTP Basic Auth：

```bash
python main.py --url https://example.com --basic-user user --basic-pass pass
```

## 认证访问

NOVA 第一版优先支持用户提供登录态：

- `--cookie "SESSION=..."`
- `--header "Authorization: Bearer ..."`
- `--basic-user` / `--basic-pass`
- `NOVA_AUTH_HEADERS_FILE=auth_headers.json`

所有认证信息只在内存请求中使用。写入 `.Nova/*.json` 和 `reports/*.md` 时只保留脱敏摘要，不写入明文 Cookie、Token 或密码。

## 候选 Payload 与 Safety Filter

NOVA 支持两类候选 payload 来源：

- `local_template`：本地上下文模板，根据 URL、参数名、输入类型和发现项生成。
- `local_progression_template`：漏洞已经由本地规则确认后，根据响应证据生成只读推进候选，例如 SQLi 的列数、UNION 回显位、库名/表名/字段名枚举参考。
- `llm`：由 LLM 根据页面上下文、输入点和已有 findings 生成。
- `llm_progression`：漏洞已经确认后，由 LLM 基于确认漏洞证据生成后续推进候选。

候选 payload 第一版仅写入报告，不自动执行，也不参与漏洞确认。所有候选必须经过本地 Safety Filter。

如果 LLM 可用，报告会额外生成 `## LLM PoC 与授权验证流程` 章节。该章节只展示来源为 `llm` 或 `llm_progression` 的 AI 内容，包括 LLM PoC 标题、PoC payload、预期现象、授权验证流程、使用建议和风险提示。这些内容仍然是“报告型建议”：NOVA 不会自动执行 LLM PoC，也不会把 LLM 输出作为漏洞确认依据。验证流程会经过本地文本过滤，包含提权、持久化、批量攻击、数据导出、绕过认证、反弹 shell、写文件、删除文件等高风险内容的步骤会被过滤或摘要化。

报告和 JSON 会同时保留机器可读的 `category` 以及中文 `category_label` / `category_group`，例如 `sqli` 会显示为“SQL 注入（错误回显/UNION）”，`sqli_blind` 会显示为“SQL 盲注（布尔型）”。Markdown 报告会先给出“漏洞类型汇总”，再按类型分组展示发现项；默认展示确认漏洞和可验证候选，隐藏普通配置建议和扫描提示。

Safety Filter 会阻止危险 payload，例如：

- `DROP`、`DELETE`、`UPDATE`、`INSERT`、`ALTER`、`TRUNCATE`
- `INTO OUTFILE`
- `LOAD_FILE`
- `xp_cmdshell`
- 反弹 shell
- 写文件或删除文件
- 长时间 `SLEEP` 或 `BENCHMARK`

SQL 盲注必须比较 true/false 成对响应差异。只看到单条 payload 返回 `User ID exists in the database.` 不能证明 SQL 盲注成立。报告会把盲注候选按 true/false 成对展示，例如：

```text
true:  1' AND '1'='1' #
false: 1' AND '1'='2' #
```

人工复核时应比较两次响应的状态码、响应长度、关键文本或页面结构差异。

## 安全边界

- 默认只扫描用户提供 URL 的同源范围：协议、主机和端口必须一致。
- TargetProbe 如果发现最终跳转到不同 host，默认停止扫描；只有该 host 出现在 `NOVA_ALLOWED_HOSTS` 时才继续。
- 默认不做子域名爆破、不爆破、不上传文件、不做目录大字典扫描。
- 默认不提交未知 POST/PUT/PATCH/DELETE 业务表单。
- 主动验证主要限于已有 GET 参数和 GET 表单；例外是 DVWA `weak_id` 的 Generate 表单，NOVA 只提交同页空/Generate 请求并读取响应 Cookie，不提交业务字段。
- 命令注入默认只执行短 `echo NOVA_CMD` 标记探测；可通过 `NOVA_COMMAND_INJECTION_PROBES=false` 关闭。
- SSRF、存储型 XSS、文件上传默认不触发服务端外连、POST 提交或文件上传。
- 默认排除 `/logout`、`/signout`、`/delete`、`/remove` 等危险路径。
- 爬取去重按路径和参数名处理，不把反射参数值变化当成无限新页面，避免 XSS 反射页面反复入队。
- 所有漏洞确认必须有本地请求/响应证据；LLM 只能提供解释、修复建议和候选 payload。

## 配置项

运行时环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `NOVA_MAX_PAGES` | `10` | 最大爬取页面数 |
| `NOVA_MAX_DEPTH` | `1` | BFS 爬取深度 |
| `NOVA_MAX_LINKS` | `30` | 每个页面保留的最大链接和脚本数量 |
| `NOVA_REQUEST_TIMEOUT` | `10` | 目标 HTTP 请求超时时间，单位秒 |
| `NOVA_RATE_LIMIT` | `0.2` | 爬虫请求间隔，单位秒 |
| `NOVA_ACTIVE_SCAN` | `true` | 是否启用安全 GET 参数探测 |
| `NOVA_ACTIVE_REQUEST_TIMEOUT` | `3.0` | 主动探测单个 payload 请求超时，单位秒 |
| `NOVA_MAX_ACTIVE_INPUTS` | `5` | 单次扫描最多主动探测的输入点数量 |
| `NOVA_COMMAND_INJECTION_PROBES` | `true` | 是否启用非破坏性命令注入 echo 标记探测 |
| `NOVA_OPEN_REDIRECT_PROBES` | `true` | 是否启用开放重定向 GET 参数探测 |
| `NOVA_FETCH_SAME_ORIGIN_SCRIPTS` | `true` | 是否抓取同源 JavaScript 用于静态分析 |
| `NOVA_MAX_SCRIPT_BYTES` | `200000` | 单个 JS 文件最多读取字节数 |
| `NOVA_SSRF_CALLBACK_URL` | 空 | SSRF callback 验证 URL；为空时只生成候选/疑似 |
| `NOVA_STORED_XSS_PROBES` | `false` | 是否允许提交带 nonce 的存储型 XSS 测试表单 |
| `NOVA_FILE_UPLOAD_PROBES` | `false` | 是否允许上传 harmless 文本文件做文件上传验证 |
| `NOVA_FOCUS_TARGET_PATH` | `true` | 是否只对目标 URL 所在路径内的输入点做主动验证；可避免 DVWA 菜单页串扫到其它漏洞模块 |
| `NOVA_ALLOWED_HOSTS` | 空 | 额外允许扫描的主机列表，英文逗号分隔 |
| `NOVA_EXCLUDE_PATHS` | 空 | 排除路径前缀，英文逗号分隔 |
| `NOVA_AUTH_HEADERS_FILE` | 空 | 认证 Header JSON 文件 |
| `NOVA_BASIC_USER` | 空 | HTTP Basic Auth 用户名 |
| `NOVA_BASIC_PASS` | 空 | HTTP Basic Auth 密码 |
| `NOVA_LLM_ANALYSIS` | `true` | 是否启用 LLM 对 findings 的中文分析补充 |
| `NOVA_LLM_ON_LOCAL_TARGETS` | `true` | 是否允许对 localhost、127.0.0.1、内网地址调用 LLM；本地靶场默认可以使用 LLM 做候选 payload 迭代 |
| `NOVA_LLM_PAYLOAD_ADVISOR` | `true` | 是否启用候选 payload 生成 |
| `NOVA_LLM_PAYLOAD_MAX_PER_PARAM` | `5` | 每个参数最多保留的候选数量 |
| `NOVA_LLM_PAYLOAD_MAX_TOTAL` | `10` | LLM/LLM progression 候选 payload 总量上限；优先保留关键推进候选 |
| `NOVA_LLM_PAYLOAD_REPORT_ONLY` | `true` | 候选 payload 是否仅报告。第一版按仅报告处理 |
| `NOVA_LLM_REQUEST_TIMEOUT` | `60` | LLM 单次调用超时时间，单位秒；上下文较大或模型较慢时可调到 `90` 或 `120` |
| `NOVA_LLM_REQUEST_RETRIES` | `2` | LLM 调用遇到临时 TLS/网络断开时的重试次数 |
| `NOVA_LLM_PROXY` | 空 | LLM 专用代理地址，例如 `http://127.0.0.1:7890`；当 `api.deepseek.com` 直连超时或被重置时使用 |
| `NOVA_REPORT_CONFIRMED_ONLY` | `true` | 报告是否过滤普通非确认项 |
| `NOVA_REPORT_VERIFIABLE_CANDIDATES` | `true` | 在过滤模式下是否仍展示 SSRF、存储型 XSS、文件上传等可验证候选 |

## 输出文件

运行后会生成：

- `.Nova/TargetProbe_agent.json`
- `.Nova/Webscan_agent.json`
- `.Nova/Auditor_agent.json`
- `reports/扫描日期/漏洞名称_扫描日期.json`
- `reports/扫描日期/漏洞名称_扫描日期.md`

报告文件会先进入以扫描时间命名的新文件夹；如果同一秒内生成同名文件夹，NOVA 会自动追加 `_2`、`_3` 等序号。每个文件夹内保存本次扫描的 Markdown 和 JSON 报告。这些运行产物已在 `.gitignore` 中忽略，不会提交到仓库。

## DVWA 示例

先在浏览器登录 DVWA，复制 Cookie，然后运行：

```bash
python main.py --url http://127.0.0.1/DVWA/vulnerabilities/sqli/ --cookie "PHPSESSID=your_value; security=low"
python main.py --url http://127.0.0.1/DVWA/vulnerabilities/sqli_blind/ --cookie "PHPSESSID=your_value; security=low"
python main.py --url http://127.0.0.1/DVWA/vulnerabilities/xss_r/ --cookie "PHPSESSID=your_value; security=low"
python main.py --url http://127.0.0.1/DVWA/vulnerabilities/fi/?page=include.php --cookie "PHPSESSID=your_value; security=low"
python main.py --url http://127.0.0.1/DVWA/vulnerabilities/exec/ --cookie "PHPSESSID=your_value; security=low"
python main.py --url http://127.0.0.1/DVWA/vulnerabilities/weak_id/ --cookie "PHPSESSID=your_value; security=low"
python main.py --url http://127.0.0.1/DVWA/vulnerabilities/javascript/ --cookie "PHPSESSID=your_value; security=low"
python main.py --url http://127.0.0.1/DVWA/vulnerabilities/open_redirect/ --cookie "PHPSESSID=your_value; security=low"
python main.py --url http://127.0.0.1/DVWA/vulnerabilities/csp/ --cookie "PHPSESSID=your_value; security=low"
python main.py --url http://127.0.0.1/DVWA/vulnerabilities/captcha/ --cookie "PHPSESSID=your_value; security=low"
```

如果登录态有效，NOVA 会识别 DVWA 页面中的 GET 表单参数，并尝试用本地规则验证 SQLi、XSS、LFI/目录穿越、命令注入或弱会话 ID 生成风险。候选 payload 会写入报告，但不会自动执行。

扫描 DVWA 单个漏洞页面时，默认 `NOVA_FOCUS_TARGET_PATH=true`，所以例如扫描 `/vulnerabilities/xss_d/` 时，NOVA 不会主动测试左侧菜单里的 `/brute/`、`/sqli/` 等其它模块，避免报告被其它靶场漏洞“抢占”。如果你确实要做同源多页面扫描，可以设置 `NOVA_FOCUS_TARGET_PATH=false`。

反射型 XSS 页面会使用非破坏性 GET payload 做主动验证。如果 `<script>alert('NOVA_XSS')</script>` 或属性逃逸类 payload 以未编码形式回显，NOVA 会把该输入点报告为“确认存在反射型 XSS”；如果只是普通文本反射或上下文无法判断，则只保留为疑似风险。

DOM XSS 页面不会通过普通 HTTP 客户端执行 JavaScript。NOVA 对 `/xss_d/` 这类页面使用轻量 source-to-sink 静态规则：当 URL 参数进入 `document.location/location.href` 并写入 `document.write/innerHTML` 等 sink 时，报告为“DOM 型跨站脚本 XSS”。

LFI/目录穿越只会对 `file/path/page/template/include` 等路径型 GET 参数尝试只读探测，并以 `/etc/passwd` 或 `win.ini` 这类稳定特征作为确认依据。命令注入只会对 `cmd/command/ip/host/ping/target` 等命令型参数发送短 `echo NOVA_CMD` 标记 payload，只有响应中出现唯一标记才确认。对 DVWA `/exec/` 这类明确的命令注入靶场表单，NOVA 也会提交同源 POST 的短 `echo NOVA_CMD` 标记验证，不执行删除、写文件、下载或反弹 shell 等危险命令。

开放重定向会对 `url/next/redirect/return/callback/continue` 等 GET 参数使用 `https://nova.invalid/redirect-check` 做无副作用跳转验证。SSRF 只在配置 `NOVA_SSRF_CALLBACK_URL` 后主动验证；未配置时仅报告候选输入点。存储型 XSS 和文件上传默认也只报告候选表单，避免污染业务数据或留下文件。

DVWA Open Redirect 页面里的漏洞入口是带 `redirect` 参数的链接，不是表单。NOVA 会把同源链接上的查询参数也建模为输入点，并尝试完整 URL、协议相对 URL 等安全外部跳转候选；只有响应 `Location` 离开当前 host 时才确认开放重定向。

DVWA JavaScript 页面属于客户端校验绕过。NOVA 会识别 `phrase/token` 表单，使用本地规则计算 low/medium/high 三类 token 并提交 `phrase=success` 做验证；只有响应出现 `Well done!` 才报告为“确认存在 JavaScript 客户端校验绕过”。

DVWA CSP 页面属于 CSP Bypass challenge。NOVA 会识别 `include` 表单和 CSP 响应头：low 级别验证白名单外部脚本是否能被用户控制为 `script src`，medium 级别验证 nonce 是否可被复用，high 级别验证同源 JSONP callback 是否可控。只有响应中出现对应可执行脚本证据时才报告为确认漏洞。

DVWA CAPTCHA 页面属于 Insecure CAPTCHA 流程绕过。NOVA 会识别 `password_new/password_conf/step/Change` 这类改密码流程字段，以及 low/medium/high 中可手工复现的绕过信号，并在报告里给出手工 PoC；为了避免真实修改密码，NOVA 不会自动提交这些 PoC，也不会把它们写成“已执行 payload”。

DVWA CSRF 页面通常是 GET 改密码表单。NOVA 不会提交该表单，但会根据 `password_new/password_conf/Change` 等状态变更字段和缺失 Token 证据，将其报告为“确认存在 GET 状态变更 CSRF 风险”。

确认 CSRF 后，报告的“候选 Payload”章节会额外给出仅供手工验证的 PoC 候选，例如带占位密码的 GET URL 和 `<img src="...">` 触发片段。它们用于说明“浏览器可在受害者登录态下跨站发起状态变更请求”，NOVA 不会自动访问这些 PoC。

本地靶场如果响应较慢或某些 payload 触发长时间等待，可以收紧主动探测预算：

```bash
set NOVA_ACTIVE_REQUEST_TIMEOUT=1
set NOVA_MAX_ACTIVE_INPUTS=2
python main.py --url http://127.0.0.1/sqli-labs-master/Less-1/
```

Linux/macOS 使用：

```bash
NOVA_ACTIVE_REQUEST_TIMEOUT=1 NOVA_MAX_ACTIVE_INPUTS=2 python main.py --url http://127.0.0.1/sqli-labs-master/Less-1/
```

对 sqli-labs Less-1 这类错误回显 SQLi 关卡，建议带上参数入口：

```bash
python main.py --url http://127.0.0.1/sqli-labs-master/Less-1/?id=1
```

确认 SQLi 后，NOVA 会继续做授权靶场内的轻量后续验证，包括 `ORDER BY` 列数探测和 `UNION SELECT` 回显标记探测，并把实际执行过的 payload 写入确认漏洞。

如果确认结果中拿到了列数和回显位，报告的“候选 Payload”章节还会给出推进型参考，例如读取当前库名、数据库版本、当前用户、当前库表名和字段名的只读 `UNION SELECT` 候选。LLM 可用且目标允许调用时，NOVA 会额外调用 LLM 生成 `llm_progression` 候选；这些候选仍然只写入报告，不会自动执行，也不能替代本地响应证据。

对 sqli-labs Less-1 这类 MySQL 单引号字符串型注入，NOVA 会使用可复制的 `-- -` 注释后缀，例如：

```text
-1' UNION SELECT 1,database(),3 -- -
```

不要把后缀简化成 `--`。MySQL 的 `--` 注释需要后面跟空白字符；如果注释没有生效，原始 SQL 后面的 `LIMIT 0,1` 会继续拼接，常见报错就是 `near '' LIMIT 0,1`。

本地靶场现在默认允许 LLM 调用。如果你不希望把本地目标上下文发送给 LLM，可以显式关闭：

```bash
set NOVA_LLM_ON_LOCAL_TARGETS=false
```

## 手动运行单个 Agent

```bash
python -m backend.helper.agent probe --url https://example.com
python -m backend.helper.agent scan --url https://example.com --probe .Nova/TargetProbe_agent.json
python -m backend.helper.agent audit --input .Nova/Webscan_agent.json
python -m backend.helper.agent report --probe .Nova/TargetProbe_agent.json --webscan .Nova/Webscan_agent.json --input .Nova/Auditor_agent.json
```

## 测试

```bash
python -m pytest -q
```
