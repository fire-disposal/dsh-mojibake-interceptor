# dsh-mojibake-interceptor — DeepSeek Harness 乱码拦截器

在 AI 把乱码写进文件**之前**打断，要求复查；若 AI 复查后仍执意（原样重试同一次写入）则放行。
纯**特征值/算法**检测——不维护任何关键词表。

```yaml
- insert:
    - id: mojibake-interceptor
      name: 'dsh-mojibake-interceptor'
      config:
        mode: warn
        resultWatchTools: [pwsh, bash, bash_persistent, read]
```

## 工作原理

### 两个挂载点

| 挂载点 | 事件 | 行为 |
|---|---|---|
| 写入前拦截 | `tools/pre-execute` | `write` / `edit` / `str_replace_editor` 的待写入文本，以及 `pwsh` / `bash` / `bash_persistent` 的**命令文本**，在落盘/执行前被扫描；命中乱码特征或危险编码则返回 `deny` 并附复查说明 |
| 输出监视 | `tools/post-execute` | `pwsh` / `bash` / `bash_persistent` / `read` 的捕获结果被扫描；输出本身乱码时注入一条通知，警告模型「别把这段输出抄进文件」（Windows 上最常见的污染源） |

### pwsh 命令执行前审计（Windows 批量乱码悲剧的主防线）

AI 用 pwsh 写文件/替换内容时，命令文本在**执行前**被双重检查：

1. **内容层**：命令内嵌文本直接跑全部乱码特征（`Set-Content -Value 'ä¸­æ–‡'`、heredoc 等执行前即命中）。
2. **编码层**（`pwshEncodingGuard: warn`，默认）：命中「写入原语 + 含非 ASCII 内容」时校验编码声明——
   - 危险编码（`-Encoding Default/ANSI/OEM/Unicode`、`[Text.Encoding]::Default`、`GetEncoding(936/950/…)`、`[Console]::OutputEncoding=`、`chcp` 非 65001）→ **严重**拦截；
   - 未声明编码（PS 5.1 `Set-Content` 默认 ANSI/GBK、`Out-File`/`>` 默认 UTF-16LE）→ **中等**拦截，提示显式 `-Encoding utf8`；
   - 知情编码（`-Encoding utf8`、`[Text.Encoding]::UTF8`、.NET `WriteAllText` 两参重载默认 UTF-8）→ 放行。
   - 纯 ASCII 命令永不触发编码审计；`if ($a > $b)` 的比较运算符不会被误判为重定向。

### 误报控制（正常操作不拦）

- **注释剥离**：`# 中文注释` / `<# 块注释 #>` 先剥离再审计，注释里的中文不会触发；
- **文件名豁免**：`-Path`/`-LiteralPath`/`-Destination` 等参数值、读取命令（`Get-Content 中文.txt`）后的中文文件名不算内容；
- **知情写法全识别**：`-Enc utf8` 参数缩写、`[System.Text.Encoding]::UTF8`、`[System.IO.File]::WriteAllText` 全限定类型名均视为安全；
- **非内容操作不审计**：`Set-Item`（环境变量/注册表）、`Copy-Item`/`Move-Item`/`Remove-Item`/`Rename-Item`、变量赋值（`$x = '你好'`）不触发；
- **刻意灰色地带**：`Set-Content 副本.txt` 这类**无引号位置参数**中文文件名在 PS 5.1 下确实按默认编码写入（可能乱码），会拦一次提示加 `-Encoding utf8`，重试即放行；
- 验证：`test/regression-normal.test.mjs` 覆盖正常中文文档、中英混排、日韩泰文、符号/数学/货币、西欧多语种、emoji、各类代码文件，以及十余条正常 pwsh/bash 命令，全部断言零误报（全套 72 项测试）。

### 复查→放行流程（`mode: warn`，默认）

1. 首次命中乱码特征 → 写入被 `deny`，模型看到复查消息（列出命中的特征与还原结果）。
2. AI 复查：
   - 修正编码 → 新内容重新检测，干净即放行；
   - 执意保留 → **原样重试同一次写入**（同一工具 + 路径 + 内容指纹）→ 放行。
3. `mode: block`：命中即永久拒绝（直到内容变化）；`mode: ask`：每次命中都走 harness 审批通道（人工裁决）。

指纹键是 `工具 + 路径 + 待写入文本`，因此「改一个字的乱码重试」会被当作新内容重新检测，不会绕过。

## 检测特征（算法，无关键词表）

所有信号均由字符统计或**编码回环校验**推导：

| 特征 | 说明 | 严重度 |
|---|---|---|
| `utf8-as-cp1252-cjk` | 拉丁段重编码 CP1252 → 严格 UTF-8 解码，还原出 CJK（`ä¸­æ–‡` → `中文`、`ï¼š` → `：`） | 严重 |
| `utf8-as-cp1252` | 同方向，还原出紧凑的非 ASCII 字符（`Ã©` → `é`、`Â©` → `©`、`â€™` → `’`） | 中等 |
| `gbk-as-cp1252` | 拉丁段重编码 CP1252 → 严格 GBK 解码还原常用汉字（`ÖÐÎÄ` → `中文`、`ÄúºÃ` → `你好`）；仅当解码出的汉字来自 GBK 常用区（前导字节 B0–F7）才触发，`……——` 等合法标点不会误报 | 严重 |
| `utf8-as-gbk` | CJK 段按 GBK 重编码 → 严格 UTF-8 解码还原原文（`涓枃` → `中文`） | 严重 |
| `utf8-as-big5` | 同上，Big5 方向 | 严重 |
| `gbk-misread-replacement` | GBK 段重编码后严格 UTF-8 解码得到 `U+FFFD` 串（经典 `锟斤拷`） | 严重 |
| `replacement-char` / `lone-replacement` | `U+FFFD` 替换符计数（无效 UTF-8 字节被替换） | 严重 / 中等 |
| `utf16-leak` | NUL 密度或 `ASCII+NUL` 连续对（PowerShell 5.1 `Out-File` 默认 UTF-16LE 的典型残留） | 严重 |
| `control-char` | NUL 及控制字符（排除 `\t\n\r`） | 严重 |
| `ansi-escape` | `ESC[…m` 颜色码残留（彩色控制台捕获） | 中等 |
| `bom-anomaly` | 文本中部出现 `U+FEFF` BOM | 中等 |
| `literal-unicode-escape` | `\u4e2d\u6587` 字面转义代替实际字符（代码/JSON 文件豁免） | 中等 |
| `html-numeric-entity` | `&#20013;` 数字实体代替实际字符（HTML/XML 文件豁免） | 中等 |
| `pwsh-unsafe-encoding` | pwsh 写入命令使用 ANSI/GBK/OEM/UTF-16 或固定代码页（`-Encoding Default`、`GetEncoding(936)`、`chcp`…） | 严重 |
| `pwsh-ambiguous-encoding` | pwsh 写入命令含非 ASCII 但未声明 `-Encoding utf8`（PS 5.1 默认 ANSI/UTF-16） | 中等 |

### 回环校验为什么可靠（特征值的核心）

一段文本若**真是**「UTF-8 字节被按 X 字符集误读」，把它按 X 重新编码，必然还原出原始合法 UTF-8 字节流；而任意单一编码的合法文本几乎不可能恰好通过这条回环（其 X 字节不是合法 UTF-8）。加上两条守卫进一步压缩误报：

- **紧凑性**：还原结果的非 ASCII 字符数必须少于原段（`Ã©`→`é` 收缩；`åå`→`åå` 不收缩，跳过）；
- **脚本一致性**：还原结果必须出现与原段不同的脚本（CJK/全角），或落在 GBK 常用汉字区。

## 性能模型

1. **门控正则**：一条 `/[\u0080-\uFFFF]|控制字符|\\uXXXX|&#…/` 单趟扫描——纯 ASCII/无转义内容直接返回（1 MB 纯 ASCII ≈ 2 ms）。
2. **分阶段止损**：`maxFindings`、`maxRunChars`（每段回环字符上限，默认 2048）、`maxRuns`（每方向段数上限，默认 64）三重封顶；GBK/Big5 方向仅在文本含 CJK 时启用。
3. **懒加载 + 预热**：iconv-lite 在插件 `apply` 时后台预热，首个命中调用不承担模块加载成本；缺失时优雅降级（CP1252/统计特征不受影响，仅打一行日志）。
4. **有界内存**：拦截状态表上限 4096 条（超出即清空）。

## 配置

| 键 | 默认 | 说明 |
|---|---|---|
| `mode` | `warn` | `warn` 先拦一次、原样重试放行；`block` 永拒；`ask` 走人工审批 |
| `tools` | `[write, edit, str_replace_editor, pwsh, bash, bash_persistent]` | 扫描写入载荷/命令的工具 |
| `resultWatchTools` | `[pwsh, bash, bash_persistent, read]` | 扫描输出结果的通知工具 |
| `pwshEncodingGuard` | `warn` | `warn` 执行前审计 pwsh 写入编码；`off` 只查内容乱码、不查编码声明 |
| `minSeverity` | `moderate` | `severe` 时忽略中等特征 |
| `excludePaths` | `[]` | 路径 `*` 通配排除（本机已排除插件自身文档 `*dsh-mojibake-interceptor*`） |
| `maxFindings` | `8` | 发现数上限 |
| `maxRunChars` | `2048` | 每段回环字符上限 |
| `maxRuns` | `64` | 每方向段数上限 |
| `maxPreviewChars` | `80` | 复查消息中的预览宽度 |

## 安装（web profile）

bundle 版（≥0.2.0）一行安装，装完即激活：

```sh
dsh plugin --profile web add dsh-mojibake-interceptor
```

手动接线（0.1.0 或源码方式）：把包放进 profile 依赖树，在
`$DSH_HOME/profiles/<name>/cordis.patch.yml` 追加：

```yaml
- insert:
    - id: mojibake-interceptor
      name: 'dsh-mojibake-interceptor'
      config:
        mode: warn
```

重启 `dsh web` 生效。停用：`dsh plugin --profile web remove dsh-mojibake-interceptor`（bundle 方式）或删除 patch 条目（手动方式）。

## 测试

```sh
pnpm --dir dsh-plugins/dsh-mojibake-interceptor test
# 或
node --test dsh-plugins/dsh-mojibake-interceptor/test/*.test.mjs
```

37 项用例：中文/西文/标点/emoji 干净文本零误报；UTF-8↔CP1252/GBK/Big5 全部方向、UTF-16、替换符、ANSI、BOM、字面转义、实体转义命中；1 MB ASCII 与 200 KB 中文性能冒烟。

## 已知限制

- 文本已进入会话上下文后的「写入前」拦截依赖 payload 扫描；通过 `run_code` 或原始 `ctx.fs` 的绕过式写入不在覆盖内（`tools` 列表可扩展，但那些入口无结构化文本载荷）。
- GBK 扩展区字符、生僻字构成的乱码若回环到常用区之外可能漏报（`gbk-as-cp1252` 方向为此刻意收紧）。
- 状态表为内存态，会话恢复后重置（与 `repeat-tool-reminder` 同策略）。
- 二进制文件（非 UTF-8 文本）不在覆盖范围。
