# dsh-mojibake-interceptor

给 DeepSeek Harness 装的乱码拦截插件：AI 把乱码写进文件之前先拦一次，让它复查；当前版本 0.3.0，对齐 DSH 0.2.2-alpha.2 插件协议。

**状态**：可用；**要求**：Node `>=24.9.0`、DSH `>=0.2.2-alpha.2 <0.3.0`；**仓库**：[fire-disposal/dsh-mojibake-interceptor](https://github.com/fire-disposal/dsh-mojibake-interceptor)

## 本质

在写入前拦截乱码、靠字符统计与编码回环判断的 DeepSeek Harness 插件。

## 选型

基于 Cordis 的 DeepSeek Harness 插件，纯 JS ESM，运行依赖 iconv-lite，测试 Node runner。

- 插件框架
  - DeepSeek Harness
    - Cordis 4
    - @deepseek-ai/dsh-tools
    - @deepseek-ai/schemastery
- 核心
  - 原生 JS
  - iconv-lite
- 测试
  - node:test
- 分发
  - npm
  - cordis.patch.yml

## 功能

- `tools/pre-execute`：扫 `write` / `edit` / `str_replace_editor` / `apply_patch` 的待写入文本，以及 `pwsh` / `bash` / `terminal_send` 的命令文本，命中就 `deny` 并附上特征与还原结果；补丁只扫新增行，不拦修复乱码时保留的旧行
- `tools/post-execute`：扫 `pwsh` / `bash` / `terminal_open` / `terminal_send` / `terminal_read` / `job_output` / `read` 的捕获结果，输出乱码时注入通知
- pwsh 写入编码审计：危险编码（`-Encoding Default/ANSI/OEM/Unicode`、`GetEncoding(936)`、`chcp` 非 65001）严重拦截；含非 ASCII 却没声明 `-Encoding utf8` 的按中等拦截
- 16 类检测特征，覆盖 UTF-8↔CP1252/GBK/Big5 双向误读、UTF-16 残留、替换符、ANSI 转义、BOM 异常、字面转义与 HTML 实体
- 三档模式 `warn` / `block` / `ask`，SHA-256 指纹键是「工具 + 路径 + 待写入文本」，LRU 表封顶 4096 条，不长期保留原始写入内容
- 性能：门控正则先挡掉纯 ASCII（1 MB 约 2 ms），候选段按 `maxRunChars` 2048 / `maxRuns` 64 / `maxFindings` 8 止损
- 测试 85 项全过（含 1 MB ASCII、200 KB 中文性能冒烟与最新工具协议行为）

## 启动流程

```sh
# 从 GitHub 安装；bundle 安装后重启 dsh web
dsh plugin --profile web add "github:fire-disposal/dsh-mojibake-interceptor#main"

# 本地开发（替换为实际绝对路径）
dsh plugin --profile web add link:/absolute/path/to/dsh-mojibake-interceptor

# 检查 bundle 已进入组合树
dsh --profile web --dump-config

dsh plugin --profile web remove dsh-mojibake-interceptor

npm install
npm test
```

`package.json` 用 `engines.dsh` 声明运行时装载兼容范围，`dsh.bundle.patch` 指向 `cordis.patch.yml`。用户可在 profile 的 `cordis.patch.yml` 覆盖 `mojibake-interceptor` 行；注意 `config` 是整行替换，不是深合并。

配置项：`mode`、`tools`、`resultWatchTools`、`pwshEncodingGuard`、`minSeverity`、`excludePaths`、`maxFindings`、`maxRunChars`、`maxRuns`、`maxPreviewChars`。

## 边界与已知问题

- 拦截只在有结构化文本载荷的工具上生效；`run_code`、`ctx.fs` 这类入口拿不到待写入的纯文本，`tools` 列表也扩不过去。
- 缺 `iconv-lite` 时运行时会自动降级（CP1252 与统计特征照常，GBK/Big5 方向失效），但测试不降级：不装依赖跑，`regression-normal` 里 5 项会失败。
- GBK 扩展区、生僻字构成的乱码，回环到常用区之外可能漏报（`gbk-as-cp1252` 为压误报刻意收紧）。
- 状态表在内存里，会话恢复后清空，「拦一次再放行」的记忆也随之丢失。
