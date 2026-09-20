# @dsh-ext/remote — dsh web 远程访问插件集

[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (dsh) web profile 的两个配套本地插件，
让浏览器 GUI 能经公网域名（反向隧道 → 本机）访问，可选叠加账号/密码门。

| 子目录 | 包名 | 作用 |
| --- | --- | --- |
| [`remote-access/`](remote-access) | `@dsh-ext/remote-access` | 去掉启动 token 要求，保留 Host/来源围栏，让远程域名免 token 打开 GUI |
| [`remote-auth/`](remote-auth) | `@dsh-ext/remote-auth` | 在 remote-access 之上叠加 Basic 账号/密码门（远程来源必须带凭证；loopback 默认豁免） |

两个包互相独立、可按需单独安装；remote-auth 依赖 remote-access 的围栏作为内层，
安装顺序 remote-access 先、remote-auth 后。

## 安装

```sh
# 1. 把两个包加入 web profile 依赖（link: 形式）
cd ~/.dsh/profiles/web
node <pnpm-global-root>/dsh plugin add <this-repo>/remote-access
node <pnpm-global-root>/dsh plugin add <this-repo>/remote-auth

# 2. 把各自 patches/cordis.patch.yml 里的条目追加进 ~/.dsh/profiles/web/cordis.patch.yml
#    （remote-auth 行必须排在 remote-access 行之后）

# 3. 重启 web profile
systemctl restart dsh   # 或 dsh web 的运行进程
```

各子目录内的 `README.md` 有完整的配置项、安全说明与测试运行方式。

## 测试

```sh
node remote-access/test/match.test.mjs
node remote-access/test/apply.test.mjs
node remote-access/test/patch.test.mjs   # 需要 js-yaml（dsh 安装自带；或用 DSH_GLOBAL_ROOT 指到 pnpm 全局根）
node remote-auth/test/apply.test.mjs
```

## 安全

- `remote-access` **移除了**远程部署的凭据层：任何能到达端口且 Host 命中围栏的访问者都能完整操作本 harness，
  并（当 `injectTransport: true` 时）写入主机的 settings/credential 文件。**只在隧道或受信任网络后面使用。**
- `remote-auth` 把账号/密码门加回：远程来源必须携带有效 Basic 凭证，
  密码以 `sha256(salt + password)` hex 存储、常量时间比较，明文密码不进 patch 文件。
  默认账号需经 `remote-auth/make-password.mjs` 生成。
