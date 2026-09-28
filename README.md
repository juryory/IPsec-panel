# IPsec Panel

基于 **strongSwan** 的 IPsec 管理面板，专为「公司用 H3C 路由器、但没有公网 IP」的场景设计：
在一台有公网 IP 的云服务器上部署面板，让各地 H3C 主动连上来，员工在外面也能通过云端访问公司内网。

设计思路延续 [openvpn-panel](https://github.com/juryory/openvpn-panel)：面板是 strongSwan 的「薄壳」，
只负责生成配置、调用 `swanctl` / VICI，不重新实现 VPN；面板停了，隧道照常工作。

```
  员工电脑/手机 ──IKEv2（系统自带客户端）──┐
                                          ▼
                     ┌──────────────────────────────┐
                     │   云服务器（公网 IP）          │
                     │   strongSwan + IPsec Panel    │
                     │   Hub 隧道地址 10.10.0.1       │
                     └──────────────────────────────┘
                        ▲                     ▲
   H3C 主动发起（NAT-T）│                     │ H3C 主动发起
                        │                     │
            总部 192.168.1.0/24       分公司 192.168.2.0/24
                  └──────── 站点互通（经云端中转）───────┘
```

## 功能

| 模块 | 说明 |
|---|---|
| **站点（H3C）** | 新增站点只需填内网网段；自动生成 PSK 与身份标识；支持 IKEv1 野蛮模式 / IKEv2；三档算法预设 |
| **H3C 配置生成** | Comware V7 / Comware V5 完整命令行（ACL、IKE、IPsec 策略、接口应用、NQA 保活），ER 系列逐项 Web 填写指南 |
| **配置下发** | 复制粘贴，或 **经隧道 SSH 自动下发**；配置指纹跟踪，拓扑变化后自动提示哪些 H3C 需要重新下发 |
| **密钥轮换** | 一键更换 PSK，启用 SSH 时先推给 H3C 再更新云端，隧道不中断 |
| **站点互通** | 多个站点经云端 Hub 互访，可按站点开关 |
| **远程用户** | 账号密码（EAP-MSCHAPv2，只存 NT Hash）或证书认证；一键生成 iOS/macOS 描述文件、Windows PowerShell 脚本、Android strongSwan 配置、p12 |
| **证书** | 内置 CA，自动签发 / 续签服务器证书，CRL 吊销（禁用、删除、重签证书立即生效）；也可使用 Let's Encrypt 等自定义证书 |
| **监控** | 在线站点与用户、实时流量、手动断开；24 小时 / 7 天 / 30 天流量图；上下线事件 |
| **运维** | strongSwan 状态、重新加载、重启、日志查看；iptables / IP 转发 / MSS 钳制自动配置 |
| **安全** | 单管理员，scrypt 哈希，HttpOnly + SameSite 会话，登录限速（10 分钟 5 次），写操作 CSRF 校验 |

## 部署

先准备一台**有公网 IP 的 Linux 云服务器**，并在安全组中放行：

- `UDP 500`、`UDP 4500`：IPsec（必需）
- `TCP 8443`：面板（如果用 Nginx 反代，就放行 443）

两种部署方式二选一。

### 方式一：Docker

```bash
git clone https://github.com/juryory/IPsec-panel.git
cd IPsec-panel
bash scripts/docker-install.sh          # 国内服务器加 --cn 使用国内镜像
```

或手动执行：

```bash
docker compose up -d --build
docker compose logs -f                  # 首次启动会打印管理员密码，也可查看 data/initial-password.txt
```

容器使用 `network_mode: host` 和 `NET_ADMIN` 权限，strongSwan 和面板在同一个容器里运行。数据保存在 `./data`。

### 方式二：Node.js 原生安装（systemd）

```bash
git clone https://github.com/juryory/IPsec-panel.git
cd IPsec-panel
sudo bash scripts/install.sh            # 国内服务器加 --cn
```

脚本会自动完成以下工作：

- 安装 strongSwan（`swanctl` / `charon-systemd`）。
- 如果系统里没有 Node.js，或版本低于 22.13，下载独立的 Node.js 到 `/opt/ipsec-panel/runtime`。
- 安装面板并注册 `ipsec-panel.service`。

支持 Debian 11+、Ubuntu 20.04+、Rocky / Alma / CentOS Stream 8+。

| 参数 | 作用 |
|---|---|
| `--cn` | Node.js 与 npm 依赖走 npmmirror 国内镜像 |
| `--behind-proxy` | 面板只监听 `127.0.0.1:8088`（HTTP），由 Nginx / 宝塔反代并加 HTTPS |
| `--port 9443` | 修改面板端口 |

重复执行 `install.sh` 就是升级，数据和配置会保留。卸载用 `bash scripts/uninstall.sh`，加 `--purge` 会同时删除数据。

安装后可以使用命令行工具：

```bash
ipsec-panel status              # strongSwan 状态、站点和在线用户
ipsec-panel reload              # 重新生成并加载配置
ipsec-panel reset-password      # 重置管理员密码
```

### 本地开发

```bash
npm install
npm run dev        # MOCK 模式：不需要 strongSwan，模拟在线数据，http://127.0.0.1:18088
npm test
```

## 使用流程

1. **设置**：填写云服务器公网地址（IP 或域名）。其余选项可以先用默认值：隧道网段 `10.10.0.0/24`，Hub 身份 `ipsec-hub`。
2. **新增站点**：填写名称和 H3C 后面的内网网段（如 `192.168.1.0/24`），选择设备类型和 WAN 口名称。
3. **配置 H3C**：进入站点详情，点击「复制命令」，粘贴到 H3C 命令行（ER 系列按页面上的表格在 Web 界面里填写），然后点击「我已手动配置」。
4. **检查连接**：几秒钟后，NQA 保活会触发 H3C 建立隧道，站点状态变成「在线」。
5. **新增远程用户**：在「客户端配置」里下载对应平台的文件，发给员工导入。

> 以后如果新增了站点，或修改了网段、互通等设置，已有站点的 H3C 配置也需要更新（ACL 要加上新网段），面板会标记为「待下发」。
> 如果站点启用了 SSH 下发，点一下「SSH 下发到设备」即可：面板会经隧道登录 H3C 的 LAN 地址，执行命令并保存配置。

## H3C 侧的注意事项

- **H3C 没有公网 IP**，所以隧道只能由 H3C 发起。面板生成的配置里带有 **NQA 保活**：H3C 每 10 秒 ping 一次云端 Hub 地址 `10.10.0.1`，隧道断了会自动重建，也不需要等内网有流量才建立。
- **NAT 豁免**：如果 WAN 口配置了 `nat outbound`，要让 VPN 流量不做 NAT，否则报文会先被 NAT 成公网地址，匹配不上 IPsec 的 ACL。生成的配置末尾给出了需要加到 NAT ACL 里的 `deny` 规则。
- **ER 系列**一般只支持 IKEv1 野蛮模式。strongSwan 默认禁止「野蛮模式 + PSK」，安装脚本和 Docker 镜像已经通过 `deploy/strongswan-panel.conf` 打开了这个限制。
- 设备提示某条命令不支持时，先把站点算法改成「兼容老设备」再试。不同固件版本的命令可能略有差异，请以设备手册为准。
- **SSH 下发**需要 H3C 上已经开启 `ssh server enable`，并有一个 `service-type ssh` 的本地用户。

## 客户端

| 平台 | 方式 |
|---|---|
| iOS / iPadOS / macOS | `.mobileconfig` 描述文件，已包含 CA 证书，安装后在「设置 → VPN」连接 |
| Windows 10 / 11 | 用管理员身份运行 `powershell -ExecutionPolicy Bypass -File xxx.ps1`，脚本会自动导入 CA、创建 IKEv2 连接并添加路由 |
| Android | 安装 strongSwan VPN Client，导入 `.sswan` 文件 |
| 其它 | 手动配置 IKEv2：服务器填公网地址，远程 ID 与公网地址相同，认证方式 EAP-MSCHAPv2，并信任面板 CA |

默认是分流模式：只有公司各站点网段和隧道网段的流量走 VPN。在设置里开启「远程用户全局代理」后，全部流量都经云端出网（云端会自动做 NAT）。

## 常见问题

**站点一直不在线**
- 云服务器安全组是否放行了 UDP 500 和 4500。
- 在「日志 → strongSwan 日志」里查看报错：
  - `no shared key found`：PSK 或身份标识不一致。
  - `NO_PROPOSAL_CHOSEN`：两端算法不一致，重新下发配置即可。
- 在 H3C 上执行 `display ike sa`、`display ipsec sa`、`display nqa result` 查看状态。

**隧道建立了，但访问不了对端**
- 检查 H3C 的 NAT 豁免（见上文）。
- 如果启用了 firewalld，它可能拦截转发流量：`firewall-cmd --permanent --zone=trusted --add-source=10.10.0.0/24`（各站点网段同样加上）。
- 云服务器上如果装了其它防火墙面板，确认它没有清空面板添加的 `IPSP-*` 链。

**网页能 ping 通，但打不开**
这通常是 MTU 问题。面板已经自动做了 TCP MSS 钳制（1360）。如果还是不行，在 H3C 的 WAN 口配置 `tcp mss 1350`。

**Docker 部署时 iptables 规则不生效**
容器入口脚本会自动检测宿主机用的是 iptables-legacy 还是 nft，并使用同一个后端。如果宿主机上同时运行了 strongSwan 或 libreswan，请先停掉，否则会和容器争用 UDP 500 和 4500。

## 目录结构

```
src/
  server.js      入口：HTTP(S) 服务、启动时同步配置、启动采集
  api.js         REST API
  swanconf.js    生成 swanctl.conf（站点 / 远程用户 / 地址池 / 密钥）
  h3c.js         生成 H3C Comware V7 / V5 命令与 ER 指南
  h3cpush.js     SSH 下发（ssh2）
  vici.js        strongSwan VICI 协议客户端（纯 JS）
  strongswan.js  写配置、swanctl --load-all、重启、日志
  netsetup.js    IP 转发、Hub 地址、iptables（IPSP-* 自有链）
  pki.js         CA / 服务器证书 / 用户证书 / CRL（openssl）
  profiles.js    mobileconfig / PowerShell / sswan
  monitor.js     在线状态、流量采集（5 分钟桶）、事件
  auth.js        管理员认证与会话
  db.js          SQLite（node:sqlite，无原生依赖）
public/          前端（无构建步骤）
deploy/          systemd 单元、strongSwan 配置片段
docker/          容器入口脚本
scripts/         install.sh / uninstall.sh / docker-install.sh
test/            单元测试（node --test）
```

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PANEL_HOST` / `PANEL_PORT` | `127.0.0.1` / `8088` | 监听地址（安装脚本默认写入 `0.0.0.0:8443`） |
| `PANEL_TLS` | `off` | `off` / `auto`（自签）/ `custom`（配合 `PANEL_TLS_CERT`、`PANEL_TLS_KEY`） |
| `TRUST_PROXY` | `0` | 在反向代理后面时设为 `1` |
| `DATA_DIR` | `/var/lib/ipsec-panel` | 数据库、证书 |
| `SWANCTL_DIR` | `/etc/swanctl` | RHEL 系为 `/etc/strongswan/swanctl` |
| `VICI_SOCKET` | `/var/run/charon.vici` | |
| `STRONGSWAN_RESTART_CMD` | `systemctl restart strongswan` | |
| `CHARON_LOG` | `/var/log/ipsec-panel/charon.log` | 不存在时回退到 journalctl |
| `MANAGE_NETWORK` | `1` | 设为 `0` 时由你自己管理 iptables 和转发 |
| `POLL_INTERVAL` | `30` | 状态和流量的采集间隔（秒） |
| `ADMIN_USER` / `ADMIN_PASSWORD` | `admin` / 随机 | 仅在首次启动时生效 |

## License

MIT
