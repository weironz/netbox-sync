# netbox-sync

`netbox-sync` 是一个 Rust 命令行工具：只读获取 NetBox 库存，和现有监控 `inventory.yml` 对照，生成差异报告及候选。它不轮询设备，不改 NetBox，也不覆盖现网配置。

## 本地运行

```sh
just check
just build
```

`snapshot` 使用 HTTPS 和只读 Token 文件；不要在命令中传 Token 值。工具读取设备、接口、IP 和线缆的必要字段，分页核对数量与 ID，快照中只保留请求站点相关的记录。相关表会分页读取 Token 可见的精简数据，再在本地按设备／接口 ID 筛选。建议限制 Token 的对象权限。快照包含内部资产信息，不应提交到 Git。输出目录的父目录需要先存在。

```sh
just snapshot https://netbox.example.net example-site /secure/netbox.token snapshots/example-site.json
just plan snapshots/example-site.json /path/to/inventory.yml out/example-site
```

当监控的 `site` 与 NetBox 站点 slug 不同，使用 `just plan-for <netbox-site> <snapshot> <inventory> <out-dir>` 明确映射。

- `snapshot` 失败时不产生半份快照。输出文件必须是新文件。
- `plan` 输出 `plan.json`；仅当全部在用设备的名称、投用状态、角色和已有地址等价时，才输出 `inventory.candidate.yml`。等价候选逐字节保留原清单；不会自动纳管额外设备。
- 链路目前只报告精确匹配、非在用、端口缺失或对端差异。**候选完整保留已有链路基线**。本版不会根据 NetBox 的缺记录删掉现网链路。
- `plan` 返回 `0` 表示生成候选，`2` 表示报告已生成但候选被拦截，`1` 表示输入或运行错误。输出目录必须是新目录。
- 候选是给现有监控生成器审阅的输入；本工具没有 `publish` 命令，不配置定时任务，不热加载服务。

### 配置参数

命令行参数与环境变量可混用；显式命令行参数优先。同一个变量可用于相关子命令，不影响已有调用方式。Token 继续从文件读取，`NETBOX_TOKEN_FILE` 只传路径。

| 环境变量 | 命令行参数 |
| --- | --- |
| `NETBOX_URL` | `snapshot --netbox-url` |
| `NETBOX_SITE` | `snapshot --site`、`plan --netbox-site` |
| `NETBOX_TOKEN_FILE` | `snapshot --token-file` |
| `NETBOX_SNAPSHOT_FILE` | `snapshot --output`、`plan --snapshot` |
| `NETBOX_INVENTORY_FILE` | `plan --inventory` |
| `NETBOX_POLICY_FILE` | `plan --policy` |
| `NETBOX_PLAN_DIR` | `plan --out-dir` |

## 常驻同步

Linux 上使用 `netbox-sync run`；启动后立即运行一次，然后按周期同步，不需要外部定时器。它用只读 API 拉取快照，校验已批准的库存及渲染模板；只有等价的采集配置才进入已发布版本。输出目录必须提前创建，并持久化。失败时记录原因，保留上一份已发布文件。端口模式默认 `audit`，在 `plan.json` 中提供两端记录、对端和线缆 ID；不发布端口规则。

在上表的 URL、站点、Token 路径、inventory 和 policy 之外，`run` 还使用以下选项。所有显式 CLI 参数优先于同名环境变量。

| 环境变量 | 参数 |
| --- | --- |
| `NETBOX_SYNC_INTERVAL` | `--interval`（默认 `1h`，支持 `s/m/h`） |
| `NETBOX_PORT_MODE` | `--port-mode`（`audit` 或 `off`） |
| `NETBOX_RENDER_FILE` | `--render-file` |
| `NETBOX_TEMPLATES_DIR` | `--templates-dir` |
| `NETBOX_OUTPUT_DIR` | `--output-dir`（状态、快照、报告） |
| `NETBOX_PROMETHEUS_PUBLISH_DIR` | `--prometheus-publish-dir` |
| `NETBOX_VMAGENT_PUBLISH_DIR` | `--vmagent-publish-dir` |
| `NETBOX_RUN_ONCE` | `--once`（默认 `false`） |

`netbox-sync status --output-dir <dir> --max-age 3h` 可用于健康检查。它根据最后一次成功时间返回状态码；`--max-age` 也支持 `NETBOX_MAX_AGE`。两个发布目录各有一个原子更新的 `current` 相对符号链接。采集器只读挂载生成目录，不持有 NetBox Token，也不依赖同步进程在线。

对于 `biz-ping`，可在渲染配置中选用 `address: primary_ipv4`。目标直接取快照内该站点的所有 Active 设备及其 Primary IPv4。设备角色用于输出分组标签，可选的 `fleet_by_role` 用于保留部署已有的 fleet 标签。别名按配置中的 ID 和名称核对。缺失或重复地址以及与审批模板不一致都会阻止发布。已有业务地址标签和 OOB 解析规则仍适用于其他任务。

## Linux 和 Docker

GitHub Release 只提供 Linux amd64 二进制和 `SHA256SUMS`。Docker 镜像只发布到 Docker Hub 和阿里云 ACR，不作为 Release 附件。

```sh
sha256sum -c SHA256SUMS
tar -xzf netbox-sync-v0.1.0-linux-amd64.tar.gz
./netbox-sync --help
```

Docker Hub 的镜像名为 `<Docker Hub 命名空间>/netbox-sync:v0.1.0`。使用容器处理文件时，将工作目录挂载到 `/work`，Token 文件单独以只读方式挂载；Linux 上可用 `--user "$(id -u):$(id -g)"` 让容器以本地用户权限写候选目录。第一版不提供 Windows 二进制发布包。

## 发布

在 `main` 合并对应版本并更新 `Cargo.toml`、`Cargo.lock` 后，手动触发 `just release v0.1.0`。Workflow 校验版本和源码提交，执行格式、Clippy、测试和隔离镜像检查，再发布 GitHub Release。

已有 Release 的二进制可用 `just publish-images v0.1.0` 打包并推送 Docker Hub 和阿里云 ACR。这一步核对公开二进制包的 SHA-256 和版本，在同一次打包后给同一个 Docker 镜像打两个 registry 标签，不重新编译 Rust。Docker Hub 使用 `DOCKERHUB_USERNAME`、`DOCKERHUB_TOKEN`；ACR 使用 `ACR_URL`、`ACR_USERNAME`、`ACR_PASSWORD`。`ACR_URL` 只有 registry 主机名时使用 workflow 的命名空间输入。发布过程不使用部署凭据。仓库只包含合成测试数据。

## 站点别名和地址用途

如果库存标签与 NetBox 名称不一致，或者业务拨测不使用 NetBox 的主地址，可将策略文件传给 `plan --policy <policy.yml>`，或运行 `just plan-policy <snapshot> <inventory> <policy> <out-dir>`。策略属于站点部署配置，不能跨站点复用。以下是合成示例：

```yaml
version: 1
inventory_site: example-site
netbox_site: registered-site
aliases:
  old-monitoring-label: {device_id: 22, netbox_name: registered-host}
interface_aliases:
  old-monitoring-label/HCA-01: {device_id: 22, interface_id: 102, netbox_name: mlx5_0p1}
business_ip_tag_by_role:
  server: monitoring-biz
require_oob_roles: [server]
```

别名要同时匹配站点、NetBox ID 和预期名称，输出继续用原监控标签。配置业务标签的角色必须有且仅有一个绑定在启用接口上的 active IPv4；缺失或歧义会拦截候选。要求 OOB 的角色必须有一个与设备 OOB 地址相符的 active IPv4 绑定。`plan.json` 的 `resolved_devices` 记录选出的地址，供与现网逐项核对；工具不把新字段自动加到已有清单，也不会应用候选。`snapshot` 保存 NetBox IP 的状态及标签。

`interface_aliases` 用于同一设备上的端口命名差异。键是库存中的 `设备/接口`，值固定到 NetBox 设备 ID、接口 ID 和接口名。匹配要求目标接口启用，且该映射与其他清单端口或已存在的同名接口无冲突。身份校验失败时，链路报告为 `invalid_interface_alias`。对账仍检查两端的实际线缆；端口别名不改写库存、采集配置或端口规则。
