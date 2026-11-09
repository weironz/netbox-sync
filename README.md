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
- `plan` 输出 `plan.json`；仅当全部在用设备的名称、投用状态、角色和已有地址等价时，才输出 `inventory.candidate.yml`。不会自动纳管额外设备。
- 链路目前只报告精确匹配、非在用、端口缺失或对端差异。**候选完整保留已有链路基线**。本版不会根据 NetBox 的缺记录删掉现网链路。
- `plan` 返回 `0` 表示生成候选，`2` 表示报告已生成但候选被拦截，`1` 表示输入或运行错误。输出目录必须是新目录。
- 候选是给现有监控生成器审阅的输入；本工具没有 `publish` 命令，不配置定时任务，不热加载服务。

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
