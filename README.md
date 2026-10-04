# IPv4 子网分配 API

基于 **Python + FastAPI + SQLite** 的 IPv4 地址池与子网分配服务。

- 地址池可声明**排除网段**（永不参与分配）
- 按 `prefix_length` 申请子网，从剩余空间中选取**起始地址最小的对齐网段**
- 分配之间、分配与排除网段之间**保证不重叠**
- `request_id` 幂等重试：相同请求返回原结果；参数变化返回 **409 冲突**
- 分配的"检查 + 写入"在单个 SQLite `BEGIN IMMEDIATE` 写事务内完成，**并发下不会重复分配**
- 释放后查询返回当前分配列表与**合并后的最简空闲 CIDR**
- 可为当前分配生成 **RFC 2317 反向 DNS 委派计划**（只读，非八位边界 CIDR 自动拆分）
- 池状态可导出为带 **SHA-256 摘要的规范 JSON 快照**，并在一个 SQLite 写事务内校验、恢复（`restore_id` 幂等重放）
- 可将地址池**分区迁移**为一组两两不重叠、恰好覆盖源池的子池：全部校验与替换在**同一个写事务**内完成，排除网段与已分配子网按归属整体迁入子池（`operation_id` 幂等重放）
- 可将按优先级排列的 CIDR 允许/拒绝规则**编译**为覆盖整个 scope 的不重叠分段（只读，不触碰地址池与分配数据）
- 可对 BGP 公告做**无状态 AS 路径审计与 MOAS / 起源变更比对**（只计算，不读写数据库）
- 可创建**可确认的 BGP 公告计划**：创建时在一致读事务中固定池的排除网段与当前分配、
  复用 AS 路径审计并校验前缀完全位于池内/不碰排除网段/覆盖全部当前分配/同一分配单一起源，
  保存不可变计划与池状态摘要；激活时在单个写事务内重新核对，池状态一旦变化即返回冲突、绝不部分生效
  （`plan_id` 幂等重放）
- 可按策略**批量预留**子网：在**同一个写事务**内编译 allow/deny 规则并读取一致池快照，
  按输入顺序为每项选取最小对齐空闲网段，每项必须完全落在 allow 段；命中 deny 或任一项无空间时
  **整批回滚、池不变**；成功后写入普通分配并返回输入顺序的映射（`batch_id` 幂等重放，
  已有 `request_id` 沿用原幂等语义）
- 一条命令启动，监听 **8000** 端口

## 快速开始

需要 Docker 与 Compose 插件（`docker compose` 或 `docker-compose` 均可）：

```bash
docker compose up --build
```

服务启动后：

- API 文档（Swagger UI）：http://localhost:8000/docs
- 健康检查：http://localhost:8000/health
- SQLite 数据保存在命名卷 `subnet-data`（容器内 `/data/subnets.db`）

## 本地运行（不用 Docker）

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
SUBNET_DB_PATH=./subnets.db .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

运行测试：

```bash
.venv/bin/pip install pytest httpx
.venv/bin/python -m pytest -q
```

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/pools` | 创建地址池（可带排除网段） |
| `GET` | `/pools` | 列出所有地址池 |
| `GET` | `/pools/{id}` | 池状态：排除、当前分配、合并后的空闲 CIDR |
| `POST` | `/pools/{id}/exclusions` | 追加排除网段 |
| `POST` | `/pools/{id}/allocations` | 按前缀长度申请子网（需带 `request_id`） |
| `POST` | `/pools/{id}/reservations` | 按策略批量预留子网：单写事务、整批回滚（`batch_id` 幂等） |
| `DELETE` | `/pools/{id}/allocations/{request_id}` | 释放子网 |
| `POST` | `/pools/{id}/reverse-dns-plan` | 为当前分配生成 RFC 2317 反向 DNS 委派（只读） |
| `GET` | `/pools/{id}/snapshot` | 导出带 SHA-256 摘要的规范 JSON 池快照 |
| `POST` | `/pools/{id}/snapshot/restore` | 校验摘要后在一个写事务内恢复池状态（`restore_id` 幂等） |
| `POST` | `/pools/{id}/partitions` | 将源池分区迁移为一组恰好覆盖它的子池（单写事务，`operation_id` 幂等） |
| `POST` | `/cidr-policy/compile` | 将优先级 CIDR 规则编译为覆盖 scope 的不重叠动作分段（只读） |
| `POST` | `/bgp/announcements/audit` | BGP 公告 AS 路径审计与 MOAS / 起源变更比对（无状态，不读写数据库） |
| `POST` | `/pools/{id}/bgp-plans` | 创建不可变 BGP 公告计划并固定池状态摘要（`plan_id` 幂等） |
| `POST` | `/pools/{id}/bgp-plans/{plan_id}/activate` | 写事务内重新核对摘要与覆盖关系后激活计划 |
| `GET` | `/health` | 健康检查 |

### 1. 创建地址池

```bash
curl -X POST http://localhost:8000/pools \
  -H 'Content-Type: application/json' \
  -d '{"cidr": "10.10.0.0/22", "exclusions": ["10.10.2.0/24"]}'
```

```json
{
  "id": 1,
  "cidr": "10.10.0.0/22",
  "exclusions": ["10.10.2.0/24"],
  "created_at": "2026-09-22T14:55:26.830211+00:00"
}
```

### 2. 申请子网

```bash
curl -X POST http://localhost:8000/pools/1/allocations \
  -H 'Content-Type: application/json' \
  -d '{"request_id": "order-42", "prefix_length": 24}'
```

```json
{
  "id": 1,
  "pool_id": 1,
  "cidr": "10.10.0.0/24",
  "request_id": "order-42",
  "prefix_length": 24,
  "created_at": "2026-09-22T14:55:26.888890+00:00",
  "replayed": false
}
```

选取规则：在当前空闲空间（池减去排除网段与既有分配）中，选择能容纳目标前缀、
且**网络地址最小**的对齐 CIDR。例如池 `10.10.0.0/22` 排除 `10.10.2.0/24`、
已分配 `10.10.0.0/24` 与 `10.10.1.0/24` 后，申请 `/25` 会得到 `10.10.3.0/25`。

无足够连续空间时返回 `409 pool_exhausted`。

### 3. 幂等重试

相同 `request_id` + 相同 `prefix_length` 重复请求，返回**同一条原始记录**
（`id` 与 `cidr` 不变，`replayed: true`），不会二次分配：

```bash
curl -X POST http://localhost:8000/pools/1/allocations \
  -H 'Content-Type: application/json' \
  -d '{"request_id": "order-42", "prefix_length": 24}'
```

同一个 `request_id` 但参数（前缀长度或池）变化时返回冲突：

```json
HTTP 409
{"error": {"code": "request_id_conflict",
           "detail": "request_id 'order-42' already allocated prefix_length 24, not 25"}}
```

### 4. 释放子网

```bash
curl -X DELETE http://localhost:8000/pools/1/allocations/order-42
```

### 5. 查询状态（分配 + 最简空闲 CIDR）

```bash
curl http://localhost:8000/pools/1
```

```json
{
  "id": 1,
  "cidr": "10.10.0.0/22",
  "exclusions": ["10.10.2.0/24"],
  "allocated": [
    {"cidr": "10.10.3.0/25", "request_id": "a3", "prefix_length": 25, "created_at": "..."}
  ],
  "free_cidrs": ["10.10.0.0/23", "10.10.3.128/25"],
  "free_addresses": 640
}
```

`free_cidrs` 使用 CIDR 合并算法（`ipaddress.collapse_addresses`）输出覆盖全部
剩余空间的最简、不相交表示。全部释放后，`10.10.0.0/22` 排除 `10.10.2.0/24`
的空闲表示为 `10.10.0.0/23` 与 `10.10.3.0/24`。

### 6. 追加排除网段

```bash
curl -X POST http://localhost:8000/pools/1/exclusions \
  -H 'Content-Type: application/json' -d '{"cidr": "10.10.3.192/26"}'
```

排除网段必须位于池内，且不得与既有排除网段或已有分配重叠（否则 `409`）。

### 7. 生成 RFC 2317 反向 DNS 委派（只读）

为池内**当前全部已分配子网**生成反向 DNS 委派计划。该接口为只读操作：
**不会创建、释放或修改任何分配**，只有当全部输入校验通过后才返回结果，
否则返回错误且不产生任何片段。

- `parent_zone`：八位组对齐的父反向区，只接受 `/8`、`/16`、`/24`
  （例如 `2.0.192.in-addr.arpa`、`0.192.in-addr.arpa`、`10.in-addr.arpa`），
  且必须覆盖整个地址池。
- `entries[]`：每个**当前分配**恰好一条；每条提供：
  - `cidr`：必须是池内现存分配，且位于 `parent_zone` 内；
  - `child_zone`：当 CIDR 小于 `/24` 时**必填**——RFC 2317 的标签子区名，
    可以是单标签（相对所在 /24，如 `64-127`），也可以是完整名称
    （如 `64-127.2.0.192.in-addr.arpa.`）；`/24`、`/16`、`/8` 整区委派时忽略；
  - `nameservers`：至少**两台不同的**权威服务器 FQDN（大小写、尾点会归一化，
    重复项去重后仍不足两台则拒绝）；
  - `ptr`（可选）：`{IP 地址: 主机名}` 的 PTR 记录，地址必须在本子网内。

**非八位边界拆分**：跨越 /24（或 /16、/8）边界的 CIDR 会被拆成覆盖且互不重叠的
最小委派片段。例如 `/23` 拆成两个直连委派的 `/24`，`/15` 拆成两个 `/16`；
小于 `/24` 的子网整体落在一个 /24 内，作为**单个 RFC 2317 标签区**委派，
父区中为其覆盖的每个地址生成一条 CNAME。

输出顺序与请求体顺序无关：`delegations` 按片段地址排序；`records` 按片段分组，
每组内 NS（按服务器名字典序）→ CNAME（按地址数值序）→ PTR（按地址数值序）。

```bash
curl -X POST http://localhost:8000/pools/1/reverse-dns-plan \
  -H 'Content-Type: application/json' -d '{
    "parent_zone": "2.0.192.in-addr.arpa",
    "entries": [
      {
        "cidr": "192.0.2.0/26",
        "child_zone": "0-63",
        "nameservers": ["ns1.example.com", "ns2.example.com"],
        "ptr": {"192.0.2.5": "host5.example.com"}
      },
      {
        "cidr": "192.0.2.64/26",
        "child_zone": "64-127.2.0.192.in-addr.arpa",
        "nameservers": ["ns1.example.com", "ns2.example.com"]
      }
    ]
  }'
```

```json
{
  "pool_id": 1,
  "parent_zone": "2.0.192.in-addr.arpa",
  "delegations": [
    {
      "cidr": "192.0.2.0/26",
      "source_cidr": "192.0.2.0/26",
      "mode": "rfc2317",
      "enclosing_zone": "2.0.192.in-addr.arpa",
      "child_zone": "0-63.2.0.192.in-addr.arpa",
      "nameservers": ["ns1.example.com", "ns2.example.com"]
    },
    {
      "cidr": "192.0.2.64/26",
      "source_cidr": "192.0.2.64/26",
      "mode": "rfc2317",
      "enclosing_zone": "2.0.192.in-addr.arpa",
      "child_zone": "64-127.2.0.192.in-addr.arpa",
      "nameservers": ["ns1.example.com", "ns2.example.com"]
    }
  ],
  "records": [
    {"type": "NS", "name": "0-63.2.0.192.in-addr.arpa", "target": "ns1.example.com"},
    {"type": "NS", "name": "0-63.2.0.192.in-addr.arpa", "target": "ns2.example.com"},
    {"type": "CNAME", "name": "0.2.0.192.in-addr.arpa", "target": "0.0-63.2.0.192.in-addr.arpa"},
    {"type": "CNAME", "name": "1.2.0.192.in-addr.arpa", "target": "1.0-63.2.0.192.in-addr.arpa"}
  ]
}
```

（上例 `records` 仅节选；每个 /26 实际各含 64 条 CNAME。）

跨八位边界整区拆分示例：`192.0.2.0/23` 会返回两个 `direct` 片段
`192.0.2.0/24`、`192.0.3.0/24`，各自带 NS 记录，不含 CNAME；提供的 PTR
按地址归属自动落到对应片段。

### 8. 导出池快照（规范 JSON + SHA-256）

`GET /pools/{id}/snapshot` 导出池的完整状态（池本身、排除网段、全部分配），
返回：

```json
{
  "pool_id": 1,
  "digest": "0999ed9ddfb38340be19d2fcd2e1381e136246f271e5dfb5322923ff0ecdb646",
  "snapshot": {
    "version": 1,
    "digest_algorithm": "SHA-256",
    "pool": {"id": 1, "cidr": "10.10.0.0/22", "created_at": "2026-09-23T08:00:00+00:00"},
    "exclusions": [
      {"id": 1, "pool_id": 1, "cidr": "10.10.2.0/24",
       "created_at": "2026-09-23T08:00:00+00:00"}
    ],
    "allocations": [
      {"id": 1, "pool_id": 1, "cidr": "10.10.0.0/24", "request_id": "order-42",
       "prefix_length": 24, "created_at": "2026-09-23T08:01:00+00:00"}
    ]
  }
}
```

每条排除/分配记录都导出数据库行身份 `id` 与归属 `pool_id`；恢复时会校验记录归属、
并按导出的 `id` / `pool_id` 原样写回（同一外键关系），数组重排序不会丢失身份。

响应同时带 RFC 3230 头 `Digest: sha-256=<base64>`。

**规范 JSON（canonical form）**规则——`digest` 即对下列字节取 SHA-256：

- 字段按**固定顺序**：顶层 `version → digest_algorithm → pool → exclusions →
  allocations`；`pool` 为 `id → cidr → created_at`；排除项为
  `id → pool_id → cidr → created_at`；分配项为
  `id → pool_id → cidr → request_id → prefix_length → created_at`；
- `digest_algorithm` 固定为 `"SHA-256"`，恢复时只接受该算法（Pydantic 校验）；
- 紧凑分隔符（JSON 中无任何空白）、UTF-8、无尾换行；
- `exclusions` / `allocations` 按 **CIDR 数值地址排序**，摘要与数组书写顺序无关；
  排序时记录携带的 `id` / `pool_id` 随记录一起移动，不会错位。

客户端可用任何语言按同一规则复验，例如：

```bash
curl -s http://localhost:8000/pools/1/snapshot > snap.json
python3 -c '
import hashlib, json, sys
body = json.load(open("snap.json"))
canon = json.dumps(body["snapshot"], separators=(",", ":")).encode("utf-8")
assert hashlib.sha256(canon).hexdigest() == body["digest"]
print("verified")'
```

### 9. 从快照恢复池状态

```bash
curl -X POST http://localhost:8000/pools/1/snapshot/restore \
  -H 'Content-Type: application/json' \
  -d '{"restore_id": "migration-2026-09-23",
       "digest": "0999ed9d...db646",
       "snapshot": { ... 上一节 snapshot 对象的完整内容 ... }}'
```

恢复在写入前依次完成以下**全部校验**，任一失败返回错误且**现有数据不变**：

1. `digest` 必须是 64 位十六进制 SHA-256，且与快照规范 JSON 的实算摘要一致；
   `snapshot.digest_algorithm` 必须为 `"SHA-256"`；
2. `snapshot.pool.id` 必须等于路径中的池 id（外键目标存在）；每条排除/分配记录的
   `pool_id` 也必须等于该池 id（记录归属校验，拒绝别池记录混入），且同表内导出的
   `id` 不得重复；
3. 所有 CIDR 必须严格合法；排除网段与分配必须**包含在池内**；
   排除之间、分配之间、分配与排除之间**互不重叠**；
4. 每条分配的 `prefix_length` 必须与其 CIDR 一致；快照内 `request_id` 不重复；
5. 快照中的 `request_id` 不得与**其他池**的既有分配冲突（该列全局唯一）。

全部通过后，在单个 `BEGIN IMMEDIATE` 写事务内更新池、删除旧排除/分配、
**按导出的 `id` / `pool_id`** 插入快照中的排除/分配并登记本次恢复；任一步失败
整体回滚。因此恢复后的行与池保持同一条外键关系，行 id 也与导出身份一致。

成功响应：

```json
{"restore_id": "migration-2026-09-23", "pool_id": 1,
 "digest": "0999ed9d...db646", "replayed": false, "replaced": true}
```

**幂等重放**：相同 `restore_id` 携带相同池 id 与摘要重试，返回原始结果
（`replayed: true, replaced: false`），**不会二次替换**；相同 `restore_id`
但池 id 或摘要变化返回 `409 restore_id_conflict`。并发使用同一 `restore_id`
恢复时由写事务串行化，只会有一次真正替换，其余全部重放。

### 10. 编译 CIDR 策略（只读）

`POST /cidr-policy/compile` 把一组按优先级排列的 CIDR 规则编译为**覆盖整个
`scope`、互不重叠、按网络地址排序**的动作分段。该接口是纯计算：**不读取、
也不修改任何地址池、排除网段或分配数据**，不需要先创建池。

请求字段：

- `scope`：IPv4 CIDR，策略的编译范围（如 `10.0.0.0/16`、`0.0.0.0/0`）；
  必须严格合法（不允许带主机位，如 `10.0.0.5/24`），不接受 IPv6；
- `default_action`：范围内未命中任何规则的地址使用的动作，仅可为
  `allow` 或 `deny`；
- `rules`：按**优先级从高到低**排列的规则数组，顺序即匹配顺序；
  - 每条含 `cidr`（IPv4 CIDR，**必须包含在 `scope` 内**）与 `action`
    （仅 `allow` / `deny`）；
  - 规则**允许重叠甚至重复**：对任意地址，数组中第一条覆盖该地址的规则
    决定其动作（首条匹配）；因此先写粗规则会遮蔽其后落在其中的细规则，
    需要"细网段例外"时应把细网段写在前面。

**合并规则**：仅当两个网段是同一父前缀的两个等长同级分段、且动作相同时，
才合并为该父前缀；动作来自规则还是默认动作不影响合并。非同级的两个网段
即使动作相同也不会合并。结果始终是覆盖整个 `scope` 的最简分段表示。

```bash
curl -X POST http://localhost:8000/cidr-policy/compile \
  -H 'Content-Type: application/json' -d '{
    "scope": "10.0.0.0/24",
    "default_action": "deny",
    "rules": [
      {"cidr": "10.0.0.128/26", "action": "allow"},
      {"cidr": "10.0.0.64/27", "action": "allow"}
    ]
  }'
```

```json
{
  "scope": "10.0.0.0/24",
  "default_action": "deny",
  "segments": [
    {"cidr": "10.0.0.0/26", "action": "deny"},
    {"cidr": "10.0.0.64/27", "action": "allow"},
    {"cidr": "10.0.0.96/27", "action": "deny"},
    {"cidr": "10.0.0.128/26", "action": "allow"},
    {"cidr": "10.0.0.192/26", "action": "deny"}
  ]
}
```

上例中 `10.0.0.64/27` 与 `10.0.0.96/27` 动作不同（一个 allow、一个默认
deny），故不合并；若二者都是 allow，则合并为单个 `10.0.0.64/26`。
`rules` 为空或某条规则覆盖整个 `scope` 时，结果就是整个 `scope` 一段。

非法 `scope` / 规则 CIDR 返回 `422 invalid_cidr`；规则 CIDR 不在
`scope` 内返回 `422 rule_outside_scope`；动作取值非法由请求校验直接
返回 422。

### 11. BGP 公告审计（无状态）

`POST /bgp/announcements/audit` 接收一批 **AS 关系声明**与一批 **BGP 公告**，
对每条公告的 AS_PATH 做合规审计，并对审计通过的公告做 MOAS / 起源变更比对。
该接口是纯计算：**不读取、也不写入任何数据库**，不需要先创建池，可与地址池
功能完全独立使用。

**AS 关系（`relationships`）**——每条声明是带 `type` 鉴别字段的对象：

- `{"type": "customer_provider", "customer": <ASN>, "provider": <ASN>}`：
  `customer` 向 `provider` 购买中转；方向有意义，因此
  `100 → 200`（100 是客户）与 `200 → 100`（200 是客户）是相反声明；
- `{"type": "peer", "a": <ASN>, "b": <ASN>}`：对等互联，对称关系，
  `a/b` 顺序不影响。

ASN 为 32 位编号，取值 **1..4294967294**（0 与 4294967295 为保留值，由请求
校验直接 422）。同一 AS 对**完全相同**的重复声明会被忽略；但同一对 AS 同时
被声明为 peer 与中转、或中转方向互相矛盾时返回 `422 as_relation_conflict`；
AS 与自身建立关系返回 `422 invalid_as_relation`。

**公告（`announcements`）**——每条含：

- `id`：本请求内唯一的字符串标识；
- `prefix`：严格 IPv4 CIDR（不允许主机位、不接受 IPv6），返回时会规范化；
- `as_path`：**按观察点到起源**排列的 ASN 序列，即路径末尾的 ASN 为起源。

**路径审计**逐条 hop 进行：

1. **折叠**：只合并连续重复的 ASN（AS_PATH prepending），例如
   `[10,10,20,20,30]` 折叠为 `[10,20,30]`；
2. **AS 环（`as_loop`）**：折叠后出现的非连续重复记为 AS 环。逐 hop 检查时，
   一旦某条边的关系缺失（请求级 422）则优先报 422；否则抵达重复 ASN 的那条
   公告标记 `status: "as_loop"`，该公告不参与后续比对；
3. **无关系边**：某对相邻 ASN 没有任何声明关系时，整个请求返回
   `422 as_relation_unknown`，错误信息带公告 `id`、零基 hop 序号与两端 ASN；
4. **山谷自由（valley-free）形状**：其余路径必须依次由
   **0 次或多次 `customer→provider`（向上）**、**至多一个 `peer`**、
   **0 次或多次 `provider→customer`（向下）**组成，即相位只能单调地沿
   `up → peer → down` 推进。违例公告标记 `status: "invalid_path"`，并在
   `violating_hop` 中给出**首个违例 hop**（`hop` 为折叠后路径的零基边序号，
   即边 `as_path[hop] → as_path[hop+1]`，同时给出 `from_asn` / `to_asn`）。
   典型违例包括：peer 之后再向上、下降之后又向上、连续两个 peer。

**比对阶段只比较 `status: "valid"` 的公告**（`as_loop` / `invalid_path`
一律不参与）：

- **MOAS**：完全相同的前缀被多个不同起源 AS 公告时，这些公告全部标记
  `moas`（起源相同的重复公告不算 MOAS）；
- **起源变更（`origin_change`）**：某前缀的更具体公告，其起源与其
  **最近覆盖前缀**（最长匹配、严格更不具体）的起源不同。当覆盖前缀本身是
  MOAS、而更具体起源恰为其多个起源之一时，不标记变更。

结果 `results` 按 **(网络地址数值, 前缀长度, 公告 id)** 稳定排序，与请求顺序
无关；每条结果包含折叠后的 `as_path`、`origin`、`status`、`flags` 与
`violating_hop`。

```bash
curl -X POST http://localhost:8000/bgp/announcements/audit \
  -H 'Content-Type: application/json' -d '{
    "relationships": [
      {"type": "customer_provider", "customer": 10,  "provider": 100},
      {"type": "customer_provider", "customer": 20,  "provider": 100},
      {"type": "peer",               "a": 100, "b": 50},
      {"type": "customer_provider", "customer": 60,  "provider": 50}
    ],
    "announcements": [
      {"id": "m1",   "prefix": "203.0.113.0/24",    "as_path": [10, 10, 100]},
      {"id": "m2",   "prefix": "203.0.113.0/24",    "as_path": [50]},
      {"id": "spec", "prefix": "203.0.113.128/25",  "as_path": [100, 50, 50, 60]},
      {"id": "loop", "prefix": "198.51.100.0/24",   "as_path": [10, 100, 10]}
    ]
  }'
```

```json
{
  "results": [
    {
      "id": "loop",
      "prefix": "198.51.100.0/24",
      "as_path": [10, 100, 10],
      "origin": 10,
      "status": "as_loop",
      "flags": [],
      "violating_hop": null
    },
    {
      "id": "m1",
      "prefix": "203.0.113.0/24",
      "as_path": [10, 100],
      "origin": 100,
      "status": "valid",
      "flags": ["moas"],
      "violating_hop": null
    },
    {
      "id": "m2",
      "prefix": "203.0.113.0/24",
      "as_path": [50],
      "origin": 50,
      "status": "valid",
      "flags": ["moas"],
      "violating_hop": null
    },
    {
      "id": "spec",
      "prefix": "203.0.113.128/25",
      "as_path": [100, 50, 60],
      "origin": 60,
      "status": "valid",
      "flags": ["origin_change"],
      "violating_hop": null
    }
  ]
}
```

上例中：`m1` 路径折叠掉连续 prepend 的 AS10；`m1`（起源 100）与 `m2`
（起源 50）公告同一前缀 → 两者均带 `moas`；`spec` 是 `203.0.113.0/24` 的更
具体公告、起源 60 不同于覆盖前缀的起源 100/50 → `origin_change`；`loop`
折叠后 AS10 非连续重复 → `as_loop`，不参与 MOAS 比对。

山谷违例示例：关系 `100↔50 peer` 且 `50 是 70 的客户`（50→70 向上）时，
路径 `[100, 50, 70]` 在 peer 之后继续向上，`violating_hop` 为
`{"hop": 1, "from_asn": 50, "to_asn": 70}`。

### 12. 池分区迁移（替换源池）

`POST /pools/{id}/partitions` 把源池**整体替换**为一组新子池：调用方提交
`operation_id`（幂等键）与一组子网 `subnets`，这些子网必须**两两不重叠**且
**恰好覆盖**源池 CIDR。

```bash
curl -X POST http://localhost:8000/pools/1/partitions \
  -H 'Content-Type: application/json' \
  -d '{"operation_id": "split-2026-10",
       "subnets": ["10.10.0.0/23", "10.10.2.0/23"]}'
```

```json
{
  "operation_id": "split-2026-10",
  "migration_id": 1,
  "source_pool_id": 1,
  "source_cidr": "10.10.0.0/22",
  "sub_pools": [
    {"pool_id": 2, "cidr": "10.10.0.0/23"},
    {"pool_id": 3, "cidr": "10.10.2.0/23"}
  ],
  "created_at": "2026-10-02T08:00:00+00:00",
  "replayed": false
}
```

响应即**源池 → 子池的映射**（`sub_pools` 按网络地址排序，与请求顺序无关）加上
迁移记录 ID（`migration_id`）。

**全部校验与写入在同一个 `BEGIN IMMEDIATE` 写事务内完成**，依次校验：

1. `operation_id` 幂等：相同 `operation_id` + 相同源池 + 相同子网集合（顺序无关）
   重试时**返回原始结果**（`replayed: true`，即使源池已被替换）；同一
   `operation_id` 但源池或子网集合变化返回 `409 operation_id_conflict`；
2. 每个子网 CIDR 严格合法（`422 invalid_cidr`）、**位于源池内**
   （`422 partition_outside_pool`）、**两两不重叠**（`422 partition_overlap`，
   重复也算重叠）、合起来**恰好覆盖**源池（`422 partition_incomplete`）；
3. 源池的**每条排除网段**与**每个已分配子网**都完全落入**唯一**子池
   （跨子池边界时分别返回 `422 partition_exclusion_unmapped` /
   `422 partition_allocation_unmapped`）；
4. 子池 CIDR 不与**其他现有地址池**冲突（`409 partition_pool_conflict`；
   源池自身即将退役，不参与该检查）。

全部通过后，在同一事务内：删除源池、创建子池、把排除网段与分配**按原行 id
与 `created_at`** 迁入各自归属的子池、写入迁移记录。任一步失败整体回滚——
**不会留下部分子池，源池数据也不会被改动**。迁移后源池 id 返回 404，其
`request_id` 幂等键随分配一起归属新子池；子网列表只有一个且等于源池 CIDR 的
退化分区也是合法请求（源池被同 CIDR 的新池替换，池 id 改变）。

### 13. 可确认的 BGP 公告计划（创建 + 激活）

网络团队在正式发布 BGP 公告前，需要确认公告仍对应当前地址池：池内分配一旦变化，
旧的公告集合可能覆盖了已释放的地址、或漏掉新分配，绝不能把这种过期路由激活出去。
本功能提供两个端点：

- `POST /pools/{id}/bgp-plans`：提交 `plan_id`（幂等键）、`relationships`（AS 关系，
  与审计接口同一格式）与 `announcements`（公告列表），创建一条**不可变**计划；
- `POST /pools/{id}/bgp-plans/{plan_id}/activate`：在单个写事务内重新核对后，
  把计划标记为 `active`。

**创建计划**时，先在一个**一致读事务**（`BEGIN`）中读取并固定池的 CIDR、排除网段
与当前分配，再完成以下全部校验，任一失败均不落库：

1. **复用现有路径审计**：`relationships` / `announcements` 直接交给
   `/bgp/announcements/audit` 使用的同一审计逻辑。关系冲突、未知关系边、非法前缀、
   空 AS_PATH、公告 id 重复等请求级错误照旧返回 422；
2. 每条公告前缀必须**完全位于池内**（`bgp_announcement_outside_pool`），且**不得与
   任何排除网段重叠**（`bgp_announcement_overlaps_exclusion`）；
3. **每个当前分配**必须至少被一条审计状态为 `valid` 的公告覆盖
   （`bgp_allocation_uncovered`）——`as_loop` / `invalid_path` 的公告不能用于覆盖；
4. 同一分配若被不同起源 AS 的公告覆盖，拒绝（`bgp_allocation_origin_conflict`）。

全部通过后，在写事务中复查读事务以来池状态未变，然后保存：计划参数指纹、
审计结果（不可变）、池状态摘要（池 CIDR + 按数值排序的排除网段 + 按数值排序的
当前分配）以及摘要的 **SHA-256 摘要** `state_digest`。计划一经创建即不可变，
只有 `status` 可从 `planned` 变为 `active`。

```bash
curl -X POST http://localhost:8000/pools/1/bgp-plans \
  -H 'Content-Type: application/json' -d '{
    "plan_id": "release-2026-10-03",
    "relationships": [
      {"type": "customer_provider", "customer": 10,  "provider": 100},
      {"type": "peer",               "a": 100, "b": 50},
      {"type": "customer_provider", "customer": 60,  "provider": 50}
    ],
    "announcements": [
      {"id": "a0",   "prefix": "203.0.113.0/25",   "as_path": [10, 100]},
      {"id": "a128", "prefix": "203.0.113.128/25", "as_path": [100, 50, 60]}
    ]
  }'
```

```json
{
  "plan_id": "release-2026-10-03",
  "pool_id": 1,
  "status": "planned",
  "results": [
    {"id": "a0",   "prefix": "203.0.113.0/25",   "as_path": [10, 100],
     "origin": 100, "status": "valid", "flags": [], "violating_hop": null},
    {"id": "a128", "prefix": "203.0.113.128/25", "as_path": [100, 50, 60],
     "origin": 60,  "status": "valid", "flags": [], "violating_hop": null}
  ],
  "state_digest": "8f2c...e1",
  "pool_state": {
    "cidr": "203.0.113.0/24",
    "exclusions": [],
    "allocations": [
      {"cidr": "203.0.113.0/25",   "request_id": "order-1", "prefix_length": 25, "created_at": "..."},
      {"cidr": "203.0.113.128/25", "request_id": "order-2", "prefix_length": 25, "created_at": "..."}
    ]
  },
  "created_at": "2026-10-03T09:00:00+00:00",
  "activated_at": null,
  "replayed": false
}
```

**激活计划**：

```bash
curl -X POST http://localhost:8000/pools/1/bgp-plans/release-2026-10-03/activate
```

激活在**单个 `BEGIN IMMEDIATE` 写事务**内重新读取池的排除与分配，重新计算摘要：
只有 `state_digest` 与创建时固定的摘要**完全一致**、且用计划内已审计公告重新验证
覆盖关系与单一起源仍然成立时，才把 `status` 置为 `active` 并记录 `activated_at`。
期间池发生任何变化——新增/释放/重分配（即使又分配回同一 CIDR、同一
`request_id`，行的 `created_at` 不同也算）、追加排除网段——都返回
`409 bgp_plan_state_conflict`，事务回滚，**不会部分生效**，计划保持
`planned` 可稍后重试。

**幂等语义**：

- 相同 `plan_id` + 相同参数（AS 关系去重排序、公告按 id 排序，与书写顺序无关）
  重放创建请求：返回已存储计划，HTTP 200、`replayed: true`，计划只创建一次；
  计划已激活后重放则返回 `active` 状态的原计划；
- 相同 `plan_id` 但参数变化（不同池、不同关系或不同公告集合）：
  `409 bgp_plan_id_conflict`；
- 重复激活已 `active` 的计划：幂等返回原结果（`replayed: true`，
  `activated_at` 不变），不再重新核对池状态；
- 并发使用同一 `plan_id` 创建由写事务串行化，恰好产生一条计划；并发激活与分配
  也被串行化：要么激活先提交（成功），要么分配先提交（激活返回冲突），不会出现
  部分生效。

### 14. 按策略批量预留（单写事务，整批回滚）

`POST /pools/{id}/reservations` 在一个**原子批次**中预留多个子网。调用方提交：

- `batch_id`：整批的幂等键；
- `default_action`：池内未命中任何规则的地址使用的动作（`allow` / `deny`）；
- `rules`：按**优先级从高到低**排列的 CIDR allow/deny 规则（与
  `/cidr-policy/compile` 同一语义：首条覆盖该地址的规则生效，规则 CIDR 必须位于
  池内，否则 `422 rule_outside_scope`）；策略的编译范围（scope）就是池 CIDR 本身；
- `items`：若干预留项，每项含 `request_id` 与 `prefix_length`，**按输入顺序**处理。

**全部工作在同一个 `BEGIN IMMEDIATE` 写事务内完成**：先做 `batch_id` 幂等判定，
再编译规则并读取一致的池快照（排除网段 + 现有分配），随后按输入顺序为每一项在
排除网段与既有分配之外选取**起始地址最小的对齐空闲网段**（与单笔分配同一选取规则，
批内已选网段对后续项立即可见、绝不重叠）。每项必须**完全落在某条 allow 段内**；
命中 deny（或默认 deny 区域）返回 `409 reservation_denied`，任一项无足够连续空间
返回 `409 pool_exhausted`——**任一项失败整批回滚，不写入任何分配，池保持不变**，
`batch_id` 也不会被占用（修正请求后可原样重用）。

成功后，每项预留都作为**普通分配**写入（对状态查询、反向 DNS 计划、快照等其他
接口完全可见），并返回**输入顺序**的 `request_id → CIDR` 映射：

```bash
curl -X POST http://localhost:8000/pools/1/reservations \
  -H 'Content-Type: application/json' -d '{
    "batch_id": "rollout-2026-10-04",
    "default_action": "deny",
    "rules": [
      {"cidr": "10.10.0.0/24", "action": "allow"},
      {"cidr": "10.10.1.0/24", "action": "allow"}
    ],
    "items": [
      {"request_id": "edge-1", "prefix_length": 26},
      {"request_id": "edge-2", "prefix_length": 26},
      {"request_id": "core-1", "prefix_length": 25}
    ]
  }'
```

```json
{
  "batch_id": "rollout-2026-10-04",
  "pool_id": 1,
  "reservations": [
    {"request_id": "edge-1", "prefix_length": 26, "cidr": "10.10.0.0/26",
     "allocation_id": 1, "replayed": false},
    {"request_id": "edge-2", "prefix_length": 26, "cidr": "10.10.0.64/26",
     "allocation_id": 2, "replayed": false},
    {"request_id": "core-1", "prefix_length": 25, "cidr": "10.10.0.128/25",
     "allocation_id": 3, "replayed": false}
  ],
  "created_at": "2026-10-04T08:00:00+00:00",
  "replayed": false
}
```

**幂等语义**：

- 相同 `batch_id` + 相同参数（池、`default_action`、规则列表、预留项列表——
  规则顺序即优先级、预留项顺序即选取顺序，**顺序变化也算参数变化**）重放时返回
  原始结果（HTTP 200、`replayed: true`），不会二次预留；参数变化返回
  `409 batch_id_conflict`；
- 项内 `request_id` 沿用**单笔分配的原幂等语义**：已存在的 `request_id` 且池与
  前缀长度一致时，该项直接映射到既有分配（`replayed: true`，不另占空间）；
  前缀长度或池不一致时返回 `409 request_id_conflict` 并整批回滚。同一批内重复
  的 `request_id` 同理：第二次出现重放第一次的结果；
- 并发提交不同批次由写事务串行化，不会选中同一块空间；并发使用同一 `batch_id`
  时恰好记录一批，其余请求重放原结果。

## 错误响应

统一格式：

```json
{"error": {"code": "request_id_conflict", "detail": "..."}}
```

| 状态码 | code | 场景 |
| --- | --- | --- |
| 404 | `pool_not_found` / `allocation_not_found` | 池或分配不存在 |
| 409 | `pool_exists` / `exclusion_exists` | 池或排除网段已存在 |
| 409 | `exclusion_overlap` | 排除网段越界占用 |
| 409 | `pool_exhausted` | 无足够连续空闲空间 |
| 409 | `request_id_conflict` | 幂等键复用但参数变化，或恢复快照中的 request_id 已属其他池 |
| 409 | `restore_id_conflict` | 同一 `restore_id` 曾用于另一池或另一份摘要 |
| 409 | `snapshot_restore_conflict` | 恢复写入时撞上数据库唯一约束（如池 CIDR 重复） |
| 409 | `operation_id_conflict` | 同一 `operation_id` 曾用于另一源池或另一组子网的分区 |
| 409 | `partition_pool_conflict` | 子池 CIDR 与其他现有地址池重叠 |
| 409 | `partition_conflict` | 分区写入时撞上数据库唯一约束 |
| 422 | `partition_outside_pool` / `partition_overlap` / `partition_incomplete` | 分区子网不在源池内、两两重叠（含重复）或未恰好覆盖源池 |
| 422 | `partition_exclusion_unmapped` / `partition_allocation_unmapped` | 排除网段 / 已分配子网跨越子池边界，未完全落入唯一子池 |
| 422 | `invalid_cidr` / `invalid_prefix` / `exclusion_outside_pool` | 参数非法 |
| 422 | `snapshot_bad_digest` | 摘要不是 64 位十六进制 SHA-256 |
| 422 | `snapshot_digest_mismatch` | 摘要与快照规范 JSON 的实算摘要不一致 |
| 422 | `snapshot_pool_mismatch` | 快照中的池 id 与 URL 中的池不一致 |
| 422 | `snapshot_record_pool_mismatch` | 快照中的排除/分配记录 `pool_id` 与 URL 中的池不一致（记录归属错误） |
| 422 | `snapshot_duplicate_record_id` | 快照内同一条表的导出记录 `id` 重复 |
| 422 | `snapshot_allocation_outside_pool` | 快照分配不在池内 |
| 422 | `snapshot_allocation_overlap` | 快照内分配互相重叠或与排除网段重叠 |
| 422 | `snapshot_duplicate_request_id` | 快照内同一 request_id 出现多次 |
| 422 | `snapshot_prefix_mismatch` | 分配的 prefix_length 与其 CIDR 不一致 |
| 422 | `invalid_parent_zone` | 父反向区不是对齐到 /8、/16、/24 的 `in-addr.arpa` 区 |
| 422 | `reverse_parent_outside_pool` | 父反向区不覆盖整个地址池 |
| 422 | `reverse_outside_parent` | 委派子网落在父反向区之外 |
| 422 | `reverse_not_allocated` | 条目 CIDR 不是当前分配 |
| 422 | `reverse_duplicate_entry` | 同一 CIDR 出现多条 |
| 422 | `reverse_no_allocations` | 池内尚无任何分配 |
| 422 | `missing_child_zone` / `invalid_child_zone` | 小于 /24 的子网缺少子区名，或名称非法/不属于所在 /24 |
| 422 | `reverse_name_conflict` | 两个子网声明了同一个子区名 |
| 422 | `nameserver_insufficient` / `invalid_nameserver` | 权威服务器少于两台，或名称非法 |
| 422 | `invalid_ptr` | PTR 地址非法、越界、重复，或主机名非法 |
| 422 | `invalid_cidr` | 策略编译的 `scope` 或规则 CIDR 非法（含主机位、非 IPv4 等） |
| 422 | `rule_outside_scope` | CIDR 策略规则不在 `scope` 内 |
| 422 | `invalid_as_relation` | AS 与自身建立关系 |
| 422 | `as_relation_conflict` | 同一 AS 对被声明为互相矛盾的关系（peer 与中转冲突，或中转方向相反） |
| 422 | `as_relation_unknown` | 公告路径中某对相邻 ASN 没有声明关系（detail 含公告 id、hop 与两端 ASN） |
| 422 | `invalid_prefix` / `invalid_as_path` | 公告前缀非法（含主机位、非 IPv4 等）或 AS_PATH 为空 |
| 422 | `duplicate_announcement_id` | 请求内两条公告使用相同 `id` |
| 404 | `bgp_plan_not_found` | 激活的计划不存在，或计划属于其他池 |
| 409 | `bgp_plan_id_conflict` | 同一 `plan_id` 以不同参数（池、关系或公告集合）重放 |
| 409 | `bgp_plan_state_conflict` | 计划创建/激活时池状态已变：摘要不一致或覆盖关系不再成立 |
| 409 | `batch_id_conflict` | 同一 `batch_id` 以不同参数（池、规则或预留项）重放 |
| 409 | `reservation_denied` | 批内某项选中的最小空闲网段未完全落在 allow 段内（整批回滚） |
| 422 | `bgp_announcement_outside_pool` | 公告前缀不完全位于地址池内 |
| 422 | `bgp_announcement_overlaps_exclusion` | 公告前缀与池的排除网段重叠 |
| 422 | `bgp_allocation_uncovered` | 存在当前分配未被任何审计通过的公告覆盖 |
| 422 | `bgp_allocation_origin_conflict` | 同一分配被不同起源 AS 的公告覆盖 |

注：`as_loop` 与 `invalid_path` 不是错误响应，而是成功响应中对应公告的
`status`；后者还带 `violating_hop`。ASN 越界（0、≥4294967295）、关系/公告
字段缺失等请求结构问题由 Pydantic 直接返回 422。

## 并发与事务

- 所有分配使用 `BEGIN IMMEDIATE` 立即写事务：进入事务即获取 SQLite 写锁，
  并发分配被**串行化**，后到的请求在 `busy_timeout`（10 秒）内等待，基于
  提交后的最新空闲空间计算，杜绝同一块空间被分配两次。
- `allocations.request_id` 上有 `UNIQUE` 约束作为最后防线：同一请求键并发
  重试时只会产生一条记录。
- 快照恢复同样在单个 `BEGIN IMMEDIATE` 写事务内完成全部替换，
  `snapshot_restores.restore_id` 主键保证同一恢复键并发/重放只替换一次；
  所有廉价校验（摘要、CIDR、重叠、request_id 快照内唯一）在开事务前完成，
  失败时连事务都不会开启。
- 池分区迁移的**全部校验与写入**（幂等判定、覆盖/归属/冲突校验、删源池、
  建子池、迁移排除与分配、写迁移记录）都在单个 `BEGIN IMMEDIATE` 写事务内
  完成：并发分区被串行化，对同一源池的并发分区只有一个成功（其余看到源池
  已退役而返回 404）；`pool_migrations.operation_id` 上的 `UNIQUE` 约束保证
  同一操作键并发/重放只真正迁移一次。
- BGP 公告计划在创建时先用一致读事务固定池状态，再于写事务内复查状态未变后落库；
  激活的全部核对（摘要一致、覆盖与单一起源重新成立）与状态翻转都在单个
  `BEGIN IMMEDIATE` 写事务内完成，池状态变化即整体回滚返回冲突；
  `bgp_plans.plan_id` 主键保证同一计划键并发/重放只保存一条不可变计划。
- 批量预留的**全部工作**（`batch_id` 幂等判定、规则编译、一致快照读取、按序选取、
  逐条写入、批次记录）都在单个 `BEGIN IMMEDIATE` 写事务内完成：并发批次被串行化，
  不会选中同一块空闲空间；任一项失败（命中 deny、空间不足、`request_id` 冲突）
  整体回滚，**不会留下部分预留**；`reservation_batches.batch_id` 主键保证同一批次键
  并发/重放只真正执行一次。
- 数据库开启 WAL 模式，读状态不会阻塞写分配。

## 项目结构

```
├── app/
│   ├── main.py        # FastAPI 路由与异常处理
│   ├── service.py     # 业务逻辑：创建/分配/释放/状态/反向委派计划
│   ├── snapshot.py    # 池快照导出/恢复：规范 JSON、SHA-256 摘要、幂等替换
│   ├── partition.py   # 池分区迁移：单写事务校验+替换源池，operation_id 幂等
│   ├── reserve.py     # 按策略批量预留：单写事务编译规则+一致快照+按序选取，batch_id 幂等
│   ├── db.py          # SQLite 连接、建表、事务管理
│   ├── cidrmath.py    # CIDR 集合运算：差集、合并、最低对齐选取、委派片段拆分
│   ├── cidrpolicy.py  # CIDR 策略编译：首条匹配规则 -> 不重叠动作分段（仅同级同动作合并）
│   ├── bgpaudit.py    # BGP 公告无状态审计：路径折叠/AS 环/山谷自由 + MOAS/起源变更比对
│   ├── bgpplan.py     # 可确认的 BGP 公告计划：固定池状态摘要，单写事务内重新核对后激活
│   ├── reversedns.py  # RFC 2317 反向区名运算与 NS/CNAME/PTR 记录生成
│   └── schemas.py     # Pydantic 模型
├── tests/             # pytest：算法单测 + API 集成 + 并发测试
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```
