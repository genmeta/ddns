# gmdns Redis 存储说明

这份文档描述 `ddns-server` 在 Redis 里实际会存什么、怎么存、这些数据分别
是干什么用的。它优先写给人看，同时保留足够的细节，方便别的服务对接。

如果你只想先看结论，这个系统在 Redis 里只会用到 3 类原生数据结构：

1. `String`：存一条发布记录的完整二进制内容
2. `Sorted Set`：存查询用的倒排索引
3. `Set`：存黑名单域名

没有使用 `Hash`、`List`、`Stream`、`Bitmap` 之类的其他 Redis 结构。

## 1. 总览

`ddns-server` 自己维护的 Redis key 一共 4 种形态，加上 1 个外部可写黑名单：

| Key 形态 | Redis 类型 | 作用 |
| --- | --- | --- |
| `<host>:fp:<fingerprint_hex>` | `String` | 某个 host 下，某个证书指纹对应的一条完整发布记录 |
| `<host>:idx:all` | `Sorted Set` | 这个 host 的全部活动记录索引 |
| `<host>:idx:country:<country>` | `Sorted Set` | 这个 host 按国家分桶的活动记录索引 |
| `<host>:idx:asn:<asn>` | `Sorted Set` | 这个 host 按 ASN 分桶的活动记录索引 |
| `ddns:blacklist` | `Set` | 被封禁的 host 列表 |

其中：

- 主记录 `String` 是事实来源，真正的记录内容只在这里
- 3 类 `Sorted Set` 都是派生索引，只是为了加速查询
- 黑名单 `Set` 是一个独立控制面数据，不参与记录存储

## 2. Host 规范化规则

Redis 里的 host 名必须先做规范化。代码实现见
[`src/bin/ddns-server/error.rs`](/Users/lixiaofeng/code/gmdns/src/bin/ddns-server/error.rs) 的
`normalize_host(host, allowlist)`。

规则如下：

1. 去掉首尾空白
2. 不能为空
3. 不能包含 `*`
4. 如果最后一个 `:` 后面全是数字，就当成端口号去掉
5. 去掉结尾的一个 `.`
6. 用 IDNA 转成 ASCII
7. 转成小写
8. 最终结果必须匹配配置里的 `host_allowlist` 后缀之一

例子：

- `DNS.Genmeta.Net.` -> `dns.genmeta.net`
- `dns.genmeta.net:4433` -> `dns.genmeta.net`
- `blocked.example.genmeta.net` -> `blocked.example.genmeta.net`

`host_allowlist` 默认包含 `genmeta.net`，所以现有 `genmeta.net`
子域名仍然可用。

这条规则对所有 Redis key 都重要，尤其是黑名单成员必须写规范化之后的 host。

## 3. 各类 Redis 数据结构

### 3.1 主记录

Key 形式：

```text
<host>:fp:<fingerprint_hex>
```

例子：

```text
nat.genmeta.net:fp:db6905c72be9aa8b1a61f7d45dd399d64136da17ac384ef67f1f5670055a2946
```

Redis 类型：

```text
String
```

值的含义：

- 存的是一个二进制 `StoredRecord`
- 里面包含这条记录的完整 DNS 包、发布者证书、签名字段、过期时间等

TTL：

- 通过 `SETEX` / `SET EX` 写入
- TTL 等于服务配置里的 `ttl_secs`

业务语义：

- 同一个 `host` 下，同一个证书指纹只能有 1 条活动记录
- 同一个证书再次发布，会覆盖自己之前的记录
- 同一个 `host` 下，不同证书指纹可以并存

可以把它理解成：

```text
一个 host 下，以“证书指纹”作为主键的记录表
```

### 3.2 全量索引

Key 形式：

```text
<host>:idx:all
```

例子：

```text
nat.genmeta.net:idx:all
```

Redis 类型：

```text
Sorted Set
```

成员和值：

- member: `<fingerprint_hex>`
- score: 发布时间的 Unix 秒时间戳，代码里按 `f64` 写入

TTL：

- 每次写入相关记录时，会给这个索引 key 重新设置 `ttl_secs`

业务语义：

- 表示这个 host 当前有哪些候选发布者记录
- 查询时，如果 GEO 定向索引不够用，会回退到这个索引
- 返回顺序是最新发布的在前面，因为读取时用的是 `ZREVRANGE`

### 3.3 国家索引

Key 形式：

```text
<host>:idx:country:<country>
```

例子：

```text
nat.genmeta.net:idx:country:CN
```

Redis 类型：

```text
Sorted Set
```

成员和值：

- member: `<fingerprint_hex>`
- score: 发布时间的 Unix 秒时间戳

`<country>` 从哪里来：

- 发布时解析 DNS 包里的 endpoint IP
- 对这些 IP 做 GEO 查询
- 把得到的国家代码去重、排序后写入索引

业务语义：

- 这是按国家分桶的候选记录索引
- 查询时，如果请求方的源 IP 能解析出国家，会先尝试这个桶

### 3.4 ASN 索引

Key 形式：

```text
<host>:idx:asn:<asn>
```

例子：

```text
nat.genmeta.net:idx:asn:4134
```

Redis 类型：

```text
Sorted Set
```

成员和值：

- member: `<fingerprint_hex>`
- score: 发布时间的 Unix 秒时间戳

`<asn>` 从哪里来：

- 和国家索引一样，也是从发布内容里的 endpoint IP 做 GEO 解析得到

业务语义：

- 这是按 ASN 分桶的候选记录索引
- 查询时，如果请求方的源 IP 能解析出 ASN，会最先尝试这个桶

### 3.5 黑名单集合

Key：

```text
ddns:blacklist
```

Redis 类型：

```text
Set
```

成员格式：

- 规范化之后的小写 ASCII host 名

例子：

```text
blocked.example.genmeta.net
```

业务语义：

- 查询开始时先查这个集合
- 如果 `SISMEMBER ddns:blacklist <host>` 为真，直接返回 `404 Not Found`
- 黑名单只拦截查询，不拦截 publish，也不拦截 clear
- 黑名单不会删除已有记录

常用操作：

```bash
redis-cli SADD ddns:blacklist blocked.example.genmeta.net
redis-cli SREM ddns:blacklist blocked.example.genmeta.net
```

## 4. 主记录里到底存了什么

主记录 value 不是 JSON，也不是 Hash，而是一段连续的二进制。

顺序如下：

```text
u64  expire_unix_secs
u8   fingerprint[32]
u32  content_digest_len
u8   content_digest[content_digest_len]
u32  signature_input_len
u8   signature_input[signature_input_len]
u32  signature_len
u8   signature[signature_len]
u32  dns_len
u8   dns[dns_len]
u32  cert_len
u8   cert[cert_len]
```

字段说明：

| 字段 | 含义 |
| --- | --- |
| `expire_unix_secs` | 这条记录的业务过期时间，Unix 秒 |
| `fingerprint` | 发布者叶子证书的 SHA-256 原始 32 字节，不是 hex 字符串 |
| `content_digest` | HTTP 签名里的 `Content-Digest` 原始字节 |
| `signature_input` | HTTP 签名里的 `Signature-Input` 原始字节 |
| `signature` | HTTP 签名里的 `Signature` 原始字节 |
| `dns` | 序列化后的 DNS 包体 |
| `cert` | 发布者叶子证书的 DER 字节 |

补充说明：

- 使用大端序
- 没有版本号字段
- 三个签名字段都允许为空
- 如果记录没有签名，这三个字段长度就是 `0`

## 5. 写入时怎么维护这些结构

### 5.1 Publish

发布 `(host, fingerprint)` 时，流程是：

1. 读取旧的主记录
2. 如果旧记录能解码出来，就从旧记录推导出旧的国家 / ASN 标签
3. 先把旧指纹从所有相关索引里删掉
4. 用 `SETEX` 写入新的主记录
5. 把指纹加入：
   - `<host>:idx:all`
   - 若干 `<host>:idx:country:<country>`
   - 若干 `<host>:idx:asn:<asn>`
6. 给所有碰到的索引 key 重新设置 TTL
7. 对这些索引执行：

```text
ZREMRANGEBYSCORE <index-key> -inf <now_secs - ttl_secs>
```

这样做的效果是：

- 主记录会自然过期
- 索引里过旧的 member 也会被顺手清掉
- 同一个证书重复发布，不会在索引里留下重复脏数据

### 5.2 Clear

清理 `(host, fingerprint)` 时，流程是：

1. 读取旧主记录
2. 从旧主记录推导出它所在的国家 / ASN 桶
3. 把这个指纹从所有相关索引删掉
4. 删除主记录 key

### 5.3 一致性和自愈预期

这里的写入不是事务性的。

也就是说，一次 publish / clear 会改多个 key，但这些操作不是用单个 Redis
事务原子提交的。如果中途失败，短时间内可能出现下面这些情况：

- 主记录已经更新，但部分索引还没更新
- 索引里还留着旧指纹，但主记录已经不存在
- 某些 GEO 桶暂时缺少一条本该存在的记录

这个设计对上述短暂不一致是接受的，原因有两个：

1. 查询时真正可信的数据源始终是主记录 `String`，索引只是候选入口
2. 节点会大约每 30 秒重新上报一次，同一条记录会被持续刷新
3. lookup 只读 Redis，不再执行 `ZREMRANGEBYSCORE`；过期索引清理留在
   publish / clear 路径，或者由 primary 侧后台 sweeper 完成

这意味着：

- 如果索引里残留了一个已经失效的指纹，查询阶段读取不到主记录时会直接跳过
- 如果一次写入导致某个索引短暂漏写，下一次节点上报通常会把它补回来
- 即使没有专门的数据修复流程，TTL 和周期性重上报也会让大多数临时偏差自然收敛

因此，这套存储模型的目标是：

- 接受短暂的不一致
- 依赖 30 秒级的周期刷新实现轻量自愈
- 不为了少量短时脏索引引入额外复杂的数据修复机制

## 6. 查询时怎么用这些结构

当 Redis 存储启用时，查询流程是：

1. 规范化请求里的 host
2. 先查 `ddns:blacklist`
3. 按顺序收集候选指纹：
   - 先 ASN 索引
   - 再国家索引
   - 最后全量索引
4. 按这个顺序去重
5. 逐个读取 `<host>:fp:<fingerprint_hex>` 主记录
6. 丢弃解码失败或业务上已经过期的记录
7. 把剩下的记录交给现有排序逻辑继续处理

这里最重要的认识是：

- `Sorted Set` 只是“候选名单”
- 真正可信的数据源始终是主记录 `String`

## 7. 归属边界

`ddns-server` 自己维护下面这些 key：

- `<host>:fp:<fingerprint_hex>`
- `<host>:idx:all`
- `<host>:idx:country:<country>`
- `<host>:idx:asn:<asn>`

外部服务如果只是想做黑名单联动，只应该写：

- `ddns:blacklist`

如果外部服务想直接写记录，就必须完整实现：

- 主记录二进制编码
- 所有派生索引的增删
- TTL 维护
- 过期索引清理

否则很容易把 Redis 里的记录和索引写乱。

## 8. 一句话理解

这个 Redis 模型本质上是：

- 用一个 `String` 保存“完整记录”
- 用几个 `Sorted Set` 保存“按 host / 国家 / ASN 分类的候选索引”
- 用一个 `Set` 保存“是否禁止查询这个 host”

真正的记录内容不在索引里，索引只是为了更快找到应该读哪个主记录。
