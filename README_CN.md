<p align="center">
  <a href="https://github.com/genmeta/ddns" title="DDns">
    <img src="https://media.dhttp.net/img/ddns/ddns-logo-lockup.svg" width="600" alt="DDns">
  </a>
</p>
<p align="center">
  <a href="https://crates.io/crates/dyns"><img src="https://img.shields.io/crates/v/dyns?label=crates.io" alt="Crates.io"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://docs.dhttp.net/zh/docs/protocol/ddns"><img src="https://img.shields.io/badge/docs-dhttp.net-ff9900.svg" alt="Documentation"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.85%2B-dea584.svg" alt="Rust"></a>
</p>

[English](README.md) | **简体中文**

## 动机

域名是非常好的主机标识，不仅易读，而且可在全球范内接受访问。
**遗憾的是，只有服务端才配拥有域名！**

### 为什么客户端不能拥有？

DNS 协议起着解析域名到 IP 地址的重要作用，这就要求主机得有路由可达的 IP 地址；
又因为 DNS 的解析结果仅包含 IP 地址，这又要求主机要能自己控制监听的端口，尤其是 Web 服务多台主机共用一个域名时，它们必须全部都得监听相同的 443 端口。

反观客户端，大多位于 Wi-Fi 家庭网络、移动网络等私网中，只有自己所在的局域网内路由可达的 IP 地址，
该地址完全不具备广域网路由可达的能力，隐藏在公网中，公网的数据包也没法主动路由到此。
即便进一步来讲，私网主机访问因特网，总是会有一个经 NAT 转换的公网 IP 地址，
一来该公网 IP 地址经常变化；二来，私网主机更大的麻烦是无法妥善控制 NAPT 映射的公网端口，
多个私网主机想经 NAPT 映射到公网 IP 下的相同端口（比如，都想监听公网 IP 下的 443 端口）更不可能。

以上这些原因，导致**私网主机即便有域名，作用范围也十分有限**。
从另一角度看，域名成了服务端的专属，DNS 协议也只服务于服务端，
一如早期人类社会阶级的存在，**服务端是有名有姓的贵族，客户端则成了籍籍无名之辈**。

## E 记录

众所周知，私网端点的 IP 地址在广域网上路由不可达；
但少有人想到，只要给每个私网端点配一个公网端点作为其授权中介“代理”，
就能让任何一个端点都拥有了全球路由可达的能力。

E 记录（Endpoint Address 记录）就是采用这个思路，为私网端点配备公网端点作为中介“代理“；
再加上网络地址的端口信息，让私网端点不用为在公网上监听不到 443 端口而发愁，
随机监听任意端口，对端都能通过 E 记录里的端口发送数据报文最终路由到此。 
数据报文路由给中介“代理“，就如同路由给私网端点，
只要数据报文写明最终目标地址是私网端点，中介“代理“只需简单地转发给目标地址即可。

```rust
// E 记录核心内容：
pub enum EndpointAddr {
    Direct {
        addr: SocketAddr,
    },
    Mediate {
        agent: SocketAddr,
        outer: SocketAddr,
    },
}
```

### 与 A/AAAA 记录的区别

| | A/AAAA 记录 | E 记录 |
| --- | --- | --- |
| 解析结果 | IP 地址 | IP + 端口 |
| 私有网络 | 不适用 | 适用，通过 `EndpointAddr::Mediate` |
| 单机多地址 | 无关联 | 可关联 |
| 更新方式 | 由管理员配置 | 由端点自主发布和更新 |

A/AAAA 记录仍适用于云主机，**E 记录则普适于所有端点**。
E 记录提供候选地址，实际可达性仍由连接层验证；[DQuic](https://github.com/genmeta/dquic) 可使用这些地址建立点到点和多路径连接。E 记录当前使用尚未由 IANA 分配的 RRTYPE `266`。

> [!TIP]
>
> - **自主上报**：端点自行探测并发布自己的 EndpointAddr，网络变化时立刻通告更新。通过 DoH(DNS over HTTP) 发布时，解析服务还会校验名字合法性和记录内容签名正确性。
> - **单机多地址**：一台手机可以同时拥有 Wi-Fi 家庭网络和移动蜂窝网络，每个网络又都支持 IPv4、IPv6 双栈，因此它可以拥有多条 EndpointAddr，按设备编号关联为一组。这对多路径传输的 QUIC 协议而言十分重要。
> - **一名多设备**: 同一个名字下也可以有多个端点，比如一个域名对应一组服务器，每台独立的服务器通过不同编号来区分。


### 名字空间上的隔离性

为了避免与传统 DNS 域名冲突，DHttp 名字都注册在 `dhttp.net` 子域下，

<p align="center">
  <img src="https://media.dhttp.net/img/dhttp-namespace.jpg" width="720" alt="名字空间">
</p>

为了简便，`.dhttp.net` 可以用 `~` 替代，比如：

- **home 域**：`.home.dhttp.net`，简写 `.home~`
- **robot 域**：`.robot.dhttp.net`，简写 `.robot~`
- **service 域**：`.svc.dhttp.net`，简写 `.svc~`
- **car 域**：`.car.dhttp.net`，简写 `.car~`

> 传统的 DNS 域名不会以现实生活中的姓氏结尾，因为姓氏多、维护成本高昂，一个姓氏就要一个机构，不够灵活。
> 但在 DDns 中，姓氏可以出现在名字尾域，更贴近现实。


## DNS 解析

DHttp 域名可以通过 mDNS 和 DoH 查询；传统域名仍由 System DNS 解析应用可按名字和网络环境组合这些方式：

| 方式 | 用途 |
| --- | --- |
| mDNS | 局域网中应答或发起 DDns 查询；`.dhttp.net` 在 mDNS 中映射为 `._dhttp.local` |
| DoH | 通过 HTTP 发布、查询 DDns 记录 |
| System DNS | 传统域名仍交给 `getaddrinfo` 解析 |

> 目标位于局域网时，优先使用 mDNS 获得私网地址，传输时也将局域网优先，更加隐私、高效。

<p align="center">
  <img src="https://media.dhttp.net/img/ddns/ddns-e-record.jpg" width="720" alt="DDns 将一个名字解析为多个端点各自的 E 记录与 Endpoint Address">
</p>

`alice.smith~` 可对应手机、电脑等多个端点，每个端点也可拥有数量不同的 E 记录。
每条 E 记录描述一组 `EndpointAddr`，同一端点的记录由设备编号表征；
图中的网络图标仅表示地址来源。`~` 的命名规则参阅 [DDns 协议文档](https://docs.dhttp.net/zh/docs/protocol/ddns)。

## 快速开始

安装 Rust 和 Git 后，克隆仓库并运行 mDNS 示例：

```bash
git clone https://github.com/genmeta/ddns.git
cd ddns
cargo run --example mdns_discover --features mdns -- \
  --ip YOUR_LOCAL_IP \
  --device YOUR_NETWORK_INTERFACE
```

将 `YOUR_LOCAL_IP` 和 `YOUR_NETWORK_INTERFACE` 替换为本机地址及其网络接口。该示例会绑定该接口，发布内置的 E 记录，并打印收到的 mDNS 数据包。

其他查询、发布和 Rust API 示例参阅 [示例与命令说明](examples/README.md)。

## 参与贡献

欢迎提交 Bug 报告、协议讨论、文档改进和代码贡献。涉及 E 记录格式或解析协议的变更，请先通过 [GitHub Issues](https://github.com/genmeta/ddns/issues) 讨论兼容性影响。
