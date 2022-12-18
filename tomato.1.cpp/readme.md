# tomato

tomato是一个代理工具集，其核心是基于c++/asio的一系列代理服务类库（/src）。
tomato不直接提供启动代理服务的可执行文件，而是提供命令行风格的C API方便其它语言调用（/src/tomato-cli.h）。
tomato官方提供了一个基于python/ctypes的启动器（/tomato.py）。

## 启动设置

```
apt install build-essential cmake libasio-dev libssl-dev libmaxminddb-dev python3 # 安装依赖

cd certs # 生成自签名证书
./gencert.sh
cd ..

cd src # 配置
cp tomato-cfg.h.in tomato-cfg.h
vi tomato-cfg.h
cd ..

mkdir build # 编译
cd build
cmake ..
make
cd ..
```

生成的自签名证书分成两部分：key.pem和cert.pem，应保证key.pem的私密性，并将cert.pem发送给TLS服务的使用者。
在生成自签名证书的过程中会询问证书所有者的一些信息，除了COMMON NAME（域名）外都可以随意填写或不填。
COMMON NAME建议填一个看上去正常的域名。如果TLS服务的使用者未通过该域名访问，则应通过-H参数指定该域名，否则证书验证失败。

在配置中有两个参数需要注意：`TOMATO_NO_TFO`和`TOMATO_TLS_ALLOW_DOWNGRADE`，分别表示关闭TCP FASTOPEN和TLS1.3 ONLY。
出于性能和安全性考虑这两个功能默认开启，但是在实际使用中启用这两个功能可能会成为明显的特征。如果使用场景需要HTTPS混淆，建议关闭这两个功能。

## 命令行参数

```
usage: tomato.py [-h] [-i INBOUND] [-o OUTBOUND] [-c CERTFILE] [-k KEYFILE] [-C] [-H HOSTNAME] [-P PASSWORD] [-r RULESFILE] [-s]

optional arguments:
  -h, --help            show this help message and exit

  -i INBOUND, --inbound INBOUND
                        Proxy inbound url.

  -o OUTBOUND, --outbound OUTBOUND
                        Proxy outbound url.

  -c CERTFILE, --certfile CERTFILE
                        TLS certfile. Default is certs/cert.pem.

  -k KEYFILE, --keyfile KEYFILE
                        TLS keyfile. Default is certs/key.pem.

  -C, --certdfl         Use system default certfiles to verify TLS. It's useful to specify an self-signed certfile. Only client side need this option.

  -H HOSTNAME, --hostname HOSTNAME
                        Hostname to verify TLS. Default is server side hostname in it's url. Only client side need this option.

  -P PASSWORD, --password PASSWORD
                        Password of keyfile if needed.

  -r RULESFILE, --rulesfile RULESFILE
                        Socks5F rulesfile. It's useful to bypass or block ips from a set of mmdb files. It's useful to bypass or block domains from a set of txt files.

  -s, --strict          Socks5 server only accept fold request. It's useful to prevent active detection.
```

tomato.py通过inbound和outbound的scheme决定启动的代理服务类型。例如：

```
./tomato.py -i raw://localhost:1080 -o tls://www.baidu.com:443 -C
```

tomato.py通过scheme：(raw, tls)判断服务为raw2tls，将本地1080端口收到的原始请求通过TLS转发至www.baidu.com的443端口。
-C参数决定使用系统默认的证书库对TLS进行认证，而不是自签名证书（certs/cert.pem）。

## 服务类型

### forward

```
./tomato.py -i raw://localhost:1080 -o raw://www.baidu.com:80
```

最原始的流量转发。支持不同地址族（ipv4/ipv6）间的转换。

### tls2raw、raw2tls

```
./tomato.py -i tls://[::]:443 -o raw://localhost:3315
./tomato.py -i raw://localhost:33150 -o tls://mysqlserver.local:443
```

TLS流量和原始流量相互转换。可以通过TLS协议安全地将不支持TLS的内网服务暴露于公网中，也可以将TLS流量转为原始流量以方便不支持TLS的应用程序访问。

### socks5、socks5s

```
./tomato.py -i socks5://localhost:1080
./tomato.py -i socks5s://myname:mypwd@localhost:443
```

Socks5是使用最广泛的代理协议之一（另一个是HTTP代理）。Socks5S即Socks5 over TLS的简写。
代理协议避免了大量的手动配置开启代理与配置域名解析结果（DNS、hosts文件），而是通过支持代理协议的程序主动连接代理并在代理请求头中指明代理的目标。
tomato实现的Socks5与Socks5S协议支持两种请求格式：标准请求和压缩请求，与前者相比后者握手次数更少（没有握手直接发起请求）。
在命令行添加-s参数进入严格模式，在该模式下Socks5、Socks5S服务仅接受压缩格式的请求以避免主动探测。

### socks5f

```
./tomato.py -i socks5://localhost:1080 -o socks5s://myname:mypwd@proxyserver.net:443 -r rules/default.txt
```

socks5f可以将Socks5协议的流量转为Socks5S协议的流量，这个功能类似于raw2tls：

```
./tomato.py -i raw://localhost:1080 -o tls://proxyserver.net:443
```

但socks5f做了更多事：

1. 将标准格式请求转为压缩格式请求：不仅可以降低延迟，还可以配合服务端的严格模式防止主动探测。
2. 认证转换：有很多应用支持Scoks5代理但不支持Socks5认证，socks5f在转发Socks5请求前会修改认证字段。
3. 基于IP地址的分流。

socks5f对一个请求有三中处理方式：block、proxy和direct。block终止当前连接，proxy正常代理，direct本地代理。
socks5f通过-r参数指定以下格式的规则文件：

```
proxy
ip rules/cn.mmdb direct
ip rules/tracker.mmdb block
domain www.baidu.com direct
domains rules/github.txt proxy
```

第一行表示默认的处理方式为proxy，即正常代理。
第二行表示对目标地址为cn.mmdb中的地址时的处理方式为direct，即本地代理。
第三行表示对目标地址为tracker.mmdb中的地址时的处理方式为block，即丢弃该请求。
第四行表示对目标域名为www.baidu.com时的处理方式为本地代理。
第五行表示对目标域名为github.txt内的域名时的处理方式为正常代理。

用户可以在此处[(geoip)](https://github.com/Loyalsoldier/geoip)下载mmdb格式的精简版中国IP数据库。

### acceptor、connector

```
./tomato.py -i raw://[::]:2222 -o connector://myname:mypwd@[::]:443
./tomato.py -i acceptor://myname:mypwd@acceptor.net -o raw://localhost:22
```

acceptor、connector用于代理无法主动连接目标，但目标可以主动连接代理的情景。
一个常见的情景是将处于NAT或防火墙之后的内网中的服务绑定到处于公网的代理上。

示例的第一行表示acceptor先等待connector连接443端口并进行认证，成功后开始监听2222端口。当收到请求时随机绑定一个本地端口，然后接通知connector。

示例的第二行表示connector连接acceptor:443的acceptor并进行认证，成功后开始等待acceptor的通知。当收到通知时，connector连接通知的端口并将其流量转发至反向代理的目标服务。
