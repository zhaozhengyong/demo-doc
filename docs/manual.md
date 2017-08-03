# __布比区块链使用文档__

## __编译__
### Linux
支持 Ubuntu、Centos 等大多数操作系统编译，下面编译步骤以 Ubuntu 14.04 示例
- 安装依赖

```bash
sudo apt-get install automake
sudo apt-get install autoconf
sudo apt-get install libtool
sudo apt-get install g++
sudo apt-get install libssl-dev
sudo apt-get install cmake
sudo apt-get install libbz2-dev
```
- 编译

```bash
cd bubichain
chmod + x ./autogen.sh
./autogen.sh
./configure
```
生成的可执行文件目录：src/main/bubi

### Windows
- 安装 Visual Studio Ulimate 2013
- 打开 bubichain\build\win32\Bubi.vs12.sln, 使用 VS 自带编译器编译即可。生成的可执行文件在bubichain\build\win32\dbin 目录下。

## __部署__
Windows 部署与 Linux 下部署基本类似，本示例以 Linux 为准。

### __目录结构__

目录 | 描述 
|:--- | --- 
| bin | 存放可执行文件（编译后的bubi可执行程序）
| config | 配置文件目录包含：bubi.json、ca.crt、entity.crt、entity_privkey.pem、dh2048.pem
| data | 数据库目录，存放账本数据
| script | 启停脚本目录
| log | 运行日志存储目录


### __节点部署__
- 在/usr/local下创建bubichain文件夹
- 在bubichain下根据目录结构创建相应文件夹
- 把可执行文件添加到bubichain/bin目录下
- 把bubi.json拷贝到 bubichain/config目录下
- 把运行脚本添加到bubichain/script目录下
- 注册service服务

```
sudo ln -s /usr/local/bubichain/scripts/bubi /etc/init.d/bubi 
```
- 设置开机启动

 ```
sudo ln -s -f /etc/init.d/bubi /etc/rc1.d/S99bubi								
sudo ln -s -f /etc/init.d/bubi /etc/rc2.d/S99bubi								
sudo ln -s -f /etc/init.d/bubi /etc/rc3.d/S99bubi								
sudo ln -s -f /etc/init.d/bubi /etc/rc4.d/S99bubi								
sudo ln -s -f /etc/init.d/bubi /etc/rc5.d/S99bubi	
 ```
### __运行__
 ```bash
    service bubi start
  ```
### __运行状态__
 ```bash
    service bubi status
  ```
### __配置__

#### config.json 
##### 数据存储

```
    "db":{
        "ledger_path":"data/ledger.db",//
        "keyvalue_path":"data/keyvalue.db",
        "rational_db_type":"pgsql",
        "tmp_path":"tmp"
    }
```
##### 节点间网络通信
```
    "p2p":{
        "network_id":1,//节点的唯一id
        "address":"a0021ead9c8f4e30200aed9d3bfe89f7cf8e2300133d09",
        "node_private_key":"8983f237c4d9c34f29da45d56fa5dc7ffc2eab8d69897bd31d0a5eaa93a7b2f90a3d243e3ee7d743f48deb20e39134b74b761e37fa325522ae54a318cf5e2ba1194a2ed329aeb551084f86ca01536240"//节点私钥，每个节点唯一
        //加密通信配置
        "ssl":{
            "chain_file":"config/entity.crt",//用户生成的节点证书
            "private_key_file":"config/entity_privkey.pem",//用户生成的节点私钥
            "private_password":"42001df2a1f54974baa38073eae2ee53",//aes加密私钥
            "dhparam_file":"config/dh2048.pem",
            "verify_file":"config/ca.crt"//验证证书
        },
        //共识网络
        "consensus_network":{
			"heartbeat_interval":60,
            "listen_port":6333,//已监听的端口
            "target_peer_connection":50,
            "known_peers":[
                "127.0.0.1:6333"//连接参与共识的节点
            ]
        }
    }
```
##### 访问通信配置，对外通信配置
```
    "webserver":{
        "listen_addresses":"0.0.0.0:29333",
        "remote_authorized":false//部分接口权限
    }
```
##### 通信配置，对外通信配置
```
    "wsserver":{
        "listen_address":"0.0.0.0:7053"
    }
```
##### 区块配置
```
    "ledger":{
        "genesis_account":"a0017bb37115637686a4efd6fabe8bfd74d695c3616515",//创世账号，同一条链上的每一个节点都必须唯一
        "hash_type":1,// 0 : SHA256 1: SM3 //账号的hash类型
        "max_trans_per_ledger":1000,
        "max_ledger_per_message":5,
        "max_trans_in_memory":2000,
        "max_apply_ledger_per_round":3
    }
```

##### 日志配置
```
    "logger":{
        "path":"log/bubi.log",//日志目录
        "dest":"FILE|STDOUT|STDERR",//输出文件分类
        "level":"TRACE|INFO|WARNING|ERROR|FATAL",//日志级别
        "time_capacity":1,
        "size_capacity":10,
        "expire_days":10
    }
```

##### 共识配置
```
    "validation":{
        "type":"pbft",//共识类型
        "address":"a0024740b934765287b16113adc6bb285d72c124d9e3c1",//节点私钥对应的地址
        "node_private_key":"44b9aad4310804fd528d1e73da1d093abc09b5cbbaa85ff6e60e51d408a856565efd9c1f9f899c125c11d8c021b3935c935c3078cf739a765e0b2c6c9b9156feaaa4984fd2811f4eb07610029f55c44d",//私钥，每个节点唯一
        "close_interval":3,//区块关闭时间
        "validators":[
            "a0024740b934765287b16113adc6bb285d72c124d9e3c1",//参与共识的节点地址
            "a002c5199f9dd53b009ca8f54e1921b0ebee1cb60de2b9"
        ]
    }
```
#### 多节点配置说明
- 下面示例是配置多个节点在一条链上运行示例，配置多节点主要修改p2p、validation和ledger这三块的设置
##### 节点间网络通信
- known_peers填写其他节点的ip以及port,
- ssl填写每台机器申请到的证书信息,
- node_private_key和network_id保证唯一
- address与node_private_key是成对应关系
##### 共识配置
- node_private_key保证唯一
- validators填写每个节点validation的address
- address与node_private_key是成对应关系

##### 区块配置
- genesis_account是创世账号，同一条链上，每个节点配置中genesis_account的值必须一致

注意：运行前请确保每个节点的初始数据是一致，否则无法达成共识产生区块
#### 配置同步节点
 - 配置同步节点与验证节点有一点不同的是共识配置中validators不需要填写同步节点validation的address
 
##### 加密数据配置
配置文件中所有隐私数据都是加密存储的，解密密钥都是被硬编码在程序中。所以拿到密码明文后需要经过如下转换才可配置：

- 命令./bin/bubi --aes-crypto [参数]

```bash
[root@localhost bubichain]# ./bin/bubi --aes-crypto root e2ba44bf0b27f0acbe7b5857e3bc6348
```
- 需加密配置项 

名称 | 描述 
|:--- | --- 
| config.p2p.private_password |证书解密密码
| config.validation.node_private_key | 共识节点私钥

#### __证书配置__
最新版本布比区块链默认启用节点证书接入，采用双向认证方式。

##### 相关文件

名称 | 描述 
|:--- | --- 
| ca.crt | 本区块链所有节点的根证书
| entity.crt | 本节点的证书，由根证书签发
| entity_privkey.pem | 节点证书密钥，使用时需解密。密码被加密配置在 config.p2p.private_password

##### 生产根证书
- 将bubi_ca文件放在bubichain/bin/下
- 配置config/ca.json

```
{ "root" : { "file_name" : "ca", //根证书的名称"common_name" : "bubi", //证书签发机构名称"email" : "hr@bubi.cn", //证书签发机构邮箱"domain" : "www.bubi.cn", //证书签发机构网站"days" : 3650, //根证书有效期"private_password" : //根证书私钥密码 "42001df2a1f54974baa38073eae2ee53" }, "entity" : { "root_private_file" : "ca.pem", //根证书私钥名称"root_ca_file" : "ca.crt", //根证书名称"root_private_password" : //根证书私钥密码 "42001df2a1f54974baa38073eae2ee53","request_file" : "node_bubi.csr", //待签名文件"days" : 3650, //节点证书有效期"ca_enable" : true//是否开启ca验证 }, "logger" : { "path" : "log/bubi.log", "dest" : "FILESTDOUTSTDERR", "level" : "INFOWARNINGERRORFATAL", "time_capacity" : 1, "size_capacity" : 10, "expire_days" : 5 } }
```

- 执行./bin/bubi_ca--root

```
[root@localhost bubichain]# ./bin/bubi_ca --root root certificate file: /usr/local/bubichain/config/ca.crt private file: /usr/local/bubichain/config/ca.pem
```

- 在config下会生成ca.crt,ca.pem两个文件

##### 获取节点硬件地址

```
[root@localhost bubichain]# ./bin/bubi --hardware-addresslocal hardware address (0bc9143ba7ccc951cf257948af2d02ff)
```

##### 生成节点证书

- 请求证书的的命令./bin/bubi --request-cert 后加参数（全部英文）
- 参数解释
 
| 名称 | 描述
|:--- | --- 
|common_name |节点名称 
|organization |  组织机构名称 
| email | 联系邮箱 
|private_password | 证书私钥（明文）
| hardware_address |硬件地址（由上一步获取）
| node_id | 节点id，可不填
 
- 生成文件在bubichain/config目录下 node_bubi.csr：请求证书，node_bubi.pem：证书私钥

```
[root@localhost bubichain]# ./bin/bubi --request-cert //生成节点证书命令，参数含义 missing parameter, need 6 parameters (common_name, organization, email, private_password, hardware_address, node_id(when ignore, it's *) [root@localhost bubichain]# ./bin/bubi --request-cert node bubi bubi@bubi.cn bubitest 0bc9143ba7ccc951cf257948af2d02ff  request file : /usr/local/bubichain/config/node_bubi.csr private file : /usr/local/bubichain/config/node_bubi.pem 0bc9143ba7ccc951cf257948af2d02ff the request certificate information: { "ca" : { "extensions" : { "hardware_address" : "0bc9143ba7ccc951cf257948af2d02ff", "node_id" : "*" }, "subject" : { "common_name" : "node", "email" : "bubi@bubi.cn", "organization" : "bubi" } } }
```

##### 将待签发证书文件发送给管理员

通过邮件或其他方式将node_bubi.csr文件发送给系统管理员，等待管理员签发证书

##### 管理员签发证书
- 修改config/ca.json配置文件中待签名文件名称
- 执行./bin/bubi_ca --entity
- 生成节点证书
- 将ca.crt及node_bubi.crt发送给用户

##### 接收管理员签发的证书
- 保存管理员发送的node_bubi.crt文件及ca.crt文件
- 将上面两个文件放到bubichain/config下

## __运维__
### 服务启动与停止
```
启动    :service bubi start
关闭    :service bubi stop
运行状态:service bubi status
```
### 查看系统详细状态
```
[root@centos7x64-201 ~]# curl 127.0.0.1:19333/getModulesStatus
{
    "glue_manager":{
        "cache_topic_size":0,
        "ledger_upgrade":{
            "current_states":null,
            "local_state":null
        },
        "system":{
            "current_time":"2017-07-20 10:32:22", //当前系统时间
            "process_uptime":"2017-07-20 09:35:06", //bubi启动时间
            "uptime":"2017-05-14 23:51:04"
        },
        "time":"0 ms",
        "transaction_size":0
    },
    "keyvalue_db":Object{...},
    "ledger_db":Object{...},
    "ledger_manager":{
        "account_count":2316,  //账户数
        "hash_type":"sha256",
        "ledger_sequence":12187,
        "time":"0 ms",
        "tx_count":1185   //交易数
    },
    "peer_manager":Object{...},
    "web server":Object{...},

```
### 查看具体数据信息
```
[root@centos7x64-201~]#curl 127.0.0.1:19333/getAccount?address=a0024111d1cc90ac8ee0abd5f957e08e3e1b442b581e88
{
  "error_code": 0,
  "result": {
    "address": "a0024111d1cc90ac8ee0abd5f957e08e3e1b442b581e88",
    "assets": null,
    "assets_hash": "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3",
    "contract": null,
    "metadatas": null,
    "priv": {
      "master_weight": 1,
      "thresholds": {
        "tx_threshold": 1
      }
    },
    "storage_hash": "ad67d57ae19de8068dbcd47282146bd553fe9f684c57c8c114453863ee41abc3"
  }
} [root@centos7x64-201 ~]#

```
### 清空数据库
```
bubichain/bin/bubi --dropdb
```
### 数据库存储
布比区块链存储的数据默认是存放在bubichain/data目录下，如有需要可修改配置文件中数据存储部分
