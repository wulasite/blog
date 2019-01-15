---
title: 虚拟机中设置桥接模式的静态IP
date: 2017-09-20 22:21:57
tags:
---

P是为了在相通的局域网下能访问到虚拟机中的主机。做了桥接之后VM虚拟机中的系统就像一台物理机一样，占着一个IP，大家都可以访问到它。
应用场景：内网服务器，比如FTP和云盘等、需要他人远程本地虚拟机等等。
缺点：这个的缺点其实不算缺点，就是物理机的IP和网关变的话，虚拟机中也要改配置，但一般情况下同一地点的不会变。
至于桥接模式、NAT模式和仅主机模式的区别上网搜索即可。

## 更改虚拟机配置

1. 查看物理机当前上网使用的网卡
   右键点击小电脑-打开网络和共享中心-连接：以太网（WLAN）-属性即可看到当前上网使用的网卡。以太网网卡名字一般都是Realtek PCIe GBE Family Controller这种，而无线网卡一般是Qualcomm Atheros AR5BWB222 Wireless Network Adapter这种。

2. 更改虚拟机配置
   在VM菜单的编辑-虚拟网络编辑器中更改设置，如图：
   ![](http://a.wulasite.me/mdimage/vmNet.jpg)


   如果不是以管理员身份运行VM就会需要提供管理员权限才能更改设置。
![](http://a.wulasite.me/mdimage/vmNetSet.jpg)

   点击添加网络，选择要添加的名称，一般是VM0，点击确定，然后选择桥接模式，选择桥接到的网卡：

   点击确定即可。
   还有一步是把系统的网络适配器网络接入改为桥接模式


   复制状态可勾可不勾

##  更改系统配置

centos以centos6.5为例，与7不同的地方在于网络适配器的名字。6是eth0,7是ethxxxxx。
更改网络配置文件：

```
vim /etc/sysconfig/network-scripts/ifcfg-eth0
```

六个重要选项：

```
BOOTPROTO：IP分配方式，分为dhcp、none和static，不知道有没有其它的方式
IPADDR：设置的静态IP地址
NETMASK：子网掩码
GATEWAY：网关
DNS1：DNS服务器地址
ONBOOT:表明系统在启动时是否激活网卡
```

设置好了之后就可以重启网络：

```
service network restart
```

在设置静态IP之前不确定要设定的IP是否被人占用可先ping试试
重启网络完了之后需要物理机和虚拟机互ping，看一下网络状态，ifconfig也可看一下配置文件是否生效。
如果不通，回去检查一下配置，如果出现物理机能ping通虚拟机，虚拟机ping不通物理机，或者反之，有可能需要等一会。

buntu以16.04为例
与centos核心思想一样，修改适配器配置文件（需要root）即可。

```
vim /etc/network/interfaces
```

```
# interfaces(5) file used by ifup(8) and ifdown(8)
auto lo
iface lo inet loopback
# The primary network interface
auto ens33
iface ens33 inet static
address 192.168.1.21
netmask 255.255.255.0
gateway 192.168.1.1
```

根据自己的配置信息修改即可。

接下来修改DNS服务器：

```
vim /etc/resolv.conf
```

添加nameserver 114.114.114.114。

保存完之后重启网络：

```
service networking restart
```

如果DNS服务器不行可尝试重启。


