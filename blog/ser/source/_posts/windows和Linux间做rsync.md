---
title: windows和Linux间做rsync
date: 2017-09-20 23:08:25
tags:
---

**目录**
<!-- toc -->
号外号外，弦歌服务器raid5坏了一块，然后坏硬盘插在服务器上的时候还写一个多月的数据。拔下来把新买的插上去的之后就boom,bomm,boom炸了一堆服务。就进行各种姿势的抢修。
由于弦歌的运维断代严重，一直都是12级学长做，不过之前的运维工作有很多都搁置了，所以我回来的时候就接上锅了。其中就有同步。其中有文件和数据同步，这篇就是文件的同步。
用的著名的rsync，同步的文件都是用户上传的文件。

## linux操作

参考文章：  [1](http://blog.csdn.net/old_imp/article/details/8826396)	[2](http://www.05935.com/bc/1403895/)

（参考其中部分步骤，有些步骤没用到，总体思路参照第一个网址）

如果时间没有校对，先用ntp校对

```
# ntpdate -u cn.pool.ntp.org
```

### 一、先检查在linux上有没有安装rsync和xinetd:

```
# rpm -qa | grep rsync
# rpm -qa | grep xinetd
```

若没有，则用yum安装。

```
# yum -y install rsync xinetd
```

### 二、让rsync和xinetd开机自启动

```
# chkconfig rsyncd on
# chkconfig xinetd on
```
<!-- more -->

查看是否添加成功：

```
# systemctl list-unit-files | grep xinetd
# systemctl list-unit-files | grep rsyncd
```

(7之前用chkconfig --list | grep xx就可以看到了，现在改用systemctl了，包括服务的启动之类的，不过service还是保留了)

### 三、关闭selinux

将selinux改为disabled，注释掉selinuxtype=targeted

```
# setenforce 0
```

### 四、编辑rsync.conf配置文件(注意，注释不要和参数在同一行)

```
#vim /etc/rsync.conf
```

添加

```
log file = /var/log/rsyncd.log
#日志文件位置,启动rsync后自动产生这个文件，无需提前创建
pidfile = /var/run/rsyncd.pid
#pid文件的存放位置
lock file = /var/run/rsync.lock
#支持,ax connections参数的锁文件
secretsfile = /etc/rsync.pass
#用户认证配置文件，里面保存用户的名称和密码，后面会创建这个文件
motd file = /etc/rsyncd.Motd
#rsync启动时欢迎信息页面文件位置（文件内容自定义）

[Sync]
#自定义名称
path = /home/Sync/bak
#rsync服务端数据目录路径
comment = Sync
#模块名称与[md]自定义名称相同
uid = root
#设置rsync运行权限为root
gid = root
#设置rsync运行组权限为root
port = 873
#默认端口
use chroot = no
#默认为true，修改为no，增加对目录文件软连接的备份
read only = no
#设置rsync服务端文件为读写权限
list = no
#不显示rsync服务端资源列表
maxconnections = 200
#最大连接数
timeout = 600
#设置超时时间
auth users = Sync
#执行数据同步的用户名，可以设置多个，用英文状态的逗号隔开
hosts allow = 10.10.10.199
#运行进行数据同步的客户端ip地址，可以设置多个，用逗号隔开
```

### 五、创建用户认证文件

```
#vim /etc/rsync.pass
Sync:xxx
```

格式，用户：密码，可以设置多个，每一行一个用户名：密码

### 六、添加用户

```
# useradd Sync
```

建立备份路径

``` 
# mkdir /home/Sync/bak
```

### 七、设置文件权限

```
# chmod 600 /etc/rsyncd.conf /etc/rsync.pass #设置文件只有所有者才可以进行读写。
```

### 八、启动rsync

```
# systemctl start rsyncd.service
# systemctl start xinetd.service
```

（或者用service rsyncd start,比较简洁方便，而且毕竟也是指到systemctl）
查看状态

```
# systemctl status rsyncd.service
 
# systemctl status xinetd.service
```

### 九、开启防火墙tcp 873端口

```
# firewall-cmd --add-port=873/tcp –permanent
# firewall-cmd –reload
# firewall-cmd --list-port
```

（这里采用的是centos7默认的防火墙，iptables.service不额外说）

## 第二部分，在windows端操作

### 一、windows机器上安装cwrsync

可在 https://www.itefix.net/cwrsync 去下载free版本。
下载下来有个压缩包，解压到 C:\Program Files (x86)中，

传说中运行cwrsync会配置好一切东西，但是很不幸的是PATH没配，所以要添加。

右键计算机（我的电脑、此电脑）选择属性按照图上(图已丢失)步骤来即可。
打开命令控制符输入rsync,如果出现帮助提示表示成功

### 二、测试

在D盘上建立一个文件夹test，并新建test.txt，里面添加123

在命令行输入

```
rsync.exe -vzrtopgu --progress --delete /cygdrive/D/test Sync@10.10.10.204::Sync
```

（如果把路径放在命令最后面则是反向传输备份）
输入之前在linux设置的验证密码
参数解释：

[参考网址](http://www.cr173.com/html/119298_1.html)
--delete 删除那些DST中SRC没有的文件
--progress 显示备份过程

路径格式为：
/cygdrive/盘符/备份文件路径

第二个Rsync为模块名称
在linux下查看/home/Sync/bak下的文件

```
# ls
# cd test/
# cat test.txt
```

windows下的文件添加不在这里描述。

###三、创建定时任务

先创建一个密码文件，用于rsync命令读取密码
在C盘下建立一个rsyncd.password（如果是别的路径不要带上中文或者空格）,
里面写上密码即可
再创建一个bat文件，里面写入命令：

```
rsync -vzrtopgu --progress --delete /cygdrive/c/test Sync@10.10.10.204::Sync --password-file=/cygdrive/c/rsync.pass
```

接下来就是创建任务计划程序了

打开控制面板-系统和安全-管理工具-计划任务

创建任务,详细内容百度即可，网站迁移丢失了图片。

改变文件然后等下一分钟查看linux下的文件变化，至此完成，于2017/3/18服务器炸盘后的备份补救工作。
