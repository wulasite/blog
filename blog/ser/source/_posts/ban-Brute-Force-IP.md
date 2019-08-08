---
title: ban Brute Force IP
date: 2017-09-20 20:15:34
tags:
---

前阵子听家浩说，他的服务器商告诉他他的服务器多次登录失败。家浩后面用iptables ban了IP。

后来有时间了，突然想起这件事，上网搜查了一下，找到了几种办法。一种是用DenyHosts脚本的，一种是iptables的，其他的也差不多。但是用了一下DenyHosts脚本的感觉有点麻烦，不如直接自己写个。

首先，改ssh的端口，但是在此之前先开iptables，改服务端口前一定要先开iptables的端口，前天因为这被挡在门外了，随意感受下那时的心情。

首先 vim/etc/sysconfig/iptables

![](https://wulasite.top/mdimage/iptables.png)

把22端口的规则注释掉，添加新端口规则。保存退出。

然后再 

```vim/etc/ssh/sshd_config
vim /etc/ssh/sshd_config
```

![](https://wulasite.top/mdimage/Port.png)

找到这行，把注释取消，后面填上对应的端口。



这时候激动人心的时候到了，重启iptables和sshd，然后新开的连接，没什么意外的话你还是能重新连接的，如果有意外，恭喜你，你就被挡在外面了，自己去找服务器供应商吧（所以找谭师傅买主机有好处，挂了方便给你弄好），所以这是高危操作！谨慎！

```
service sshd restart
service iptables restart
```

接下来是看自己的主机有没有被人尝试着爆破，在网上看到一个awk

```
cat /var/log/secure|awk '/Failed/{print $(NF-3)}'|sort|uniq -c|awk '{print $2"="$1;}'
```

![](https://wulasite.top/mdimage/boom.png)

```
cat /var/log/secure|awk '/Failed/{print $(NF-3)}'|sort|uniq -c | awk '$1>20 {print "sshd:",$2}'>>/etc/hosts.deny
```

然后放到脚本里，再用crontab每小时执行一次。
如果没有crond服务就

```
yum install crontabs
service crontab start
```

然后添加任务

```
crontab -u root /root/
vim /var/spool/cron/root
```

添加*/30 * * * * * /root/DenyHosts.sh

每半小时执行一次。
执行

```
crontab -l
```

查看是否有记录。
