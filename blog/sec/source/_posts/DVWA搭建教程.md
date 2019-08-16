---
title: DVWA搭建教程
date: 2019-01-25 13:53:50
tags: 
---


**目录**
<!-- toc -->
DVWA(Damn Vulnerable Web Application)是一个包含一些基本WEB漏洞的web应用，特别适合新手入门WEB渗透，其中有不同的难度和源码展示，让小白更深入的理解漏洞产生的原因以及攻击的时候在代码层面发生了什么。本文主要讲述DVWA的搭建教程，而使用教程在[freebuf](https://www.freebuf.com/articles/web/123779.html)上面有比较完整的。而类似这种平台的还有webgoat,但会属于稍微进阶点的，偏实战的。

网上其实有很多DVWA的搭建教程，但感觉都不怎么适合协会这边的新手，所以给出一套教程，也方便互动。

DVWA是基于PHP/MYSQL的，所以需要这些基本环境，而这些环境的教程在我的[另外一篇博客](https://dev.wulasite.top/2019/01/23/%E5%8D%83%E5%B9%B4%E5%BC%A6%E6%AD%8C%E5%90%8E%E7%AB%AF%E5%9F%B9%E8%AE%AD%E5%85%A5%E9%97%A8%EF%BC%88%E4%B8%80%EF%BC%89WAMP%E7%9A%84%E5%AE%89%E8%A3%85%E4%B8%8E%E4%BD%BF%E7%94%A8/)有。

## 一、下载

直接下载它的github的[archive](https://github.com/ethicalhack3r/DVWA/archive/master.zip)即可，去官网也是这个下载链接。



## 二、安装

将刚才下载好的压缩包解压至web根目录，像wamp的就可以通过电脑左下角的wamp图标左键单击出来的功能列表中的www directory进入，这个在搭建教程中也有提到，而这个目录其实就是wamp安装目录下的www文件夹，像我的就是E:\wamp64\www

![](https://wulasite.top/mdimage/wamp/function.png)
<!-- more -->

解压完成后需要重命名成dvwa，方便访问和管理

![](https://wulasite.top/mdimage/dvwa/dvwa.png)

然后直接在浏览器访问[http://localhost/dvwa](http://localhost/dvwa)，记得开wamp。

访问之后会提示没有配置文件，所以要将dvwa中的config/config.inc.php.dist复制一份重命名为config.inc.php，再刷新就可以看到。

![](https://wulasite.top/mdimage/dvwa/start.png)

有一个function是红的，由于要做渗透测试，所以需要打开它。

还是像上面那个操作，电脑左下角的wamp图标左键单击出来的功能列表中的PHP，可以有两种方法，一种是勾选-PHP设置-allow_url_include，一种是点击php.ini，会打开php配置文件，然后搜索allow_url_include，将指改为allow_url_include = On



![](https://wulasite.top/mdimage/dvwa/allow.png)

其实这步不做也可以，但是为了里面的一些测试做一下。

接下来就是修改配置文件了，上面提到的config/config.inc.php,在里面修改数据库以及一些配置

主要修改的是数据库密码和默认等级

![](https://wulasite.top/mdimage/dvwa/config.png)

如果不知道数据库密码的可以试一下空，或者自己百度如何修改忘记的MYSQL数据库密码。修改完之后，点击下面的创建数据库，如果成功了有如下图一样的出现Setup success，如果不成功，会提示失败原因

![](https://wulasite.top/mdimage/dvwa/complete.png)

然后点击login跳到登录界面，使用admin/password即可登录DVWA