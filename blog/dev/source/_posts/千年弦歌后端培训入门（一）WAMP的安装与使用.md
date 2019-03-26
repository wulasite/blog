---
title: '千年弦歌后端培训入门（一）WAMP的安装与使用 '
date: 2019-01-23 23:38:50
tags: PHP
---


1. [千年弦歌后端培训入门（一）WAMP的安装与使用](https://dev.qqx.im/2019/01/23/%E5%8D%83%E5%B9%B4%E5%BC%A6%E6%AD%8C%E5%90%8E%E7%AB%AF%E5%9F%B9%E8%AE%AD%E5%85%A5%E9%97%A8%EF%BC%88%E4%B8%80%EF%BC%89WAMP%E7%9A%84%E5%AE%89%E8%A3%85%E4%B8%8E%E4%BD%BF%E7%94%A8/)
2. [后端教程资料](https://gitlab.qnxg.net/qqx/backend_class)


# 写在前面的话

现弦歌的培训模式需要人授课，如果每届都重新写的话会浪费大量的世间，所以需要形成一套教程，博文或者视频都无可以，所以就有了这文章。这套文章并不会讲解PHP知识，只有一些工具的使用，方便更好的入门PHP，虽然这么做会减少新人解决问题的能力，但这个能力也不是一天两天能培养起来的。

## 一、下载WAMP

WAMP是啥？在开始之前需要了解一下这个之后会经常使用的软件。WAMP是windows apache mysql php的缩写，相对应的还有LAMP，L对应的就是linux了。而apache也是个应用，主要负责处理 发送到它所在的服务器 的http请求（http请求简而言之就是平常打开浏览器访问一个网页 就是向某个服务器发送http请求）； mysql是种关系型数据库，就是存放数据的地方，用的存储的结构好像是B/B+树，学好数据结构很重要啊；这里的php就是php语言的解释器，就像写C++还需要一个编译器，devc++用的是mingw。有了这三样就可以开始写PHP代码了。

大一新生可能连百度可能都不会用，所以先从百度开始记录吧。

直接在[百度](https://www.baidu.com/)上搜索WAMP，就会出现如下

![](https://qqx.im/mdimage/wamp/baidu.png)

一个WAMPSERVER就是了。点进去就会看到

![](https://qqx.im/mdimage/wamp/start.png)

如果点不进去就直接去 [SourceForge](https://sourceforge.net/projects/wampserver/files/) 下载，进得去的就点击红圈的字样，会跳到下面下载的地方

![](https://qqx.im/mdimage/wamp/download.png)

下面两个黄色的button似乎是摆设，所以点击进[SourceForge](https://sourceforge.net/projects/wampserver/files/)下载吧

以后下载东西很多都是这么下载的，先直接打开百度-直接搜索软件名字-从官网下载-如果官网付费或者打不开-再去百度别的地方下载。

## 二、安装

安装就点下一步就好了，不用更改什么设置，最重要的是记住安装位置，比如我的是E:\wamp64这个是要记住的。

## 三、使用

安装完成后直接双击桌面的wampserver64启用即可，成功启用的标志是图标变成绿色的

![](https://qqx.im/mdimage/wamp/status.png)

黄色说明有的服务没成功启用，红色代表都没启用。

接下来左键点击绿色图标，列出功能列表，就可以看到一些功能，这个列表主要是管理这几个软件的，功能应有尽有，不管是管理虚拟主机的，还是apache php mysql都有

![](https://qqx.im/mdimage/wamp/function.png)

比如localhost就是用之前安装的时候设置的默认浏览器访问localhost，一般是IE



![](https://qqx.im/mdimage/wamp/localhost.png)

刚开始安装会显示wamp的主页，但是我这里的index.php替换了。所以是上图。

那么如何开始写PHP呢，返回到上面的功能列表，点击www directory，就可以进入网站的根目录了，localhost访问的就是这个目录，默认是index.php or index.html等。新建一个hello.php，一定要是php结尾的，然后在里面输入

```php
<?php
	echo "hello world!";
?>
```

![](https://qqx.im/mdimage/wamp/hellocode.png)

然后在浏览器访问 [http://localhost/hello.php](http://localhost/hello.php)

即可看到hello world!

![](https://qqx.im/mdimage/wamp/hello.png)