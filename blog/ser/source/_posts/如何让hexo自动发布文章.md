---
title:  如何让hexo自动发布文章
date:  2018-09-20 23:08:25
tags:
---

本文条件

```
1. 有台自己的服务器
2. 使用的是hexo
```

拖文章上传实在实在实在是太烦了，于是趁期末差不多考完的空档，弄下hexo的自动部署。这样就可以一次push，自动生成文章。

利用到的知识点

```
1. git的push出发的hook
2. git远程仓库
```

首先在服务器上装个git，然后在hexo的source/_post/里运行git init，这样就生成了一个git远程仓库。

需要做些修改，首先是将改_post目录改成777权限

```shell
chomod 777 -R _post/*
```

要确保.git以及子目录都是git用户可读写的。

再者修改.git/config，在后面追加

```
[receive]
    denyCurrentBranch = ignore
```

修改这两处是因为前者会导致git push的时候出现permission deny，典型的文件权限问题，后者则是因为git init出来的仓库因为有源文件和分支，所以默认不给push，可能会导致在服务器上修改和本机修改导致冲突，但是这里默认只在本机修改，且都是静态文件，所以这两个操作不会导致什么隐患存在。

接着就要做hook了。

git的hook触发条件很多，push pull什么的，push出发的是post-receive，所以在.git/hooks/下新建post-receive文件,然后加入

```
#!/bin/bash
DEPLOY_PATH=$YOUR_HEXO_DIR

# 加上这个的原因没具体深究 
unset GIT_DIR
cd $DEPLOY_PATH
git reset --hard
```

这样做的原因是什么呢？前面说过了，git init出来的是带有文件以及分支的，而git init --bare则是没有的，只记录改动。虽然git init下，也记录了改动，但是这就像大家共有个远程仓库，一个人push了另外一个人并不会自动pull，所以这里要pull一下。但是服务器本身这里就是远程仓库，记录了改动，有log，所以这里的做法是追随到最新的log处，就是git reset --hard的作用了。

接下来就是hexo如何监测改动，使用的是

```
hexo generate --watch
```

如果要开启启动或者是后台，可以写个shell脚本，里面加上

```
cd $YOUR_HEXO_DIR
nohup /root/.nvm/versions/node/v8.4.0/bin/hexo generate --watch 2>&1 1>start.out &
```

hexo命令用全路径是因为PATH的问题，所以加上全路径，没有权限问题。 这样就可以在你的hexo目录下的start.out中看到

```
INFO  Start processing
INFO  Files loaded in 1.4 s
INFO  0 files generated in 1.95 s
INFO  Hexo is watching for file changes. Press Ctrl+C to exit.
```

这时候你就可以clone下远程仓库的文章

```shell
git clone git@$YOUR_HOST:$YOUR_SERVER_HEXO_GIT_DIR
```

形如

```shell
git clone git@110.110.111.111:/usr/hexo/source/_post
```

如果你要免密clone还得在服务器的authorized_keys加上你的公钥，跟将公钥放到github上就免密是一个道理。或者你也可以选择给git用户设置一个密码，然后每次输入密码。

然后再将自己的文章加入仓库

```shell
git add .
git commit -m"my article commit"
git push
```

这样就可以在start.out看到

```
INFO  Start processing
INFO  Files loaded in 1.31 s
INFO  Generated: archives/index.html
INFO  Generated: archives/2017/index.html
INFO  Generated: archives/2017/09/index.html
INFO  Generated: 2017/09/20/图片爬虫/index.html
INFO  Generated: 2017/09/20/2017铁人三项华中区域选拔赛总结/index.html
INFO  Generated: archives/2017/10/index.html
INFO  Generated: index.html
INFO  Generated: 2017/10/12/shianbei2017Writeup/index.html
INFO  8 files generated in 1 s
INFO  Hexo is watching for file changes. Press Ctrl+C to exit
```

自动在hexo的public目录下生成了hexo的网页。



因为hexo是全静态的，想加速的话，可以整个域名当作cdn的域名，非常快速。



这里主要用到了git的hook，hook在生产中用的比较多，一般用于自动部署。我现在也在用gitlab的webhook搞自动部署，很有效。

还有更高级的自动发布文章，是无服务器的，有兴趣的可参照[大佬博客](http://blog.tms.im/2017/07/27/hexo-travisci) ，用了CI。











