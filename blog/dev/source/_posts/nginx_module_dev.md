---
title: nginx模块开发及基于clion的nginx远程debug
date: 2019-11-29 20:40:00
tags: 
---

<!-- toc -->

# 前言

前段时间接到清华大佬的nginx模块开发的打工任务，所以就开始整了一些资料，上手搞一发。

因为只求快速开发，所以不求深入了解，如果有需求，再深入了解。

所以本篇文章主要包括

1. nginx的hello world模块开发
2. 在windows上远程debug nginx（linux）

这篇文章可谓是干货满满，花了N天才搞定的。



# nginx的hello world模块

本章节主要讲如何跑起nginx的hello world模块，但不涉及原理的讲解，原理可参考其它文章以及源码。

首先按照该[博客](https://blog.csdn.net/Poechant/article/details/7627828)的教程把源码下好，模块代码放好，config写好。

我的文件结构如下：

![](https://wulasite.top/mdimage/nginx_dev/files.jpg)

然后修改conf里面的nginx.conf

```
location / {
    hello_world Poechant1;
    #root   html;
    #index  index.html index.htm;
}
```
<!-- more -->
写个bash脚本一键编译启动

```bash
#!/bin/bash

cd /nginx_dev/nginx-1.16.1/ && ./configure --add-module=/nginx_dev/nginx-1.16.1/modules/  --with-debug && make -j 8 && make install -j 8 && nginx 
```

这里的-j 8指的是cpu的核心数，为了加速编译的

![](https://wulasite.top/mdimage/nginx_dev/start.jpg)

如果没有报错就说明启动成功了，这时候执行netstat -tpnl 和ps -ef | grep nginx就可以看下有没有启动

![](https://wulasite.top/mdimage/nginx_dev/nginx_start.jpg)

然后就可以直接访问的，如果有防火墙记得关防火墙。



# 远程debug nginx

经过一段时间的在本地开发然后自动同步到远端，然后在运行编译脚本的日子，终于在某处需要debug的情况，因此想起了之前也有学长用vs做nginx的开发，但是发现vs是可以做的，但是文件结构需要自己手动调，否则会全都默认堆在一个地方。所以想试下clion，发现clion是可以保持文件结构并且能够自动识别里面的文件并构成CMakeLists,但是根据后面的实践，发现里面会缺少些Makefile里的编译选项。所以补上这些编译选项，完全可以在Clion上跑起来。

本文主要参照[51CTO](https://edu.51cto.com/course/18013.html) 的课程，如果学生党没钱看（也就十几块钱，我当初看是九块钱)，可以联系我的邮箱ZDNWc1lYTnBkR1ZBWjIxaGFXd3VZMjl0。里面的最重要的转换脚本我就不放出来了。

1. 在服务器上configure生成makefile

   为了区别之前的项目，新建了一个文件夹clion，把东西源码和模块放进去，然后运行更新的compile.sh

   ```bash
   #!/bin/bash
   
   cd /nginx_dev/clion && ./configure --add-module=/nginx_dev/clion/modules/ --prefix=/nginx_dev/clion/ --with-debug
   ```

   ![](https://wulasite.top/mdimage/nginx_dev/compile_update.png)

   可以看到已经生成了makefile

   然后把它打包拖到本地。然后用clion打开它，选用New Cmake Project from Sources

   它会自动识别，默认打开即可
   ![](https://wulasite.top/mdimage/nginx_dev/import.png)

   等clion导入并index完毕之后可以看到CMakeLists已经生成了。
   ![](https://wulasite.top/mdimage/nginx_dev/cmakelist1.png)

2. 配置clion的remote
   我主要参考的[这篇文章](https://cloud.tencent.com/developer/article/1406250)
   先设置deployment，图来自文章
   
   ![](https://wulasite.top/mdimage/nginx_dev/m5yp1prpd2.png)
   
   设置mapping,因为/nginx_dev/clion就是为这个项目准备的，所以就用这个目录。
   
   ![](https://wulasite.top/mdimage/nginx_dev/mapping.png)
   
   设置好了之后需要设置文件上传和自动同步
   ![](https://wulasite.top/mdimage/nginx_dev/upload.png)
   
   然后再设置远程debug，先设置toolchain
   
   ![](https://wulasite.top/mdimage/nginx_dev/toolchains.png)
   
   设置cmake
   
   ![](https://wulasite.top/mdimage/nginx_dev/cmake.png)
   
3. 更改cmakelist
   用python脚本把cmakelist更改一下，具体使用教程在这篇的开头的51CTO视频里有讲，跟之前一样，学生党可以联系我的邮箱。
   所以最后我的cmakelist大概长这样

   ```cmake
   cmake_minimum_required(VERSION 3.15)
   project(clion)
   # 用C编译器编译
   set(CMAKE_C_STANDARD 99)
   
   include_directories(objs)
   include_directories(src/event/modules)
   include_directories(/usr/local/include)
   include_directories(src/core)
   include_directories(src/event)
   include_directories(src/http)
   include_directories(src/http/modules)
   include_directories(src/http/modules/perl)
   include_directories(src/http/v2)
   include_directories(src/mail)
   include_directories(src/os/unix)
   include_directories(src/stream)
   
   set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -L /usr/lib64/ -ldl -lpthread -lcrypt -lpcre -lz  -Wl,-E  -pipe  -O -W -Wall -Wpointer-arith -Wno-unused-parameter  -g ")
   
   add_executable(clion
           src/core/nginx.h
           src/core/ngx_config.h
           src/core/ngx_core.h
           src/core/ngx_log.h
           src/core/ngx_palloc.h
           src/core/ngx_array.h
           src/core/ngx_list.h
           src/core/ngx_hash.h
           src/core/ngx_buf.h
           src/core/ngx_queue.h
           src/core/ngx_string.h
           src/core/ngx_parse.h
           src/core/ngx_parse_time.h
           src/core/ngx_inet.h
           src/core/ngx_file.h
           src/core/ngx_crc.h
           src/core/ngx_crc32.h
           src/core/ngx_murmurhash.h
           src/core/ngx_md5.h
           src/core/ngx_sha1.h
           src/core/ngx_rbtree.h
           src/core/ngx_radix_tree.h
           src/core/ngx_rwlock.h
           src/core/ngx_slab.h
           src/core/ngx_times.h
           src/core/ngx_shmtx.h
           src/core/ngx_connection.h
           src/core/ngx_cycle.h
           src/core/ngx_conf_file.h
           src/core/ngx_module.h
           src/core/ngx_resolver.h
           src/core/ngx_open_file_cache.h
           src/core/ngx_crypt.h
           src/core/ngx_proxy_protocol.h
           src/core/ngx_syslog.h
           src/event/ngx_event.h
           src/event/ngx_event_timer.h
           src/event/ngx_event_posted.h
           src/event/ngx_event_connect.h
           src/event/ngx_event_pipe.h
           src/os/unix/ngx_time.h
           src/os/unix/ngx_errno.h
           src/os/unix/ngx_alloc.h
           src/os/unix/ngx_files.h
           src/os/unix/ngx_channel.h
           src/os/unix/ngx_shmem.h
           src/os/unix/ngx_process.h
           src/os/unix/ngx_setaffinity.h
           src/os/unix/ngx_setproctitle.h
           src/os/unix/ngx_atomic.h
           src/os/unix/ngx_gcc_atomic_x86.h
           src/os/unix/ngx_thread.h
           src/os/unix/ngx_socket.h
           src/os/unix/ngx_os.h
           src/os/unix/ngx_user.h
           src/os/unix/ngx_dlopen.h
           src/os/unix/ngx_process_cycle.h
           src/os/unix/ngx_linux_config.h
           src/os/unix/ngx_linux.h
           src/core/ngx_regex.h
           objs/ngx_auto_config.h
           src/http/ngx_http.h
           src/http/ngx_http_request.h
           src/http/ngx_http_config.h
           src/http/ngx_http_core_module.h
           src/http/ngx_http_cache.h
           src/http/ngx_http_variables.h
           src/http/ngx_http_script.h
           src/http/ngx_http_upstream.h
           src/http/ngx_http_upstream_round_robin.h
           src/http/modules/ngx_http_ssi_filter_module.h
           src/core/nginx.c
           src/core/ngx_log.c
           src/core/ngx_palloc.c
           src/core/ngx_array.c
           src/core/ngx_list.c
           src/core/ngx_hash.c
           src/core/ngx_buf.c
           src/core/ngx_queue.c
           src/core/ngx_output_chain.c
           src/core/ngx_string.c
           src/core/ngx_parse.c
           src/core/ngx_parse_time.c
           src/core/ngx_inet.c
           src/core/ngx_file.c
           src/core/ngx_crc32.c
           src/core/ngx_murmurhash.c
           src/core/ngx_md5.c
           src/core/ngx_sha1.c
           src/core/ngx_rbtree.c
           src/core/ngx_radix_tree.c
           src/core/ngx_slab.c
           src/core/ngx_times.c
           src/core/ngx_shmtx.c
           src/core/ngx_connection.c
           src/core/ngx_cycle.c
           src/core/ngx_spinlock.c
           src/core/ngx_rwlock.c
           src/core/ngx_cpuinfo.c
           src/core/ngx_conf_file.c
           src/core/ngx_module.c
           src/core/ngx_resolver.c
           src/core/ngx_open_file_cache.c
           src/core/ngx_crypt.c
           src/core/ngx_proxy_protocol.c
           src/core/ngx_syslog.c
           src/event/ngx_event.c
           src/event/ngx_event_timer.c
           src/event/ngx_event_posted.c
           src/event/ngx_event_accept.c
           src/event/ngx_event_udp.c
           src/event/ngx_event_connect.c
           src/event/ngx_event_pipe.c
           src/os/unix/ngx_time.c
           src/os/unix/ngx_errno.c
           src/os/unix/ngx_alloc.c
           src/os/unix/ngx_files.c
           src/os/unix/ngx_socket.c
           src/os/unix/ngx_recv.c
           src/os/unix/ngx_readv_chain.c
           src/os/unix/ngx_udp_recv.c
           src/os/unix/ngx_send.c
           src/os/unix/ngx_writev_chain.c
           src/os/unix/ngx_udp_send.c
           src/os/unix/ngx_udp_sendmsg_chain.c
           src/os/unix/ngx_channel.c
           src/os/unix/ngx_shmem.c
           src/os/unix/ngx_process.c
           src/os/unix/ngx_daemon.c
           src/os/unix/ngx_setaffinity.c
           src/os/unix/ngx_setproctitle.c
           src/os/unix/ngx_posix_init.c
           src/os/unix/ngx_user.c
           src/os/unix/ngx_dlopen.c
           src/os/unix/ngx_process_cycle.c
           src/os/unix/ngx_linux_init.c
           src/event/modules/ngx_epoll_module.c
           src/os/unix/ngx_linux_sendfile_chain.c
           src/core/ngx_regex.c
           src/http/ngx_http.c
           src/http/ngx_http_core_module.c
           src/http/ngx_http_special_response.c
           src/http/ngx_http_request.c
           src/http/ngx_http_parse.c
           src/http/modules/ngx_http_log_module.c
           src/http/ngx_http_request_body.c
           src/http/ngx_http_variables.c
           src/http/ngx_http_script.c
           src/http/ngx_http_upstream.c
           src/http/ngx_http_upstream_round_robin.c
           src/http/ngx_http_file_cache.c
           src/http/ngx_http_write_filter_module.c
           src/http/ngx_http_header_filter_module.c
           src/http/modules/ngx_http_chunked_filter_module.c
           src/http/modules/ngx_http_range_filter_module.c
           src/http/modules/ngx_http_gzip_filter_module.c
           src/http/ngx_http_postpone_filter_module.c
           src/http/modules/ngx_http_ssi_filter_module.c
           src/http/modules/ngx_http_charset_filter_module.c
           src/http/modules/ngx_http_userid_filter_module.c
           src/http/modules/ngx_http_headers_filter_module.c
           src/http/ngx_http_copy_filter_module.c
           src/http/modules/ngx_http_not_modified_filter_module.c
           src/http/modules/ngx_http_static_module.c
           src/http/modules/ngx_http_autoindex_module.c
           src/http/modules/ngx_http_index_module.c
           src/http/modules/ngx_http_mirror_module.c
           src/http/modules/ngx_http_try_files_module.c
           src/http/modules/ngx_http_auth_basic_module.c
           src/http/modules/ngx_http_access_module.c
           src/http/modules/ngx_http_limit_conn_module.c
           src/http/modules/ngx_http_limit_req_module.c
           src/http/modules/ngx_http_geo_module.c
           src/http/modules/ngx_http_map_module.c
           src/http/modules/ngx_http_split_clients_module.c
           src/http/modules/ngx_http_referer_module.c
           src/http/modules/ngx_http_rewrite_module.c
           src/http/modules/ngx_http_proxy_module.c
           src/http/modules/ngx_http_fastcgi_module.c
           src/http/modules/ngx_http_uwsgi_module.c
           src/http/modules/ngx_http_scgi_module.c
           src/http/modules/ngx_http_memcached_module.c
           src/http/modules/ngx_http_empty_gif_module.c
           src/http/modules/ngx_http_browser_module.c
           src/http/modules/ngx_http_upstream_hash_module.c
           src/http/modules/ngx_http_upstream_ip_hash_module.c
           src/http/modules/ngx_http_upstream_least_conn_module.c
           src/http/modules/ngx_http_upstream_random_module.c
           src/http/modules/ngx_http_upstream_keepalive_module.c
           src/http/modules/ngx_http_upstream_zone_module.c
           /nginx_dev/clion/modules/ngx_http_hello_world_module.c
           objs/ngx_modules.c)
   
   ```

4. 收尾工作
   在当前目录新建一个logs文件夹，没有运行会报错。
   修改nginx.conf以方便调试，在nginx.conf新增

   ```
   daemon off;
   master_process off;
   # 修改location
   location / {
               hello_world Poechant1;
               #root   html;
               #index  index.html index.htm;
           }
   ```

   一个是让nginx在前台运行
   一个是关闭nginx多线程

   然后直接点击debug按钮，如果没有的话可以自己创建

   ![](https://wulasite.top/mdimage/nginx_dev/cmake_app.png)

   ![](https://wulasite.top/mdimage/nginx_dev/debug1.png)

   然后在我们的模块代码断点试一下

   ![](https://wulasite.top/mdimage/nginx_dev/debug2.png)

   到此就已经完成了。

由于这个环境是docker的，所以我也会把它提交到我的dockerhub里 wulasite/nginx_module_dev，但是我也没使用docker-compose所以无yml文件，只需要自己build的时候指定ssh port和web port



# 附录

参考文献：

可能内容有重复的

[官方参考文档](http://nginx.org/en/docs/dev/development_guide.html)

https://blog.csdn.net/Poechant/article/details/7627831系列

https://www.oschina.net/translate/nginx-development-guide

https://blog.csdn.net/xxb249/article/details/85269953

https://www.kancloud.cn/kancloud/master-nginx-develop

https://tengine.taobao.org/book/module_development.html

https://blog.csdn.net/Poechant/article/details/7627828

