---
title: ELK搭建
date: 2018-6-27 19:12:00
tags:
---

Centos下安装ELK

**目录**
<!-- toc -->

[参考链接](https://ken.io/note/elk-deploy-guide )

1. 先下载安装jdk，以及设置JAVA_HOME等环境变量，这里安装的java1.8

2. 下载ELK
   [es](https://www.elastic.co/downloads/elasticsearch)
   [logstash](https://www.elastic.co/downloads/logstash> )

   [kibana](https://www.elastic.co/downloads/kibana )
<!-- more -->

3. 将  elasticsearch的包移动到/usr/elk目录下，解压。然后cd进目录，运行  bin/elasticsearch  就会发现报错， 
   ![](https://wulasite.top/mdimage/elk/elk1.png)

   那就新建个用户,并且将该目录的拥有者改为该用户 chown xx:xx -R /usr/elk/elasticsearch  再启动  bin/elasticsearch  可以正常启动，但是监听的地址是127.0.0.1，看了下配置文件，修改为0.0.0.0即可。  
   ![](https://wulasite.top/mdimage/elk/elk2.png)

   但是报错了，

   ![](https://wulasite.top/mdimage/elk/elk3.png)

   搜索了一下，发现装这个的常见错误很多，一般都是配置不够，按照教程修改一下就好了。 

   我这个的解决方法是  vim /etc/security/limits.conf(管理员权限)  

   hhh soft nofile 65536 

   hhh hard nofile 65536  

   hhh为用户名，

   然后退出重新该用户进入,运行  ulimit -Hn  

   ![](https://wulasite.top/mdimage/elk/elk4.png)

   启动即可 
   ![](https://wulasite.top/mdimage/elk/elk5.png)

   


4. 安装Logstash 
   安装epel源后可以直接yum -y install redis就可以了，免去编译安装以及配置开机自启动的配置。  
   做一些配置，修改几处  
   bind  0.0.0.0  #关闭保护模式   
   protected-mode no  
   由于是内网测试环境，就不设置密码了。  将下载好的logstash移动到/usr/elk下，解压，由于解压的文件基本都配置好了，再加个配置文件就可以用了。  
   vim config/input-output.conf    

   ```
   #配置内容
   
   input {
     redis {
       data_type => "list"
       key => "logstash"
       host => "192.168.1.21"
       port => 6379
       threads => 5
       codec => "json"
     }
   }
   filter {
   }
   output {
     elasticsearch {
       hosts => ["192.168.1.31:9200","192.168.1.32:9200"]
       index => "logstash-%{type}-%{+YYYY.MM.dd}"
       document_type => "%{type}"
     }
     stdout {
     }
   }
   
   
   ```

   \#进入Logstash根目录
    启动logstash

   ./bin/logstash -f config/input-output.conf

   成功后最后会显示
   ![](https://wulasite.top/mdimage/elk/elk6.png)

5. 装Kibana  
   将下载好的Kibana移动/usr/elk的目录下，解压，修改配置文件config/kibana.yml  
   server.port: 5601  
   server.host: "0.0.0.0"  
   elasticsearch.url: <http://yourip:9200>  
   这是es的服务器地址  
   启动  bin/kibana  
   访问该ip的5601端口，可看到  
   ![](https://wulasite.top/mdimage/elk/elk7.png)点击左边菜单栏的Discover，会出现
   ![](https://wulasite.top/mdimage/elk/elk8.png)

   点击Check for new data创建新的pattern

   第一步输入匹配的模式
   ![](https://wulasite.top/mdimage/elk/elk9.png)

   第二步选择时间过滤器。 

   创建完成后，在服务器上启动redis-cli，

   输入  lpush logstash '{"host":"127.0.0.1","type":"logtest","message":"hello"}'，

   也可以多次输入，插入数据。 

   然后再点击Kibana的discover就可以看到数据了 

6. 使用Logstash收集web服务器日志  文档地址：  [](https://www.elastic.co/guide/en/logstash/current/advanced-pipeline.html )

   可以下载日志样例  [](https://download.elastic.co/demos/logstash/gettingstarted/logstash-tutorial.log.gz)  

   按照文档所说，需要下载Filebeat将日志发送到logstash  下载Filebeat  [](https://www.elastic.co/downloads/beats/filebeat )  

   切换到filebeat的目录，编辑配置文件，filebeat.yml，

   找到  

   ```
   filebeat.prospectors:
   - type: 
    log paths: 
      - /path/to/file/logstash-tutorial.log 
   output.logstash: 
    hosts: ["localhost:5044"]
   
   ```

    路径就是刚才下的样例日志，是httpd，拿别的httpd日志文件也行。  然后再切换到logstash的目录修改logstash的配置文件  vim conf/input-output.conf  形如 

   ```
   input { 
   		beats { 
   			port => "5044" 
   		} 
   } 
   filter { 
   		grok { 
   			match => { 
   				"message" => "%{COMBINEDAPACHELOG}"
   			}
   		 } 
   		geoip {
   			 source => "clientip" 
   		} 
   } 
   output 
   { 
   		elasticsearch { 
   			hosts => [ "localhost:9200" ]
   			index => "httpd-%{type}-%{+YYYY.MM.dd}" 
   			document_type => "%{type}" 
   		}
    }
   
   ```

   详细内容在文档中都有解释，以及日志格式，代表意义都有，最简单的形式就是这样。  

   然后运行

   ```
   logstath   bin/logstash -f first-pipeline.conf --config.reload.automatic
   ```

    带上自动更新配置文件参数就可以在后台运行了，不用重启。  然后在切换到filebeat文件，运行filebeat  ./filebeat -e -c filebeat.yml -d "publish"  可以看到很多输出在上面，然后去kibana看，跟上面一样增加httpd-*的index，然后可看到。    
   ![](https://wulasite.top/mdimage/elk/elk10.png)

     