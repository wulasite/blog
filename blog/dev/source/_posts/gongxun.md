---
title: 年轻人的第一个自己的项目
date: 2018-06-28 20:40:00
tags: PHP
---

今年寒假同学在空间喊说老师有东西要做，招前端后端。本着既然转开发了，这方面要积累点经验就去了，结果招了一堆人之后，只有我一个能打的，前端还是我自己找的朋友。跟老师确定大概的需求之后就开始做了，大概花了一个寒假，一个月的时间。前期主要是出流程图、模块图、数据库设计和api文档。

刚开始想用的是RABC的那一套，功能及其子节点由权限给出，因为之前在做新生宝典后台开发的时候前辈用了这个，觉得不错就想试一下。结果做了之后由于异地沟通，前端表示没接触过，所以就使用更简单的方法，不同的数字有不同的权限，可以有多种权限。前端也有做路由权限控制，所以基本上不会存在越权的问题。

至于登录会话的信息存储，原本是想用jwt+cookie去做每次会话的认证，但是前端表示不懂，只好老老实实用session了。而至于改密码当前session无效也没有需求，也就没做了。

在开发中遇到的比较大的一个问题是跨域和restful风格api。vue用的ajax请求的函数好像是axios，不仅有跨域，还有post请求之前，会发一次options请求。所以api还得放行options请求，但刚开始写的时候并没有很好的处理这个请求方法，是这样写的

```php
    public function checkAccess($id, $roleString)
    {
        if($_SERVER['REQUEST_METHOD'] != 'OPTIONS')
        {
            $roles = $this->getRoleList($id);
            for($i = 0; $i < strlen($roleString); $i++)
            {
                if(in_array($roleString[$i], $roles)) 
                    return 1;
            }
            exit(self::jsonFail('对不起没有权限'));
        }   
    }
```

[OPTIONS的作用](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Methods/OPTIONS)

[OPTIONS的RFC](https://tools.ietf.org/html/rfc7231#section-4.3.7)

看了这两个之后，才知道OPTIONS只是一个预请求，以检测服务器支持哪些 HTTP 方法

```
响应报文包含一个 Allow 首部字段，该字段的值表明了服务器支持的所有 HTTP 方法：
Allow: OPTIONS, GET, HEAD, POST

在 CORS 中，可以使用 OPTIONS 方法发起一个预检请求，以检测实际请求是否可以被服务器所接受。预检请求报文中的 Access-Control-Request-Method 首部字段告知服务器实际请求所使用的 HTTP 方法；Access-Control-Request-Headers 首部字段告知服务器实际请求所携带的自定义首部字段。服务器基于从预检请求获得的信息来判断，是否接受接下来的实际请求。

Access-Control-Request-Method: POST 
```

所以只需要在路由配置那里直接处理OPTIONS请求，使其返回的头部包含支持的方法即可，PHP的写法

```php
header("Access-Control-Allow-Methods:PUT, GET, POST, DELETE, OPTIONS");
```

这样就不会导致安全隐患的问题了。

至于restful风格的api，前端不能很好的处理，就采用查询用get，其它用post。



写完之后让老前辈review了一下，逻辑上没什么大问题，就是数据层代码层重复太多了，换句话说就是没有model。所以下次得学习下model该怎么写。