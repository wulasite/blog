#!/bin/bash

cd /qqx/blog/dev/ && nohup /usr/bin/hexo s -w -p 1234 &
cd /qqx/blog/sec/ && nohup /usr/bin/hexo s -w -p 1235 &
cd /qqx/blog/ser/ && nohup /usr/bin/hexo s -w -p 1236 &

