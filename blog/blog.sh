#!/bin/bash

cd /blog/blog/dev/ && nohup /usr/bin/hexo s -w -p 1234 &
cd /blog/blog/sec/ && nohup /usr/bin/hexo s -w -p 1235 &
cd /blog/blog/ser/ && nohup /usr/bin/hexo s -w -p 1236 &

