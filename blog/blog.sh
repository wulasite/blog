#!/bin/bash

cd /blog/blog/dev/ && nohup /usr/bin/hexo s -w &
cd /blog/blog/sec/ && nohup /usr/bin/hexo g -w &
cd /blog/blog/ser/ && nohup /usr/bin/hexo g -w &

