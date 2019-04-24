#!/bin/bash

cd /blog/blog/dev/ && nohup /usr/bin/hexo g -w -d&
cd /blog/blog/sec/ && nohup /usr/bin/hexo g -w -d&
cd /blog/blog/ser/ && nohup /usr/bin/hexo g -w -d&

