#!/bin/bash

cd /blog/blog/dev/ && nohup /bin/hexo g -w -d&
cd /blog/blog/sec/ && nohup /bin/hexo g -w -d&
cd /blog/blog/ser/ && nohup /bin/hexo g -w -d&

