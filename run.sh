#!/bin/sh
sudo ./build/listener -c 0xe -n 2 -- --rx "(0,0,1),(1,0,1)" --tx "(0,1),(1,1)" --w "2,3" --ip-list ip_list.txt
