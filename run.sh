#!/bin/sh
#sudo ./build/listener -c 0xe -n 2 -- --rx "(0,0,1),(1,0,1)" --tx "(0,1),(1,1)" --w "2,3" --ip-list ip_list.txt
#sudo ./build/listener -c 0xff8 -n 4 -- --rx "(0,0,3),(1,0,3)" --tx "(0,3),(1,3)" --w "4,5,6,7,8,9,10,11" --ip-list ip_list.txt
sudo ./listener/build/listener -c 0xffff8 -n 4 -- --rx "(0,0,3),(1,0,3)" --tx "(0,3),(1,3)" --w "4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19" --ip-list ./listener/ip_list.txt
