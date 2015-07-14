file ./listener/build/listener
#b main
#run -c 0xffff8 -n 4 -- --rx "(0,0,3),(1,0,3)" --tx "(0,3),(1,3)" --w "4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19" --ip-list ./listener/ip_list.txt   
run -c 0xffff8 -n 4 -- --rx "(0,0,3),(1,0,3)" --tx "(0,3),(1,3)" --w "4" --ip-list ./listener/ip_list.txt   
