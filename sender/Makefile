all: sender

sender: sender.h sender.c ../librdkafka/src/librdkafka.a ../geolocation/libgeolocation.a
	gcc -DDEBUG -g -fPIC -Wall -I../geolocation  -I../librdkafka/src-cpp -I../librdkafka/src sender.c -o sender \
		../librdkafka/src/librdkafka.a ../geolocation/libgeolocation.a -lz -lpthread -lrt -lm

clean:
	rm -f sender
