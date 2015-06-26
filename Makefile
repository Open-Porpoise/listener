all: ./sender/sender ./listener/build/listener

./sender/sender: ./geolocation/libgeolocation.a ./librdkafka/src/librdkafka.a
	make -C sender

./listener/build/listener: ./geolocation/libgeolocation.a
	make -C listener

./librdkafka/src/librdkafka.a: ./librdkafka/Makefile.config
	make -C ../librdkafka

./librdkafka/Makefile.config: ./librdkafka/configure
	cd ../librdkafka && ./configure

./geolocation/libgeolocation.a: ./geolocation/Makefile
	make -C ../geolocation

./geolocation/Makefile: ./geolocation/CMakeLists.txt
	cd ../geolocation && cmake .



clean:
	make clean -C sender
	make clean -C listener
