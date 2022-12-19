CC = gcc
CFLAGS = -Wall -g
TARGET = new_exp

$(TARGET):
	gcc $(TARGET).c -o $(TARGET) -I.. -I../common -L./.libs -L../common/.libs -DHAVE_CONFIG_H -lxrdpapi -lcommon
	cp ./$(TARGET) /tmp/$(TARGET)
	rm ./$(TARGET)
