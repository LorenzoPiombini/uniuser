TARGET = user_manager
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c, obj/%.o, $(SRC))
OBJlibuser = obj/user_create.o

LIBNAMEuser = user
LIBDIR = /usr/local/lib
INCLUDEDIR = /usr/local/include
SHAREDLIBuser = lib$(LIBNAMEuser).so

default:$(TARGET)

clean:
	sudo rm -r obj/*.o
	rm $(TARGET)
	rm -f $(INCLUDEDIR)/user_create.h
	rm -f $(LIBDIR)/$(LIBNAMEuser)

object-dir:
	@if [ ! -d ./obj ]; then\
		echo "creating obj directory..." ;\
		mkdir obj ;\
	fi

check-linker-path:                                                                                                
	@if [ ! -f /etc/ld.so.conf.d/customtech.conf ]; then \
        echo "setting linker configuration..." ;\
        echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/customtech.conf >/dev/null ;\
		sudo ldconfig;\
	fi

library:
	sudo gcc -Wall -fPIC -shared -o $(SHAREDLIBuser) $(OBJlibuser)


$(TARGET):$(OBJ)
	gcc -o $@ $? -lcrypt -lstrOP -fsanitize=address -pie -z relro -z now -z noexecstack 

obj/%.o:src/%.c
	gcc -Wall -g3 -c $< -o $@ -Iinclude -fstack-protector-strong -D_FORTiFY_SOURCE=2 -fPIE -fsanitize=address

install:
	install -d $(INCLUDEDIR)
	install -m 644 include/user_create.h $(INCLUDEDIR)
	install -m 755 $(SHAREDLIBuser) $(LIBDIR)
	ldconfig

build:object-dir default library check-linker-path install

.PHONY: install object-dir default library check-linker-path
