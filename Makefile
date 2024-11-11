SOURCES = $(wildcard src/*.cpp)
HEADERS = $(wildcard src/*.hpp)

OBJECTS = $(SOURCES:%.cpp=%.o)
PROGRAM =sslsniff

CC := g++
CFLAGS = -Wall -Wextra -Werror
LIBS = m pcap
LDFLAGS =$(LIBS:%=-l%)

$(PROGRAM) : $(OBJECTS)
		$(CC) $(OBJECTS) $(CFLAGS) $(LDFLAGS) -o $@

%.o : %.cpp
		$(CC) $(CFLAGS) -c -o $@ $<

.PHONY : clean
clean :
		rm -f $(PROGRAM) $(OBJECTS)
package: clean
	tar -cvf xlorin01.tar Makefile src sslsniff.1 manual.pdf