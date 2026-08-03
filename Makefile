#
# DUNN - Firewall Security Monitor
#

CC = gcc

CFLAGS = -Wall -Wextra -std=c11 -Iinclude

TARGET = dunn

SRC = \
	src/main.c \
	src/ufw.c \
	src/display.c


OBJ = $(SRC:.c=.o)


all: $(TARGET)


$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	rm -f $(OBJ) $(TARGET)


run: $(TARGET)
	./$(TARGET)


.PHONY: all clean run
