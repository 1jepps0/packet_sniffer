# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -O2

# Linker flags
LDFLAGS = -lpcap

# Target
TARGET = sniffer

# Source file
SRC = sniffer.c

# Build rule
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

# Clean rule
clean:
	rm -f $(TARGET)

