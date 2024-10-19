# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -g

# Source files
SRCS = test.c

# Output executable
TARGET = program

# Object files
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# Compile the C source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Run objdump with Intel syntax disassembly
objdump: $(TARGET)
	objdump -S -M intel $(TARGET) > disassembly.s
	cat disassembly.s

# Clean up the generated files
clean:
	rm -f $(TARGET) $(OBJS) disassembly.s

# Phony targets
.PHONY: all clean objdump
