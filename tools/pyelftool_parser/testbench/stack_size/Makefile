# Compiler
CC = gcc

# Compiler flags
CFLAGS = -O3 -fno-stack-check

# Source files
SRCS = stack_size.c stack_size_other.c

# Output binary
TARGET = ss.elf

# Disassembly output file
DISASSEMBLY = disassembly.s

# Default target
all: $(TARGET)

# Rule to compile the binary
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET)

# Rule to disassemble the binary
disassemble: $(TARGET)
	objdump -S -M intel $(TARGET) > $(DISASSEMBLY)

# Clean up generated files
clean:
	rm -f $(TARGET) $(DISASSEMBLY)

