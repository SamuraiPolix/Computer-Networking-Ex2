#################################################################################
# 	Sniffer Application for TCP connections of Calculator application Makefile	#
# 	Authors: Roy Simanovich and and Yuval Yurzdichinsky (c) 2023				#
# 	Description: This Makefile compiles the programs and libraries 				#
# 							Date: 2023-01										#
# 					Course: Communication and Computing							#
# 							Compiler: gcc										#
# 							OS: Linux											#
# 						IDE: Visual Studio Code									#
#################################################################################

# Use the gcc compiler.
CC = gcc

# Flags for the compiler.
CFLAGS = -Wall

# Flags for the linker.
LDFLAGS = -lpcap

# Command to remove files.
RM = rm -f

# Phony targets - targets that are not files but commands to be executed by make.
.PHONY: all clean default run

# Default target - compile everything and create the executables and libraries.
all: Sniffer

# Alias for the default target.
default: all


############
# Programs #
############

# Compile the sniffer program.
Sniffer: Sniffer.o
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@


################
# Object files #
################

# Compile all the C files into object files.
%.o: %.c net_head.h
	$(CC) $(CFLAGS) -c $<


#########
# Rules #
#########

# Run the sniffer program in sudo mode.
run: Sniffer
	sudo ./Sniffer


#################
# Cleanup files #
#################

# Remove all the object files, shared libraries and executables.
clean:
	$(RM) *.o Sniffer