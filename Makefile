# Makefile for pyx_decomp - Cython C-source -> Python decompiler
#
# Build:  make
# Run:    ./pyx_decomp <input.c|input.py|input.so> [-o output.py]

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wno-unused-parameter -Wno-missing-field-initializers
LDLIBS   ?= -lz -lbz2

TARGET   := pyx_decomp
SRC      := pyx_decomp.cpp

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGET) *.o

# Quick self-test on the uploaded experiment file
test: $(TARGET)
	./$(TARGET) "/home/z/my-project/upload/V3 FILE HI2.py" -o /tmp/test_recovered.py --json /tmp/test_report.json --debug
	@echo "--- first 80 lines of recovered Python ---"
	@head -80 /tmp/test_recovered.py
