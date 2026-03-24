LLVM_CONFIG_PATH ?= /opt/homebrew/opt/llvm/bin/llvm-config
CXX := $(shell $(LLVM_CONFIG_PATH) --bindir)/clang++
CXXFLAGS := $(shell $(LLVM_CONFIG_PATH) --cxxflags) -fPIC -fno-rtti
LDFLAGS := $(shell $(LLVM_CONFIG_PATH) --ldflags) -shared -Wl,-undefined,dynamic_lookup

all: CFAGeneratorPass.dylib

CFAGeneratorPass.dylib: CFAGeneratorPass.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f *.o *.dylib
