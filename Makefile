# Makefile to build class 'helloworld' for Pure Data.
# Needs Makefile.pdlibbuilder as helper makefile for platform-dependent build
# settings and rules.

# library name
lib.name = hmacsha256

# input source file (class name == source file basename)
class.sources = hmacsha256.c

# all extra files to be included in binary distribution of the library
datafiles = helloworld-help.pd helloworld-meta.pd README.md

# include Makefile.pdlibbuilder from submodule directory 'pd-lib-builder'
include pd-lib-builder/Makefile.pdlibbuilder