# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/glee/lte/openlte-code/polarssl

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/glee/lte/openlte-code/polarssl/build

# Include any dependencies generated for this target.
include tests/CMakeFiles/test_suite_aes.ecb.dir/depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/test_suite_aes.ecb.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/test_suite_aes.ecb.dir/flags.make

tests/test_suite_aes.ecb.c: ../tests/scripts/generate_code.pl
tests/test_suite_aes.ecb.c: library/libmbedtls.a
tests/test_suite_aes.ecb.c: ../tests/suites/helpers.function
tests/test_suite_aes.ecb.c: ../tests/suites/main_test.function
tests/test_suite_aes.ecb.c: ../tests/suites/test_suite_aes.function
tests/test_suite_aes.ecb.c: ../tests/suites/test_suite_aes.ecb.data
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/glee/lte/openlte-code/polarssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating test_suite_aes.ecb.c"
	cd /home/glee/lte/openlte-code/polarssl/build/tests && /usr/bin/perl /home/glee/lte/openlte-code/polarssl/tests/scripts/generate_code.pl /home/glee/lte/openlte-code/polarssl/tests/suites test_suite_aes test_suite_aes.ecb

tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o: tests/CMakeFiles/test_suite_aes.ecb.dir/flags.make
tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o: tests/test_suite_aes.ecb.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/glee/lte/openlte-code/polarssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o"
	cd /home/glee/lte/openlte-code/polarssl/build/tests && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o   -c /home/glee/lte/openlte-code/polarssl/build/tests/test_suite_aes.ecb.c

tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.i"
	cd /home/glee/lte/openlte-code/polarssl/build/tests && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/glee/lte/openlte-code/polarssl/build/tests/test_suite_aes.ecb.c > CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.i

tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.s"
	cd /home/glee/lte/openlte-code/polarssl/build/tests && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/glee/lte/openlte-code/polarssl/build/tests/test_suite_aes.ecb.c -o CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.s

tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o.requires:

.PHONY : tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o.requires

tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o.provides: tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o.requires
	$(MAKE) -f tests/CMakeFiles/test_suite_aes.ecb.dir/build.make tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o.provides.build
.PHONY : tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o.provides

tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o.provides.build: tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o


# Object files for target test_suite_aes.ecb
test_suite_aes_ecb_OBJECTS = \
"CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o"

# External object files for target test_suite_aes.ecb
test_suite_aes_ecb_EXTERNAL_OBJECTS =

tests/test_suite_aes.ecb: tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o
tests/test_suite_aes.ecb: tests/CMakeFiles/test_suite_aes.ecb.dir/build.make
tests/test_suite_aes.ecb: library/libmbedtls.a
tests/test_suite_aes.ecb: library/libmbedx509.a
tests/test_suite_aes.ecb: library/libmbedcrypto.a
tests/test_suite_aes.ecb: tests/CMakeFiles/test_suite_aes.ecb.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/glee/lte/openlte-code/polarssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable test_suite_aes.ecb"
	cd /home/glee/lte/openlte-code/polarssl/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_suite_aes.ecb.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/test_suite_aes.ecb.dir/build: tests/test_suite_aes.ecb

.PHONY : tests/CMakeFiles/test_suite_aes.ecb.dir/build

tests/CMakeFiles/test_suite_aes.ecb.dir/requires: tests/CMakeFiles/test_suite_aes.ecb.dir/test_suite_aes.ecb.c.o.requires

.PHONY : tests/CMakeFiles/test_suite_aes.ecb.dir/requires

tests/CMakeFiles/test_suite_aes.ecb.dir/clean:
	cd /home/glee/lte/openlte-code/polarssl/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/test_suite_aes.ecb.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/test_suite_aes.ecb.dir/clean

tests/CMakeFiles/test_suite_aes.ecb.dir/depend: tests/test_suite_aes.ecb.c
	cd /home/glee/lte/openlte-code/polarssl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/glee/lte/openlte-code/polarssl /home/glee/lte/openlte-code/polarssl/tests /home/glee/lte/openlte-code/polarssl/build /home/glee/lte/openlte-code/polarssl/build/tests /home/glee/lte/openlte-code/polarssl/build/tests/CMakeFiles/test_suite_aes.ecb.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/test_suite_aes.ecb.dir/depend

