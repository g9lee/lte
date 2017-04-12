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
include programs/hash/CMakeFiles/hello.dir/depend.make

# Include the progress variables for this target.
include programs/hash/CMakeFiles/hello.dir/progress.make

# Include the compile flags for this target's objects.
include programs/hash/CMakeFiles/hello.dir/flags.make

programs/hash/CMakeFiles/hello.dir/hello.c.o: programs/hash/CMakeFiles/hello.dir/flags.make
programs/hash/CMakeFiles/hello.dir/hello.c.o: ../programs/hash/hello.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/glee/lte/openlte-code/polarssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object programs/hash/CMakeFiles/hello.dir/hello.c.o"
	cd /home/glee/lte/openlte-code/polarssl/build/programs/hash && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/hello.dir/hello.c.o   -c /home/glee/lte/openlte-code/polarssl/programs/hash/hello.c

programs/hash/CMakeFiles/hello.dir/hello.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/hello.dir/hello.c.i"
	cd /home/glee/lte/openlte-code/polarssl/build/programs/hash && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/glee/lte/openlte-code/polarssl/programs/hash/hello.c > CMakeFiles/hello.dir/hello.c.i

programs/hash/CMakeFiles/hello.dir/hello.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/hello.dir/hello.c.s"
	cd /home/glee/lte/openlte-code/polarssl/build/programs/hash && /usr/bin/cc  $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/glee/lte/openlte-code/polarssl/programs/hash/hello.c -o CMakeFiles/hello.dir/hello.c.s

programs/hash/CMakeFiles/hello.dir/hello.c.o.requires:

.PHONY : programs/hash/CMakeFiles/hello.dir/hello.c.o.requires

programs/hash/CMakeFiles/hello.dir/hello.c.o.provides: programs/hash/CMakeFiles/hello.dir/hello.c.o.requires
	$(MAKE) -f programs/hash/CMakeFiles/hello.dir/build.make programs/hash/CMakeFiles/hello.dir/hello.c.o.provides.build
.PHONY : programs/hash/CMakeFiles/hello.dir/hello.c.o.provides

programs/hash/CMakeFiles/hello.dir/hello.c.o.provides.build: programs/hash/CMakeFiles/hello.dir/hello.c.o


# Object files for target hello
hello_OBJECTS = \
"CMakeFiles/hello.dir/hello.c.o"

# External object files for target hello
hello_EXTERNAL_OBJECTS =

programs/hash/hello: programs/hash/CMakeFiles/hello.dir/hello.c.o
programs/hash/hello: programs/hash/CMakeFiles/hello.dir/build.make
programs/hash/hello: library/libmbedtls.a
programs/hash/hello: library/libmbedx509.a
programs/hash/hello: library/libmbedcrypto.a
programs/hash/hello: programs/hash/CMakeFiles/hello.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/glee/lte/openlte-code/polarssl/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable hello"
	cd /home/glee/lte/openlte-code/polarssl/build/programs/hash && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/hello.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
programs/hash/CMakeFiles/hello.dir/build: programs/hash/hello

.PHONY : programs/hash/CMakeFiles/hello.dir/build

programs/hash/CMakeFiles/hello.dir/requires: programs/hash/CMakeFiles/hello.dir/hello.c.o.requires

.PHONY : programs/hash/CMakeFiles/hello.dir/requires

programs/hash/CMakeFiles/hello.dir/clean:
	cd /home/glee/lte/openlte-code/polarssl/build/programs/hash && $(CMAKE_COMMAND) -P CMakeFiles/hello.dir/cmake_clean.cmake
.PHONY : programs/hash/CMakeFiles/hello.dir/clean

programs/hash/CMakeFiles/hello.dir/depend:
	cd /home/glee/lte/openlte-code/polarssl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/glee/lte/openlte-code/polarssl /home/glee/lte/openlte-code/polarssl/programs/hash /home/glee/lte/openlte-code/polarssl/build /home/glee/lte/openlte-code/polarssl/build/programs/hash /home/glee/lte/openlte-code/polarssl/build/programs/hash/CMakeFiles/hello.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : programs/hash/CMakeFiles/hello.dir/depend

