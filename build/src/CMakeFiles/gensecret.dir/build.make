# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

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
CMAKE_SOURCE_DIR = /home/jinweizhao/disk2/Github/libsnark-test

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jinweizhao/disk2/Github/libsnark-test/build

# Include any dependencies generated for this target.
include src/CMakeFiles/gensecret.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/gensecret.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/gensecret.dir/flags.make

src/CMakeFiles/gensecret.dir/gensecret.cpp.o: src/CMakeFiles/gensecret.dir/flags.make
src/CMakeFiles/gensecret.dir/gensecret.cpp.o: ../src/gensecret.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jinweizhao/disk2/Github/libsnark-test/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/CMakeFiles/gensecret.dir/gensecret.cpp.o"
	cd /home/jinweizhao/disk2/Github/libsnark-test/build/src && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/gensecret.dir/gensecret.cpp.o -c /home/jinweizhao/disk2/Github/libsnark-test/src/gensecret.cpp

src/CMakeFiles/gensecret.dir/gensecret.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/gensecret.dir/gensecret.cpp.i"
	cd /home/jinweizhao/disk2/Github/libsnark-test/build/src && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jinweizhao/disk2/Github/libsnark-test/src/gensecret.cpp > CMakeFiles/gensecret.dir/gensecret.cpp.i

src/CMakeFiles/gensecret.dir/gensecret.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/gensecret.dir/gensecret.cpp.s"
	cd /home/jinweizhao/disk2/Github/libsnark-test/build/src && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jinweizhao/disk2/Github/libsnark-test/src/gensecret.cpp -o CMakeFiles/gensecret.dir/gensecret.cpp.s

src/CMakeFiles/gensecret.dir/gensecret.cpp.o.requires:

.PHONY : src/CMakeFiles/gensecret.dir/gensecret.cpp.o.requires

src/CMakeFiles/gensecret.dir/gensecret.cpp.o.provides: src/CMakeFiles/gensecret.dir/gensecret.cpp.o.requires
	$(MAKE) -f src/CMakeFiles/gensecret.dir/build.make src/CMakeFiles/gensecret.dir/gensecret.cpp.o.provides.build
.PHONY : src/CMakeFiles/gensecret.dir/gensecret.cpp.o.provides

src/CMakeFiles/gensecret.dir/gensecret.cpp.o.provides.build: src/CMakeFiles/gensecret.dir/gensecret.cpp.o


# Object files for target gensecret
gensecret_OBJECTS = \
"CMakeFiles/gensecret.dir/gensecret.cpp.o"

# External object files for target gensecret
gensecret_EXTERNAL_OBJECTS =

src/gensecret: src/CMakeFiles/gensecret.dir/gensecret.cpp.o
src/gensecret: src/CMakeFiles/gensecret.dir/build.make
src/gensecret: src/CMakeFiles/gensecret.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/jinweizhao/disk2/Github/libsnark-test/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable gensecret"
	cd /home/jinweizhao/disk2/Github/libsnark-test/build/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/gensecret.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/gensecret.dir/build: src/gensecret

.PHONY : src/CMakeFiles/gensecret.dir/build

src/CMakeFiles/gensecret.dir/requires: src/CMakeFiles/gensecret.dir/gensecret.cpp.o.requires

.PHONY : src/CMakeFiles/gensecret.dir/requires

src/CMakeFiles/gensecret.dir/clean:
	cd /home/jinweizhao/disk2/Github/libsnark-test/build/src && $(CMAKE_COMMAND) -P CMakeFiles/gensecret.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/gensecret.dir/clean

src/CMakeFiles/gensecret.dir/depend:
	cd /home/jinweizhao/disk2/Github/libsnark-test/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jinweizhao/disk2/Github/libsnark-test /home/jinweizhao/disk2/Github/libsnark-test/src /home/jinweizhao/disk2/Github/libsnark-test/build /home/jinweizhao/disk2/Github/libsnark-test/build/src /home/jinweizhao/disk2/Github/libsnark-test/build/src/CMakeFiles/gensecret.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/gensecret.dir/depend
