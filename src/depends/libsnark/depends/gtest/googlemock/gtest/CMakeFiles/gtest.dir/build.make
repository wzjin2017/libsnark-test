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
CMAKE_SOURCE_DIR = /home/jinweizhao/disk2/GitLab/sabres/libsnark-test

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src

# Include any dependencies generated for this target.
include depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/depend.make

# Include the progress variables for this target.
include depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/progress.make

# Include the compile flags for this target's objects.
include depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/flags.make

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.o: depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/flags.make
depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.o: ../depends/libsnark/depends/gtest/googletest/src/gtest-all.cc
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.o"
	cd /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/depends/gtest/googlemock/gtest && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/gtest.dir/src/gtest-all.cc.o -c /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/depends/libsnark/depends/gtest/googletest/src/gtest-all.cc

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/gtest.dir/src/gtest-all.cc.i"
	cd /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/depends/gtest/googlemock/gtest && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/depends/libsnark/depends/gtest/googletest/src/gtest-all.cc > CMakeFiles/gtest.dir/src/gtest-all.cc.i

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/gtest.dir/src/gtest-all.cc.s"
	cd /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/depends/gtest/googlemock/gtest && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/depends/libsnark/depends/gtest/googletest/src/gtest-all.cc -o CMakeFiles/gtest.dir/src/gtest-all.cc.s

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.o.requires:

.PHONY : depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.o.requires

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.o.provides: depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.o.requires
	$(MAKE) -f depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/build.make depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.o.provides.build
.PHONY : depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.o.provides

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.o.provides.build: depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.o


# Object files for target gtest
gtest_OBJECTS = \
"CMakeFiles/gtest.dir/src/gtest-all.cc.o"

# External object files for target gtest
gtest_EXTERNAL_OBJECTS =

depends/libsnark/depends/gtest/googlemock/gtest/libgtest.a: depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.o
depends/libsnark/depends/gtest/googlemock/gtest/libgtest.a: depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/build.make
depends/libsnark/depends/gtest/googlemock/gtest/libgtest.a: depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libgtest.a"
	cd /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/depends/gtest/googlemock/gtest && $(CMAKE_COMMAND) -P CMakeFiles/gtest.dir/cmake_clean_target.cmake
	cd /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/depends/gtest/googlemock/gtest && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/gtest.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/build: depends/libsnark/depends/gtest/googlemock/gtest/libgtest.a

.PHONY : depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/build

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/requires: depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/src/gtest-all.cc.o.requires

.PHONY : depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/requires

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/clean:
	cd /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/depends/gtest/googlemock/gtest && $(CMAKE_COMMAND) -P CMakeFiles/gtest.dir/cmake_clean.cmake
.PHONY : depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/clean

depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/depend:
	cd /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jinweizhao/disk2/GitLab/sabres/libsnark-test /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/depends/libsnark/depends/gtest/googletest /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/depends/gtest/googlemock/gtest /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/depends/gtest/googlemock/gtest/CMakeFiles/gtest.dir/depend

