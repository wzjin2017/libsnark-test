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

# Utility rule file for Continuous.

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/Continuous.dir/progress.make

depends/libsnark/libsnark/CMakeFiles/Continuous:
	cd /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/libsnark && /usr/bin/ctest -D Continuous

Continuous: depends/libsnark/libsnark/CMakeFiles/Continuous
Continuous: depends/libsnark/libsnark/CMakeFiles/Continuous.dir/build.make

.PHONY : Continuous

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/Continuous.dir/build: Continuous

.PHONY : depends/libsnark/libsnark/CMakeFiles/Continuous.dir/build

depends/libsnark/libsnark/CMakeFiles/Continuous.dir/clean:
	cd /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/Continuous.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/Continuous.dir/clean

depends/libsnark/libsnark/CMakeFiles/Continuous.dir/depend:
	cd /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jinweizhao/disk2/GitLab/sabres/libsnark-test /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/depends/libsnark/libsnark /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/libsnark /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/libsnark/CMakeFiles/Continuous.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/Continuous.dir/depend

