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

# Utility rule file for NightlyMemoryCheck.

# Include the progress variables for this target.
include depends/libsnark/libsnark/CMakeFiles/NightlyMemoryCheck.dir/progress.make

depends/libsnark/libsnark/CMakeFiles/NightlyMemoryCheck:
	cd /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/libsnark && /usr/bin/ctest -D NightlyMemoryCheck

NightlyMemoryCheck: depends/libsnark/libsnark/CMakeFiles/NightlyMemoryCheck
NightlyMemoryCheck: depends/libsnark/libsnark/CMakeFiles/NightlyMemoryCheck.dir/build.make

.PHONY : NightlyMemoryCheck

# Rule to build all files generated by this target.
depends/libsnark/libsnark/CMakeFiles/NightlyMemoryCheck.dir/build: NightlyMemoryCheck

.PHONY : depends/libsnark/libsnark/CMakeFiles/NightlyMemoryCheck.dir/build

depends/libsnark/libsnark/CMakeFiles/NightlyMemoryCheck.dir/clean:
	cd /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/libsnark && $(CMAKE_COMMAND) -P CMakeFiles/NightlyMemoryCheck.dir/cmake_clean.cmake
.PHONY : depends/libsnark/libsnark/CMakeFiles/NightlyMemoryCheck.dir/clean

depends/libsnark/libsnark/CMakeFiles/NightlyMemoryCheck.dir/depend:
	cd /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jinweizhao/disk2/GitLab/sabres/libsnark-test /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/depends/libsnark/libsnark /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/libsnark /home/jinweizhao/disk2/GitLab/sabres/libsnark-test/src/depends/libsnark/libsnark/CMakeFiles/NightlyMemoryCheck.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : depends/libsnark/libsnark/CMakeFiles/NightlyMemoryCheck.dir/depend

