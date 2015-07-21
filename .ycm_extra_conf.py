#!/usr/bin/env python
#
# Copyright (C) 2014  Google Inc.
#
# This file is part of YouCompleteMe.
#
# YouCompleteMe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# YouCompleteMe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with YouCompleteMe.  If not, see <http://www.gnu.org/licenses/>.

import os
import ycm_core

# These are the compilation flags that will be used in case there's no
# compilation database set (by default, one is not set).
# CHANGE THIS LIST OF FLAGS. YES, THIS IS THE DROID YOU HAVE BEEN LOOKING FOR.
flags = [
'-Wall',
'-Wextra',
'-Werror',
'-fexceptions',
'-DNDEBUG',
# THIS IS IMPORTANT! Without a "-std=<something>" flag, clang won't know which
# language to use when compiling headers. So it will guess. Badly. So C++
# headers will be compiled as C headers. You don't want that so ALWAYS specify
# a "-std=<something>".
# For a C project, you would set this to something like 'c99' instead of
# 'c++11'.
'-std=c++11',
# ...and the same thing goes for the magic -x option which specifies the
# language that the files to be compiled are written in. This is mostly
# relevant for c++ headers.
# For a C project, you would set this to 'c' instead of 'c++'.
'-x',
'c++',
'-isystem',
'/usr/include',
'-isystem',
'/usr/local/include',
'-isystem',
'/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/../lib/c++/v1',
'-isystem',
'/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/include',
'-I','./listener',
'-I','./geolocation',
'-I','./sender',
'-I','./listener/lib/librte_acl',
'-I','./listener/lib/librte_cfgfile',
'-I','./listener/lib/librte_cmdline',
'-I','./listener/lib/librte_compat',
'-I','./listener/lib/librte_distributor',
'-I','./listener/lib/librte_eal',
'-I','./listener/lib/librte_ether',
'-I','./listener/lib/librte_hash',
'-I','./listener/lib/librte_ip_frag',
'-I','./listener/lib/librte_ivshmem',
'-I','./listener/lib/librte_jobstats',
'-I','./listener/lib/librte_kni',
'-I','./listener/lib/librte_kvargs',
'-I','./listener/lib/librte_lpm',
'-I','./listener/lib/librte_malloc',
'-I','./listener/lib/librte_mbuf',
'-I','./listener/lib/librte_mempool',
'-I','./listener/lib/librte_meter',
'-I','./listener/lib/librte_net',
'-I','./listener/lib/librte_pipeline',
'-I','./listener/lib/librte_pmd_af_packet',
'-I','./listener/lib/librte_pmd_bond',
'-I','./listener/lib/librte_pmd_e1000',
'-I','./listener/lib/librte_pmd_enic',
'-I','./listener/lib/librte_pmd_fm10k',
'-I','./listener/lib/librte_pmd_i40e',
'-I','./listener/lib/librte_pmd_ixgbe',
'-I','./listener/lib/librte_pmd_mlx4',
'-I','./listener/lib/librte_pmd_null',
'-I','./listener/lib/librte_pmd_pcap',
'-I','./listener/lib/librte_pmd_ring',
'-I','./listener/lib/librte_pmd_virtio',
'-I','./listener/lib/librte_pmd_vmxnet3',
'-I','./listener/lib/librte_pmd_xenvirt',
'-I','./listener/lib/librte_port',
'-I','./listener/lib/librte_power',
'-I','./listener/lib/librte_reorder',
'-I','./listener/lib/librte_ring',
'-I','./listener/lib/librte_sched',
'-I','./listener/lib/librte_table',
'-I','./listener/lib/librte_timer',
'-I','./listener/lib/librte_vhost',
]


# Set this to the absolute path to the folder (NOT the file!) containing the
# compile_commands.json file to use that instead of 'flags'. See here for
# more details: http://clang.llvm.org/docs/JSONCompilationDatabase.html
#
# Most projects will NOT need to set this to anything; you can just change the
# 'flags' list of compilation flags.
compilation_database_folder = ''

if os.path.exists( compilation_database_folder ):
  database = ycm_core.CompilationDatabase( compilation_database_folder )
else:
  database = None

SOURCE_EXTENSIONS = [ '.cpp', '.cxx', '.cc', '.c', '.m', '.mm' ]

def DirectoryOfThisScript():
  return os.path.dirname( os.path.abspath( __file__ ) )


def MakeRelativePathsInFlagsAbsolute( flags, working_directory ):
  if not working_directory:
    return list( flags )
  new_flags = []
  make_next_absolute = False
  path_flags = [ '-isystem', '-I', '-iquote', '--sysroot=' ]
  for flag in flags:
    new_flag = flag

    if make_next_absolute:
      make_next_absolute = False
      if not flag.startswith( '/' ):
        new_flag = os.path.join( working_directory, flag )

    for path_flag in path_flags:
      if flag == path_flag:
        make_next_absolute = True
        break

      if flag.startswith( path_flag ):
        path = flag[ len( path_flag ): ]
        new_flag = path_flag + os.path.join( working_directory, path )
        break

    if new_flag:
      new_flags.append( new_flag )
  return new_flags


def IsHeaderFile( filename ):
  extension = os.path.splitext( filename )[ 1 ]
  return extension in [ '.h', '.hxx', '.hpp', '.hh' ]


def GetCompilationInfoForFile( filename ):
  # The compilation_commands.json file generated by CMake does not have entries
  # for header files. So we do our best by asking the db for flags for a
  # corresponding source file, if any. If one exists, the flags for that file
  # should be good enough.
  if IsHeaderFile( filename ):
    basename = os.path.splitext( filename )[ 0 ]
    for extension in SOURCE_EXTENSIONS:
      replacement_file = basename + extension
      if os.path.exists( replacement_file ):
        compilation_info = database.GetCompilationInfoForFile(
          replacement_file )
        if compilation_info.compiler_flags_:
          return compilation_info
    return None
  return database.GetCompilationInfoForFile( filename )


# This is the entry point; this function is called by ycmd to produce flags for
# a file.
def FlagsForFile( filename, **kwargs ):
  if database:
    # Bear in mind that compilation_info.compiler_flags_ does NOT return a
    # python list, but a "list-like" StringVec object
    compilation_info = GetCompilationInfoForFile( filename )
    if not compilation_info:
      return None

    final_flags = MakeRelativePathsInFlagsAbsolute(
      compilation_info.compiler_flags_,
      compilation_info.compiler_working_dir_ )
  else:
    relative_to = DirectoryOfThisScript()
    final_flags = MakeRelativePathsInFlagsAbsolute( flags, relative_to )

  return {
    'flags': final_flags,
    'do_cache': True
  }

