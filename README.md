# Windows CE ARM Bughunting
Various scripts and programs that support my Windows CE 4.2/6.0 exploit development and fuzzing efforts

Current Files:

HarnessHandler.cpp
- A harness to facilitate the remote fuzzing of Windows CE 4.2 programs using Peach and other fuzzers
- Currently testing with MSXML3.dll, peach agent coming soon
- Supports injection/hooking based fuzzing, intended for file format fuzzing

ImageFuzz.cpp
- A barebones use case of the harness described in HarnessHandler.cpp
- Puts fuzzing thread into kernel mode and fuzzes LoadKernelLibrary function
- Currently being used to build agent
