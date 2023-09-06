# What is this?
This is a reverse engineering utility for Armored Core 6 which monitors accesses to param
memory in order to generate typed XML paramdefs. It does so using vectored exception
handling, but patches each instruction after the access took place to avoid further
access violations, thereby allowing the game to run at playable framerate. It also 
logs said instructions to the console, allowing one to quickly find instructions 
that make use of a given param field. 

# How do I use it?
Simply unpack the ZIP file to a folder (you do *NOT* need to put this in game files), 
and run `launcher.exe` and play for as long as possible. Trying to use every mechanic 
and explore every bit of content means generation of more completed type maps!

Generated XML paramdefs will be dumped to the `paramdefs` folder next to the DLL and launcher
every 10 seconds.

# IMPORTANT
**Currently, the DLL DOES NOT load existing paramdef data on boot. All the existing data
will be overwritten when you re-inject it!** You will have to copy the defs out of the
folder after a gaming session, and merge them with existing ones using your own code.

# Roadmap (may do, may not)
- [x] Add basic config file
- [x] Support loading existing defs as a base
- [ ] Support logging accesses to specific params or offsets for RE purposes

# Bugs
Self-modifying code on this scale is hard, and you may encounter a crash or panic
due to an edge case I didn't consider. In this case please raise an issue or 
contact me on the Souls modding discord server (username `tremwil`). 

# How does it work?
Once loaded into the process, the DLL uses main thread hijacking to run its code before
Arxan does. Arxan code restoration routines are then patched out, allowing the 
many thousands of machine code patches which will later be performed. Since Arxan encrypts
some functions when the game boots and keeps them encrypted until they are called, the 
thread hijacking method allows flow analysis of these functions to be performed regardless.

Using the games's exception tables, a control flow graph (CFG) of the majority of the game's code
is then generated. This is required, since hooking arbitrary instructions reliably requires knowing 
all branch targets. In fact, we even need a heuristic to find branch targets in leaf functions, which
may not be reachable via exception tables. 

The DLL then waits for the game to load param data and proceeds to remap it. This is done by registering 
a [vectored exception handler (VEH)](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling) 
and taking the remapping the memory of each param file in a specific way. The original file, which looks like this
```
| Header | ID table | Param data |
```
is turned into
```
| Header | ID table || Enough PAGE_NOACCESS pages | ... | Original param file |
```
where `||` is a page boundary. Thus, when the game attempts to access param data, an access violation
exception is raised. It is then caught by our VEH. From there, we know the address of the instruction
which accessed the data, the accessed memory address, and the context of the thread. Since the layout
of our remapped param memory is fully known, the accessed param row and its offset can be identified.

From there, the instruction can be decoded using a [dissassembler library](https://github.com/zyantific/zydis)
to obtain information such as load size and memory operand type, allowing us to deduce the field type.
Once this is done, the instruction's memory displacement is shifted so that it now points to the
original, readable param data. 

Note that there are a few complications to this approac:
- An instruction could access data from many different param files, especially if they share a paramdef.
  Since we do not know which paramdefs are shared a-priori, the offset between the "fake, inaccesible" and
  "real" param file in memory must be constant for all params.
  
- The same instruction could also access non-param data. For example, if a struct within a param is copied,
  or a pointer to a param field is passed to a function. Hence simply patching the displacement of the instruction
  is not enough. To solve this, the code allocates all remapped param data in a contiguous memory block, and then
  generates a *conditional hook* at every instruction, which only runs the patched instruction if the accessed address
  lies within the param memory block. To avoid false positives and performance degradations due to excessive branching,
  common functions which may do this, such as `memcpy`, are hooked prior to remapping.

- Hooking arbitrary instructions is not easy. Program flow must be kept intact through multiple relocations, and
  branch targets which would be rendered invalid after generating a trampoline may not have enough range to be
  patched directly, in which case trampolines have to be recursively generated. At every step CFGs must be
  updated or regenerated. This required writing all my hooking code from scratch. 

- Hooking arbitrary instructions in hot threaded code without suspending the program is especially not easy.
  Program flow must be kept valid at almost all times, and (inevitable) data races limited to the patching of
  single instructions.

- Threads may simultaneously run the same param-accessing instruction. In this case, program flow may no
  longer be valid for the second one after the VEH is done patching the instruction for the 1st thread.
  Hence a map of `original -> patched` instruction addresses must be kept so that `RIP` can be explicitly
  adjusted for the second thread. 

# Credits
- [LukeYui](https://github.com/LukeYui) for showing me how to disable Arxan code restoration checks
- [Chainfailure](https://github.com/vswarte) for FD4 resource repository struct layouts

## Libraries Used
- HDE (MinHook's) dissassembler, by Vyacheslav Patkov. Quick and dirty, but fast!
- [Zydis](https://github.com/zyantific/zydis) for information-rich dissassembly
- [mem](https://github.com/0x1F9F1/mem) for RE QoL and its blazing-fast AVX2 pattern scanner
- [spdlog](https://github.com/gabime/spdlog) for logging
- [pugixml](https://github.com/zeux/pugixml) for XML serialization
- [ValveFileVDF](https://github.com/TinyTinni/ValveFileVDF) to find the game's install path
