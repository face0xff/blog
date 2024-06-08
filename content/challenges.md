---
title: "Challenges"
---

As much as I love solving CTF challenges, I also greatly enjoy designing my own puzzles.
This page indexes some challenges I have created in the past for various occasions (not an exhaustive list).

---

## SSTIC 2024: The Green Shard Brawl

<span class="challenge-tag">#pwn</span> <span class="challenge-tag">#linux</span> <span class="challenge-tag">#heap</span>

A binary exploitation problem created for the renowned, annual SSTIC challenge.
It consists of a Linux client for a multi-player SDL game written in C, and a Python server that implements a custom protocol. 
The goal is to spawn a reverse shell on another player's machine solely by interacting with the server.

You can download the challenge files [here](/challs/the-green-shard-brawl.zip), including a Docker Compose setup
to run both the server and the victim's client.

<img src="/img/challs/the-green-shard-brawl.png" style="margin: 0 auto; margin-top: 1em; margin-bottom: 1em;" alt="Game client" />

*Green Shard Brawl* is a fun way to learn about glibc heap exploitation (fastbin, tcache, safe-linking...)
in a unique client-to-client exploitation setting. The vulnerabilities are rather easy to spot, which allows
to focus primarily on exploitation. The sources for the client are not given, however the binary does contain symbols.

<div class="spoiler">
A use-after-free vulnerability can be triggered when a player goes from one map to another while holding an object,
taking inspiration from <a href="https://www.youtube.com/watch?v=rCxRjjLs6z0">a real bug in The Legend of Zelda: Ocarina of Time</a>.
This can be exploited on a remote player by leveraging game physics such as the attack kickback effect,
and then turned into an arbitrary read/write primitive through some careful heap feng shui.
</div>

Multiple write-ups about this challenge are featured over on [SSTIC's website](https://www.sstic.org/2024/challenge/).

---

## ECW 2023: kaleidoscope

<span class="challenge-tag">#reverse</span> <span class="challenge-tag">#windows</span> <span class="challenge-tag">#vm</span>

A reverse engineering challenge made for the European Cyber Week CTF qualifiers,
focusing on Windows-specific mechanisms and obfuscation, with a little twist.

You can download the challenge [here](/challs/kaleidoscope.zip) (password: `ecw2023`).

<div class="spoiler">
The binary is a virtual machine that leverages inter-thread communication to implement
opcode fetching and decryption, inspired by <em>Instruction Set Randomization</em>.
The twist is that the emulated program auto-exploits a chain of bugs in the VM host in order to
obfuscate itself, by redirecting the control flow to change the key used to decrypt the instructions.
</div>

I published an official, detailed write-up for this challenge [over on Thalium's blog](https://blog.thalium.re/posts/ecw-2023-kaleidoscope-write-up/).

---

## ECW 2023: spaceships

<span class="challenge-tag">#reverse</span> <span class="challenge-tag">#puzzle</span>

A reverse engineering challenge made for the European Cyber Week CTF qualifiers which consists of
a single ELF binary file ([download](/challs/spaceships)), sheltering an interesting visual puzzle.

<div class="spoiler">
The binary implements the <a href="https://en.wikipedia.org/wiki/Conway%27s_Game_of_Life">Game of Life</a> cellular automaton.
The input encodes the starting positions of <a href="https://conwaylife.com/wiki/Middleweight_spaceship">middleweight spaceships</a>.
These are expected to run into <a href="https://conwaylife.com/wiki/135-degree_MWSS-to-G">converters</a> after several iterations,
which reflect the input spaceships into outgoing glider patterns. The goal is to find the correct input positions
that allow to shoot and destroy specific targets using these gliders.
</div>

Here are some community write-ups for this challenge:
* https://basilics.github.io/2023/10/02/Spaceships.html
* https://github.com/apoirrier/CTFs-writeups/blob/master/ECW2023/Reverse/Spaceships.md

---

## Root-Me 10K CTF (2022): chef's kiss

<span class="challenge-tag">#reverse</span> <span class="challenge-tag">#misc</span>

I came up with this challenge idea for an event organized by Root-Me. It fits into [a single URL](https://gchq.github.io/CyberChef/#recipe=Label('loop')Conditional_Jump('%5EPROG%3DA',false,'handle_A',10000)Conditional_Jump('%5EPROG%3DD',false,'handle_D',10000)Conditional_Jump('%5EPROG%3DE',false,'handle_E',10000)Conditional_Jump('%5EPROG%3DI',false,'handle_I',10000)Conditional_Jump('%5EPROG%3DJ',false,'handle_J',10000)Conditional_Jump('%5EPROG%3DP',false,'handle_P',10000)Conditional_Jump('%5EPROG%3DR',false,'handle_R',10000)Conditional_Jump('%5EPROG%3DS',false,'handle_S',10000)Conditional_Jump('%5EPROG%3D%5C%5C$',false,'handle_sys',10000)Label('nexti')Fork('%5C%5Cn','%5C%5Cn',false)Conditional_Jump('%5EPROG%3D',true,'endfork',10000)Find_/_Replace(%7B'option':'Regex','string':'%5EPROG%3D'%7D,'',true,false,true,false)Drop_bytes(0,1,false)Find_/_Replace(%7B'option':'Regex','string':'(.%2B)'%7D,'PROG%3D$1',true,false,true,false)Label('endfork')Merge(true)Jump('loop',10000)Return()Label('handle_A')Fork('%5C%5CnSTACK%3D','%5C%5CnSTACK%3D',false)Conditional_Jump('%5EPROG%3D',false,'handle_A_endfork',10000)Label('handle_A_forkinnerloop')Conditional_Jump('%5E%5C%5Cx00',false,'handle_A_endforkinnerloop',10000)ADD(%7B'option':'Hex','string':'ff010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'%7D)Jump('handle_A_forkinnerloop',10000)Label('handle_A_endforkinnerloop')Drop_bytes(0,1,false)Label('handle_A_endfork')Merge(true)Jump('nexti',10000)Label('handle_D')Find_/_Replace(%7B'option':'Regex','string':'STACK%3D(.)(.*)'%7D,'STACK%3D$1$1$2',true,false,true,true)Jump('nexti',10000)Label('handle_E')Find_/_Replace(%7B'option':'Regex','string':'STACK%3D(.)(.)(.*)'%7D,'STACK%3D$2$1$3',true,false,true,true)Jump('nexti',10000)Label('handle_I')Fork('%5C%5CnSTACK%3D','%5C%5CnSTACK%3D',false)Conditional_Jump('%5EPROG%3D',false,'handle_I_endfork',10000)ADD(%7B'option':'Hex','string':'010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'%7D)Label('handle_I_endfork')Merge(true)Jump('nexti',10000)Label('handle_J')Conditional_Jump('STACK%3D%5C%5Cx00',true,'handle_J_end',10000)Find_/_Replace(%7B'option':'Regex','string':'PROG%3DJ%5C%5C%5B%5B%5E%5C%5C%5D%5D%2B%5C%5C%5D(.*)'%7D,'PROG%3DJ$1',true,false,true,false)Label('handle_J_end')Find_/_Replace(%7B'option':'Regex','string':'STACK%3D.(.*)'%7D,'STACK%3D$1',true,false,true,true)Jump('nexti',10000)Label('handle_P')Find_/_Replace(%7B'option':'Regex','string':'STACK%3D(.*)'%7D,'STACK%3D%5C%5Cx00$1',true,false,true,true)Jump('nexti',10000)Label('handle_R')Find_/_Replace(%7B'option':'Regex','string':'STACK%3D(.)(.*)'%7D,'STACK%3D$2$1',true,false,true,true)Jump('nexti',10000)Label('handle_S')Fork('%5C%5CnSTACK%3D','%5C%5CnSTACK%3D',false)Conditional_Jump('%5EPROG%3D',false,'handle_S_endfork',10000)SUB(%7B'option':'Hex','string':'010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'%7D)Label('handle_S_endfork')Merge(true)Jump('nexti',10000)Label('handle_sys')Conditional_Jump('STACK%3D%5C%5Cx01',false,'handle_sys_1',10000)Conditional_Jump('STACK%3D%5C%5Cx02',false,'handle_sys_2',10000)Conditional_Jump('STACK%3D%5C%5Cx03',false,'handle_sys_3',10000)Conditional_Jump('STACK%3D%5C%5Cx04',false,'handle_sys_4',10000)Jump('handle_sys_err',10000)Label('handle_sys_end')Jump('nexti',10000)Label('handle_sys_1')Fork('%5C%5CnSTACK%3D','%5C%5CnSTACK%3D',false)Conditional_Jump('%5EPROG%3D',false,'handle_sys_1_endfork',10000)Drop_bytes(0,1,false)RC4(%7B'option':'UTF8','string':'A%20cyberchef%20crackme?%20Are%20you%20kidding%20me?'%7D,'Latin1','Latin1')Label('handle_sys_1_endfork')Merge(true)Jump('handle_sys_end',10000)Label('handle_sys_2')Fork('%5C%5CnSTACK%3D','%5C%5CnSTACK%3D',false)Conditional_Jump('%5EPROG%3D',false,'handle_sys_2_endfork',10000)Drop_bytes(0,1,false)Rotate_right(4,false)Label('handle_sys_2_endfork')Merge(true)Jump('handle_sys_end',10000)Label('handle_sys_3')Find_/_Replace(%7B'option':'Regex','string':'.%2B'%7D,'Wrong%20:(',true,false,true,true)Return()Label('handle_sys_4')Find_/_Replace(%7B'option':'Regex','string':'.%2B'%7D,'Congrats%20:)',true,false,true,true)Return()Label('handle_sys_err')Find_/_Replace(%7B'option':'Regex','string':'.%2B'%7D,'Fatal%20error:%20unrecognized%20syscall',true,false,true,true)Return()&input=UFJPRz1QSSRQSUkkUElJSUFSUElBUlBJSUlJQVJQSUFSUElJSUlJQVJQSUlJSUlJSUlJQVJQSUlBUlBJSUlJSUlBUlBJSUlJSUFSUElJSUFSUElJSUlJQVJQSUlJSUlJSUlBUlBJSUlJSUlJSUlBUlBJSUlJSUlJQVJQSUlJSUlJSUlJQVJQSSRTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NKW1BJSUkkXVNTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU0pbUElJSSRdU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTSltQSUlJJF1TU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU0pbUElJSSRdU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTSltQSUlJJF1TU1NTU1NTU1NTU1NTU1NTU1NKW1BJSUkkXVNTU0pbUElJSSRdU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTSltQSUlJJF1TU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU0pbUElJSSRdU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU0pbUElJSSRdU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU0pbUElJSSRdU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NKW1BJSUkkXVNTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTSltQSUlJJF1TU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NKW1BJSUkkXVNTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTSltQSUlJJF1QSUlJSSQKU1RBQ0s9ZW50ZXJfZmxhZ19oZXJl), which redirects to a CyberChef recipe.

<div class="spoiler">
The recipe is a crackme that validates an input. However, it goes even further by implementing a basic virtual machine.
</div>

You can find my official write-up for this challenge [over here](https://ctf.0xff.re/2022/rootme10k/chefskiss).

---

## ECW 2021: Pipe Dream

<span class="challenge-tag">#reverse</span> <span class="challenge-tag">#linux</span> <span class="challenge-tag">#puzzle</span>

A reverse engineering challenge ([download](/img/pipedream/pipedream)) made for the European Cyber Week CTF qualifiers, that leverages some specific Linux-specific mechanisms to implement a logic puzzle.

<div class="spoiler">
The input key is validated by going through a mesh of forked processes one character at a time.
Adjacent processes communicate through pipes using a custom protocol.
These basically implement a fifteen sliding puzzle, which initial state is derived from the username.
</div>

I released an official, detailed write-up for this challenge [here](/posts/ecw-ctf-2021-pipe-dream-writeup/).
