# SharpShellcodeObfus

Just a simple C# exec to obfuscate shellcode using caeser cipher w/ a supplied # of rotations (pass shellcode without quotes)

```
SharpShellcodeObfus -r [rotations] -s [shellcode]
```

to reverse, run the command supplied giving the number of rotations used to encode the shellcode and the encoded shellcode
```
SharpShellcodeObfus -o -r [rotations] -s [shellcode]
```
