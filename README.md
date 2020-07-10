# BTP Wireshark Plugin

## Requirements

- CMake >= 3.5 (>= 3.7 on 32 bit Windows)
- Python >= 3.4
- Qt >= 5


## Building the Plugin

These instructions were made for MacOS.

### Shake

Build the plugin to `.build/dist/x86_64-osx/btp.so`:

```
$ ./Shakefile.hs
```

Build and copy the `btp.so` file to a Wireshark 3.0.x installation:

```
$ ./Shakefile.hs install
```

Remove the `.build` directiory:

```
$ ./Shakefile.hs clean
```


## Filters

You can filter BTP packets in Wireshark by using the tag `btp.[fieldName]`, e.g. `btp.authToken`. The fieldNames are exactly the same as the ones listed in Bitnomial Protocol docs.
