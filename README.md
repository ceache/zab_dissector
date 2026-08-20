Zookeeper Client Packets Wireshark Dissector
============================================

Should works as of Wireshark v2.0.2.

This is a LUA dissector for the ZAB protocol used by Zookeeper.

**Only the messages exchanged between the client and the server are supported**

Installation
------------

For the tshark CLI utility

``` shell
$ tshark  \
    -X lua_script:zab.lua \
    -X lua_script1:port=20000 \
    [ ... tshark read/capture params ... ] \
    -VOzab  -Yzab -x | view -
```

A client may talk to many servers on different ports. Use the `ports=` argument
to register several ports at once (this is useful for cluster scenarios):

``` shell
$ tshark \
    -X lua_script:zab.lua \
    -X lua_script1:ports=2181,2182,20000 \
    -r <capture file> -Yzab
```

`port=N` always sets a single port (and is equivalent to `ports=N`), so the
single-port form remains fully backward compatible.

For the Wireshark GUI

Windows:
   1. Copy `zab.lua` to somewhere in your wireshark directory. For example,
      C:\Program Files\Wireshark.
   2. Open `init.lua` in your wireshark root directory. Comment the line
      `disable_lua = true` or change it to `disable_lua = false`.

Linux/MacOS
   1. Open/Create `init.lua` in your Wireshark config directory,
      `~/.config/wireshark`, with the line `disable_lua = false`
   2. Copy `zab.lua` to your plugins directory `~/.config/wireshark/plugins`
      (you may have to create it)

Running
-------

The default port is set to 2181, but keep in mind that clients can connect to
the Zookeeper server using any port configured in the configuration file.

In Wireshark GUI, you can right click on a packet and request to "decode as..."
and select the ZAB protocol.

With the `tshark` CLI, you'll need to use the `-X lua_script1:port` as above.


Capturing traffic
-----------------

Make sure you capture *full* streams or the decode will fail.
I also recommend setting some high buffer to avoid any packet drops by BPF.

``` shell
  $ tcpdump \
    -p -i lo \
    -s 0 -B 919400 \
    -w <path to capture file> \
    tcp port 2181
```

Code quality tooling
--------------------

The project ships two portable shell runners for Lua code quality. Both exit
with status `0` on clean code and `1` when issues are found.

``` shell
$ ./scripts/lint.sh        # run luacheck against zab.lua
$ ./scripts/format.sh      # format zab.lua in place (stylua)
$ ./scripts/format.sh --check  # verify zab.lua is formatted (no changes)
```

Install the underlying tools if they are missing:

``` shell
$ luarocks install luacheck   # Lua linter
$ brew install stylua         # or: cargo install stylua
```

