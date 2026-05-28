Zookeeper Client Packets Wireshark Dissector
============================================

Should works as of Wireshark v4.6.2.

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

