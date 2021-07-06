# BTP Wireshark Plugin

A Wireshark plugin for the [Bitnomial Transfer Protocol (BTP)](https://bitnomial.com/docs/bitnomial-transfer-protocol/): a binary, low latency, direct market access, trading and market data protocol.

## Installation

To install the BTP Wireshark plugin, copy `btp.lua` to the correct path for your operation system

 - Windows users can copy the file to `%APPDATA%\Wireshark\plugins\` or `WIRESHARK\plugins\`, where WIRESHARK is their Wireshark installation location.
 - Linux and other unix-like users can copy the file to `~/.local/lib/wireshark/plugins`
 - macOS users can copy the file to `INSTALLDIR/lib/wireshark/plugins`, unless they are using an application bundle, in which case they should copy the file to `Wireshark.app/Contents/PlugIns/wireshark`

More information is available [here](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html).

## Resources

The following are resources which were useful for the development and maintenance of this plugin.

- [Lua documentation](https://www.lua.org/manual/5.4/)
- [Wireshark Lua API reference](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html)
- [Wireshark wiki Lua article](https://gitlab.com/wireshark/wireshark/-/wikis/Lua)
- [This step-by-step guide with examples](https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html)
- [This guide to heuristic dissectors](https://mika-s.github.io/wireshark/lua/dissector/2018/12/30/creating-port-independent-wireshark-dissectors-in-lua.html)
