CAIRN FOR WINDOWS (x64)

Extract the whole ZIP to a folder you own. No administrator access, Rust,
Node.js, service installation or firewall changes are needed.

Double-click Start Cairn.cmd to start your node and open its web interface.
Close the Cairn node window to stop it. Your data stays under
%LOCALAPPDATA%\Cairn. Starting again reopens the same data.

If another application uses port 8080, the node reports that and stops.
For a different port, run the command below in PowerShell and open the
corresponding localhost URL in your browser:

  .\cairn.exe --data-dir "$env:LOCALAPPDATA\Cairn" --root "$env:LOCALAPPDATA\Cairn" run --listen 127.0.0.1:0 --serve 127.0.0.1:8090 --no-mcp

Stop the existing Cairn node before starting another copy on the same data.

The executable also provides every CLI subcommand, including mcp and lab.
Run .\cairn.exe --help for the command list. It embeds the web interface.

Windows supports the node, reading/syncing, signed workspaces, and in-process
checkers. There is no qualified native Windows sandbox for objective-authored
programs yet: those verifiers report Unavailable instead of running unconfined.
CAIRN_REQUIRE_SANDBOX=off cannot disable this Windows requirement. Use a
supported verifier host for external code and a supported Linux sandbox for
isolated lab experiments.

This portable package is unsigned. Its adjacent SHA-256 file checks download
integrity; it is not an Authenticode signature or proof of publisher identity.
