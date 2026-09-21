cairn @VERSION@ for macOS (@ARCH_LABEL@)
======================================================================

Double-click "Install Cairn.pkg". It installs:

    /Applications/Cairn.app        the app: runs a node and shows it in a window
    /usr/local/cairn/bin/cairn     the command-line program the app runs
    /usr/local/bin/cairn           a link to it, so `cairn` is on your PATH

It starts no background service and adds no login item. The app's node runs
only while the app is open, and keeps its data in
~/Library/Application Support/Cairn.


@GATEKEEPER_NOTE@


THEN
----------------------------------------------------------------------

Open Cairn from Applications. Or, from a new terminal window:

    cairn --version
    cairn run                  # a complete local node
                               # reader: http://127.0.0.1:8080/ui/

Check it before you trust it. This re-derives a real settled log, which is
the point of the whole project:

    git clone https://github.com/aburan28/cairn
    cd cairn
    cairn --log launch/cairn.jsonl --root . audit


TO REMOVE IT
----------------------------------------------------------------------

    sudo rm -rf /usr/local/cairn /usr/local/bin/cairn /Applications/Cairn.app
    sudo pkgutil --forget @IDENTIFIER@
    sudo pkgutil --forget @APP_IDENTIFIER@

That leaves the app's node data in ~/Library/Application Support/Cairn,
which holds the node's identity; delete it only if you mean to.


Documentation, and every other way to install:
    https://github.com/aburan28/cairn/blob/main/docs/install.md
