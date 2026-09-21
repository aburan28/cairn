cairn @VERSION@ for macOS (@ARCH_LABEL@)
======================================================================

Double-click "Install Cairn.pkg". It installs one command-line program:

    /usr/local/cairn/bin/cairn     the program
    /usr/local/bin/cairn           a link to it, so `cairn` is on your PATH

It starts no background service and adds no login item.


@GATEKEEPER_NOTE@


THEN
----------------------------------------------------------------------

Open a new terminal window:

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

    sudo rm -rf /usr/local/cairn /usr/local/bin/cairn
    sudo pkgutil --forget @IDENTIFIER@


Documentation, and every other way to install:
    https://github.com/aburan28/cairn/blob/main/docs/install.md
