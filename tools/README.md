# Campaign tools

Use the installed `ghidra-manager` entrypoint. Commands work without a checkout;
campaign artifacts belong outside the managed Ghidra installation.

```sh
ghidra-manager campaign --state ./campaign init --project fixture \
  --program fixture.exe --program-path /fixture.exe --goal 'Recover symbol names'
ghidra-manager campaign --state ./campaign --json status
ghidra-manager campaign --state ./campaign validate
ghidra-manager campaign --state ./campaign report
```

Lifecycle commands are offline: they neither connect to nor save Ghidra.
Initialization refuses a nonempty directory. Existing version 1 and 2 campaigns
remain readable, and the legacy skill scripts remain compatibility wrappers.
Reports render from canonical evidence without rewriting it.
