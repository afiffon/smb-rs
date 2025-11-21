# SMB-CLI

this is a sample-ish program that uses the `smb` crate to build a command line utility.

## Usage

```sh
cargo run -- --help
```

Check out the subcommands `info` and `copy` for more details.

## Profiling

From the project's root, build with:

```sh
cargo build --profile profiling --features profiling
```

### macOS

- Build the program as described above.
- Install `instruments` from Xcode.
- Launch the program from command line.
- Open `instruments` and attach, using the right profiler.
- Enter in the command line to actually begin the execution of the program.

>[!note]
> Launching the program from within `instruments` doesn't work properly, since local network connections are blocked. This also happens when using `lldb` to attach to the process. The program must be launched from the command line, and then `instruments` can attach to it.
