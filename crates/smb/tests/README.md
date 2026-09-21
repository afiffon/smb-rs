# Integration tests

## Running the tests

The tests below are intended to test the library's integration with the SMB protocol,
by starting up a samba container and running the tests against it.

To start the container, run the following command:

```bash
docker compose up [-d]
```

Then, you can run the tests as usual, using `cargo test`.

> [!IMPORTANT]
> The tests bind to port 445 by default, so make sure it is available on your machine.
> On many windows machines, this port is already in use by the system;
> Modify docker-compose.yml to use a different port if necessary,
> and use the `SMB_RUST_TESTS_SERVER=HOST:PORT` environment variable
> to specify the new port.
> The same goes for the IP address, if necessary.

The Samba image is a disposable `SMB.TEST` Active Directory domain controller.
It serves the regular authenticated share, a guest share, and a dedicated
Kerberos share from the same process. Its fixed test identity is
`LocalAdmin@SMB.TEST` with password `123456`.

Start it with:

```bash
docker compose up -d --build --wait tests
```

The image registers `cifs/localhost`, so the complete local suite needs only the
KDC address. No `kinit`, hosts-file change, or separate Kerberos test command is
required:

```bash
SSPI_KDC_URL=tcp://127.0.0.1:88 cargo test -p smb --features kerberos
```

The normal tests explicitly use NTLM, while Kerberos tests disable NTLM fallback
and use `KerberosShare`. CI enables the `kerberos` feature in its regular test
matrix, so both paths and the guest share run every time. Set
`SMB_RUST_TESTS_KERBEROS_SERVER` only when the KDC's SMB hostname is not
`localhost`; the hostname must have a matching CIFS service principal.

Ports 88 (TCP and UDP), 139, and 445 must be available. Recreating the container
provisions a fresh domain and discards its test files.
