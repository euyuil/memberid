#!/usr/bin/env python3
"""Manage MemberID's local development TLS certificates."""
import argparse
import contextlib
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile

CA_DIRECTORY = Path.home() / ".local/share/memberid/dev-ca"
ROOT_CERTIFICATE = "root-ca.pem"
ROOT_KEY = "root-ca-key.pem"
COMPOSE_ENV = Path(".local/compose/compose.env")
TLS_DIRECTORY = COMPOSE_ENV.parent / "tls"
TLS_FILES = ("ca.pem", "server.pem", "server-key.pem")
LEAF_DAYS = 90


def openssl(*args):
    result = subprocess.run(["openssl", *args], capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError(f"OpenSSL {args[0]} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def private(path, kind):
    metadata = path.lstat()
    if not kind(metadata.st_mode):
        raise ValueError(f"Unexpected file type: {path}")
    if os.name == "posix" and (metadata.st_uid != os.getuid() or metadata.st_mode & 0o077):
        raise ValueError(f"Only the current owner may access {path}")


def check_key(certificate, key):
    if openssl("x509", "-in", certificate, "-noout", "-pubkey") != openssl(
        "pkey", "-passin", "pass:", "-in", key, "-pubout"
    ):
        raise ValueError(f"The certificate and private key do not match: {certificate}")


def initialize_ca(directory):
    directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.mkdir(mode=0o700)
    try:
        certificate, key = directory / ROOT_CERTIFICATE, directory / ROOT_KEY
        openssl(
            "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "1825",
            "-subj", "/CN=MemberID Shared Development CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "nameConstraints=critical,permitted;DNS:.memberid.localhost,"
            "excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0",
            "-keyout", key, "-out", certificate,
        )
        check_key(certificate, key)
        openssl("verify", "-check_ss_sig", "-CAfile", certificate, certificate)
    except BaseException:
        shutil.rmtree(directory)
        raise
    print(f"Public CA certificate: {certificate}")


def environment():
    values = {}
    for line in COMPOSE_ENV.read_text(encoding="utf-8").splitlines():
        name, _, value = line.partition("=")
        values[name] = value
    port = values.get("MEMBERID_LOCAL_HTTPS_PORT", "19000")
    auth_host = values.get("MEMBERID_LOCAL_AUTH_HOST", "auth.memberid.localhost")
    admin_host = values.get("MEMBERID_LOCAL_ADMIN_HOST", "admin.memberid.localhost")
    match = re.fullmatch(r"auth(-[a-z0-9](?:[a-z0-9-]{0,55}[a-z0-9])?)?\.memberid\.localhost", auth_host)
    if not match:
        raise ValueError("Invalid MemberID local auth hostname")
    suffix = match[1] or ""
    expected_admin = f"admin{suffix}.memberid.localhost"
    valid_port = re.fullmatch(r"1900[1-9]", port) if suffix else port == "19000"
    if admin_host != expected_admin or not valid_port:
        raise ValueError("Expected MemberID's matching local auth/admin hostnames and HTTPS port")
    return (auth_host, admin_host), int(port)


def issue_leaf(directory, output, hosts):
    certificate, key = directory / ROOT_CERTIFICATE, directory / ROOT_KEY
    private(directory, stat.S_ISDIR)
    private(certificate, stat.S_ISREG)
    private(key, stat.S_ISREG)
    check_key(certificate, key)
    openssl("verify", "-check_ss_sig", "-CAfile", certificate, certificate)
    openssl("x509", "-in", certificate, "-noout", "-checkend", str(LEAF_DAYS * 86400))
    request = output / "server.csr"
    extensions = output / "server.ext"
    leaf, leaf_key = output / "server.pem", output / "server-key.pem"
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj",
            f"/CN={hosts[0]}", "-keyout", leaf_key, "-out", request)
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        f"subjectAltName=DNS:{hosts[0]},DNS:{hosts[1]}\n",
        encoding="ascii",
    )
    serial = "0x" + openssl("rand", "-hex", "16").strip()
    openssl("x509", "-req", "-sha256", "-days", str(LEAF_DAYS), "-in", request,
            "-extfile", extensions, "-CA", certificate, "-CAkey", key, "-passin", "pass:",
            "-set_serial", serial, "-out", leaf)
    shutil.copyfile(certificate, output / "ca.pem")
    check_key(leaf, leaf_key)
    for host in hosts:
        openssl("verify", "-CAfile", output / "ca.pem", "-purpose", "sslserver",
                "-verify_hostname", host, leaf)


def check_served(hosts, port):
    root, leaf = TLS_DIRECTORY / "ca.pem", TLS_DIRECTORY / "server.pem"
    expected = ssl.PEM_cert_to_DER_cert(leaf.read_text(encoding="ascii"))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=root)
    for host in hosts:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
            with context.wrap_socket(connection, server_hostname=host) as secured:
                if secured.getpeercert(binary_form=True) != expected:
                    raise ValueError(f"{host}:{port} is serving a different certificate")
        print(f"Verified TLS for https://{host}:{port}")


def recreate():
    subprocess.run(
        ["docker", "compose", "--env-file", str(COMPOSE_ENV), "up", "-d", "--no-deps",
         "--force-recreate", "--wait", "--wait-timeout", "45", "proxy", "console"],
        env={**os.environ, "MSYS_NO_PATHCONV": "1", "MSYS2_ARG_CONV_EXCL": "*"},
        check=True,
    )


@contextlib.contextmanager
def tls_lock():
    lock = TLS_DIRECTORY / ".certificate-update"
    lock.mkdir()
    try:
        yield
    finally:
        lock.rmdir()


def update(command, directory, hosts, port):
    renewing = command == "renew"
    if not renewing:
        TLS_DIRECTORY.mkdir(mode=0o700, exist_ok=True)
    private(TLS_DIRECTORY, stat.S_ISDIR)
    with tls_lock(), tempfile.TemporaryDirectory(dir=TLS_DIRECTORY) as temporary:
        output = Path(temporary)
        if renewing:
            for name in TLS_FILES:
                private(TLS_DIRECTORY / name, stat.S_ISREG)
        elif any(os.path.lexists(TLS_DIRECTORY / name) for name in TLS_FILES):
            raise ValueError("Existing TLS material found. Use renew to replace it.")

        issue_leaf(directory, output, hosts)
        backup = None
        if renewing:
            backup = Path(tempfile.mkdtemp(prefix="previous-tls-", dir=COMPOSE_ENV.parent))
            for name in TLS_FILES:
                shutil.copy2(TLS_DIRECTORY / name, backup / name)
            print(f"Previous certificates and key: {backup}", flush=True)

        installed = []
        try:
            for name in TLS_FILES:
                os.replace(output / name, TLS_DIRECTORY / name)
                installed.append(name)
            if renewing:
                recreate()
                check_served(hosts, port)
        except (OSError, ValueError, subprocess.CalledProcessError, KeyboardInterrupt):
            for name in installed:
                destination = TLS_DIRECTORY / name
                if backup is None:
                    destination.unlink()
                else:
                    shutil.copy2(backup / name, output / name)
                    os.replace(output / name, destination)
            if renewing and installed:
                recreate()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca-dir", type=Path, default=CA_DIRECTORY)
    parser.add_argument("command", choices=("init", "issue", "renew", "check"))
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "init":
            initialize_ca(args.ca_dir)
        else:
            hosts, port = environment()
            if args.command == "check":
                check_served(hosts, port)
            else:
                update(args.command, args.ca_dir, hosts, port)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
