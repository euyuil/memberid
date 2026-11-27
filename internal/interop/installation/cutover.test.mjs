import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { once } from "node:events";
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { setTimeout as sleep } from "node:timers/promises";

const source = process.env.MEMBERID_SCHEMA37_PACKAGE;
const target = process.env.MEMBERID_UPGRADE_PACKAGE;
const postgres =
  "postgres:18.6@sha256:bd5dfa494a5a259704365813dbfa5fa6b3e69be7348d43b547f540c730478583";

async function origin() {
  const listener = net.createServer();
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const port = listener.address().port;
  await new Promise((resolve) => listener.close(resolve));
  return "http://127.0.0.1:" + port;
}

function browser() {
  const cookies = new Map();
  return async function request(url, fields, headers = {}) {
    const response = await fetch(url, {
      redirect: "manual",
      method: fields ? "POST" : "GET",
      headers: {
        Cookie: [...cookies].map(([k, v]) => k + "=" + v).join("; "),
        ...(fields ? { Origin: new URL(url).origin } : {}),
        ...headers,
      },
      body: fields && new URLSearchParams(fields),
    });
    for (const c of response.headers.getSetCookie()) {
      const pair = c.split(";")[0];
      cookies.set(
        pair.slice(0, pair.indexOf("=")),
        pair.slice(pair.indexOf("=") + 1),
      );
    }
    return response;
  };
}

async function passwordCallback(
  request,
  start,
  issuer,
  callback,
  organization,
  password,
) {
  let response = await request(start);
  for (let i = 0; i < 12; i++) {
    if ([302, 303].includes(response.status)) {
      const location = new URL(response.headers.get("location"), response.url);
      if (location.origin + location.pathname === callback) return location;
      response = await request(location);
      continue;
    }
    assert.equal(response.status, 200, "expected a login form");
    const page = await response.text();
    const field = (name) => {
      const match = page.match(
        new RegExp('name="' + name + '" value="([^"]+)"'),
      );
      assert.ok(match, "missing " + name);
      return match[1];
    };
    const common = { request: field("request"), csrf: field("csrf") };
    if (page.includes('value="choose-organization"')) {
      response = await request(issuer + "/login", {
        ...common,
        action: "choose-organization",
        organization,
      });
    } else {
      assert.ok(page.includes('name="password"'), "expected a password field");
      response = await request(issuer + "/login", {
        ...common,
        action: "password",
        username: "root",
        password,
      });
    }
  }
  throw Error("login did not reach the registered callback");
}

test(
  "schema 37 root, protected console and relying-party account across cutover and recovery",
  { skip: !source || !target, timeout: 180000 },
  async (t) => {
    const temp = mkdtempSync(path.join(os.tmpdir(), "memberid-installation-"));
    t.after(() => rmSync(temp, { recursive: true }));
    const env = { ...process.env };
    const command = (binary, args, input) => {
      // Suppress command stdout/stderr on failure: they may contain credentials.
      try {
        return execFileSync(binary, args, {
          encoding: "utf8",
          env,
          input,
          timeout: 60000,
          windowsHide: true,
          stdio: ["pipe", "pipe", "pipe"],
        }).trim();
      } catch {
        throw Error(path.basename(binary) + " " + args[0] + " failed");
      }
    };
    const container = command("docker", [
      "run",
      "--detach",
      "--rm",
      "--tmpfs",
      "/var/lib/postgresql",
      "-p",
      "127.0.0.1::5432",
      "-e",
      "POSTGRES_HOST_AUTH_METHOD=trust",
      postgres,
    ]);
    const pg = (...args) => command("docker", ["exec", container, ...args]);
    t.after(() => command("docker", ["stop", container]));
    let ready = false;
    for (let i = 0; i < 60; i++) {
      try {
        pg("pg_isready", "-h", "127.0.0.1", "-U", "postgres");
        ready = true;
        break;
      } catch {
        await sleep(250);
      }
    }
    assert.ok(ready, "PostgreSQL startup");
    const port = command("docker", ["port", container, "5432/tcp"])
      .split(":")
      .at(-1);
    env.MEMBERID_DATABASE_URL =
      "postgres://postgres@127.0.0.1:" + port + "/postgres?sslmode=disable";
    env.MEMBERID_TEST_PGDUMP_CONTAINER = container;
    const exe = process.platform === "win32" ? "memberid.exe" : "memberid";
    let binary = path.join(source, exe);
    let config = path.join(temp, "installation");
    const issuer = await origin(),
      admin = await origin(),
      rp = await origin();
    const cli = (...args) => command(binary, args);
    cli(
      "config",
      "init",
      "--directory",
      config,
      "--issuer",
      issuer,
      "--allow-loopback-http",
    );
    const passwordFile = path.join(temp, "initial-password");
    cli("database", "init", "--initial-root-password-file", passwordFile);
    const password = readFileSync(passwordFile, "utf8").trim();
    const register = (name, callback, ...flags) =>
      JSON.parse(
        cli(
          "client",
          "add",
          "--directory",
          config,
          "--name",
          name,
          "--redirect",
          callback,
          "--preauthorized",
          ...flags,
        ),
      );
    const consoleClient = register(
      "Synthetic console",
      admin + "/auth/callback",
      "--system",
    );
    const application = register("Synthetic RP", rp + "/callback");
    writeFileSync(
      path.join(config, "console-secret"),
      consoleClient.client_secret,
      { mode: 0o600 },
    );
    writeFileSync(
      path.join(config, "console.json"),
      JSON.stringify({
        origin: admin,
        clientId: consoleClient.client_id,
        clientSecretFile: "console-secret",
      }),
      { mode: 0o600 },
    );
    const processes = [];
    async function stop() {
      for (const child of processes.splice(0).reverse()) {
        if (child.exitCode === null && child.signalCode === null) {
          const done = once(child, "exit");
          child.kill();
          await done;
        }
      }
    }
    t.after(stop);
    async function start(role, base, route) {
      const child = spawn(
        binary,
        [role, "--directory", config, "--listen", new URL(base).host],
        { env, windowsHide: true, stdio: "ignore" },
      );
      processes.push(child);
      for (let i = 0; i < 70; i++) {
        try {
          if ((await fetch(base + route)).ok) return;
        } catch {}
        if (child.exitCode !== null) break;
        await sleep(150);
      }
      throw Error(role + " startup failed");
    }
    async function exercise(organization, member, loginName) {
      await start("serve", issuer, "/.well-known/openid-configuration");
      await start("serve-console", admin, "/");
      const session = browser();
      const consoleCallback = await passwordCallback(
        session,
        admin + "/auth/login",
        issuer,
        admin + "/auth/callback",
        loginName,
        password,
      );
      assert.equal((await session(consoleCallback)).status, 303);
      const who = (await (await session(admin + "/api/session")).json()).actor;
      assert.equal(who.memberId, member);
      assert.equal(who.organizationId, organization);
      assert.equal(who.platform, true);
      const list = await (
        await session(
          admin + "/api/organizations/" + organization + "/oidc-applications",
        )
      ).json();
      const protectedClient = list.items.find(
        (item) => item.clientId === consoleClient.client_id,
      );
      assert.ok(protectedClient?.system && protectedClient.enabled);
      assert.equal(protectedClient.ownerOrganizationId, organization);

      const metadata = await (
        await fetch(issuer + "/.well-known/openid-configuration")
      ).json();
      const verifier = randomBytes(32).toString("base64url"),
        nonce = randomBytes(20).toString("hex"),
        state = randomBytes(20).toString("hex");
      const request = new URL(metadata.authorization_endpoint);
      request.search = new URLSearchParams({
        response_type: "code",
        scope: "openid profile",
        client_id: application.client_id,
        redirect_uri: rp + "/callback",
        state,
        nonce,
        code_challenge_method: "S256",
        code_challenge: createHash("sha256")
          .update(verifier)
          .digest("base64url"),
      });
      const agent = browser();
      const callback = await passwordCallback(
        agent,
        request,
        issuer,
        rp + "/callback",
        loginName,
        password,
      );
      assert.equal(callback.searchParams.get("state"), state);
      const tokens = await agent(
        metadata.token_endpoint,
        {
          grant_type: "authorization_code",
          code: callback.searchParams.get("code"),
          redirect_uri: rp + "/callback",
          code_verifier: verifier,
        },
        {
          Authorization:
            "Basic " +
            Buffer.from(
              application.client_id + ":" + application.client_secret,
            ).toString("base64"),
        },
      );
      assert.equal(tokens.status, 200);
      const [header, payload, signature] = (await tokens.json()).id_token.split(
        ".",
      );
      const decode = (encoded) =>
        JSON.parse(Buffer.from(encoded, "base64url").toString());
      const { alg, kid } = decode(header);
      assert.equal(alg, "RS256");
      const jwks = await (await fetch(metadata.jwks_uri)).json();
      const jwk = jwks.keys.find((key) => key.kid === kid && key.kty === "RSA");
      assert.ok(
        verify(
          "RSA-SHA256",
          Buffer.from(header + "." + payload),
          createPublicKey({ key: jwk, format: "jwk" }),
          Buffer.from(signature, "base64url"),
        ),
      );
      const claims = decode(payload);
      assert.equal(claims.iss, issuer);
      assert.equal(claims.sub, member);
      assert.equal(claims.nonce, nonce);
      assert.ok(
        [claims.aud].flat().includes(application.client_id) &&
          claims.exp > Date.now() / 1000,
      );
      await stop();
      return JSON.stringify([claims.iss, claims.sub]);
    }
    const legacy = await exercise("org_system", "mbr_root", "org_system");
    const account = { id: "fixture-account", permissions: ["approve"] };
    const links = new Map([[legacy, account]]);
    const relink = (oldKey, newKey) => {
      assert.equal(links.get(oldKey)?.id, account.id);
      assert.ok(!links.has(newKey));
      links.set(newKey, links.get(oldKey));
      links.delete(oldKey);
    };
    const pgDump = path.join(
      temp,
      process.platform === "win32" ? "pgdump.exe" : "pgdump",
    );
    command("go", ["build", "-o", pgDump, "./internal/interop/saml/pgdump"]);
    const recovery = path.join(temp, "recovery");
    binary = path.join(target, exe);
    const upgraded = JSON.parse(
      cli(
        "database",
        "upgrade",
        "--directory",
        config,
        "--backup-directory",
        recovery,
        "--maintenance-confirmed",
        "--pg-dump",
        pgDump,
      ),
    );
    assert.equal(upgraded.currentVersion, 38);
    cli("database", "backup-check", "--backup-directory", recovery);
    const ids = JSON.parse(cli("setup", "identities"));
    const next = JSON.stringify([issuer, ids.rootMemberId]);
    relink(legacy, next);
    const linked = links.get(
      await exercise(ids.organizationId, ids.rootMemberId, "system"),
    );
    assert.deepEqual(linked, {
      id: "fixture-account",
      permissions: ["approve"],
    });
    t.diagnostic(
      "upgraded protected console and verified RP subject both resolve to the expected accounts",
    );
    pg("createdb", "-U", "postgres", "restored");
    command(
      "docker",
      [
        "exec",
        "-i",
        container,
        "pg_restore",
        "-U",
        "postgres",
        "-d",
        "restored",
        "--exit-on-error",
        "--single-transaction",
      ],
      readFileSync(path.join(recovery, "database.dump")),
    );
    command(
      "docker",
      [
        "exec",
        "-i",
        container,
        "psql",
        "-U",
        "postgres",
        "-d",
        "restored",
        "-v",
        "ON_ERROR_STOP=1",
      ],
      readFileSync("docs/recovery-sessions.sql"),
    );
    env.MEMBERID_DATABASE_URL = env.MEMBERID_DATABASE_URL.replace(
      "/postgres?",
      "/restored?",
    );
    config = path.join(temp, "restored");
    cpSync(path.join(recovery, "installation"), config, { recursive: true });
    binary = path.join(source, exe);
    cli("database", "check");
    relink(next, legacy);
    assert.deepEqual(
      links.get(await exercise("org_system", "mbr_root", "org_system")),
      linked,
    );
    t.diagnostic(
      "restored the original console configuration, root subject, local account and grants",
    );
  },
);
