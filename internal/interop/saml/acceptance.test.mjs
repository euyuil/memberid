import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { once } from "node:events";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { alterAndSign, createConsumer, parse } from "./consumer.mjs";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const postgres =
  "postgres:18.6@sha256:bd5dfa494a5a259704365813dbfa5fa6b3e69be7348d43b547f540c730478583";
const distribution = process.env.MEMBERID_SAML_PACKAGE;
const upgradeBaseline = process.env.MEMBERID_UPGRADE_BASELINE_PACKAGE;

function command(executable, args, env = process.env) {
  try {
    return execFileSync(executable, args, {
      env,
      encoding: "utf8",
      windowsHide: true,
      timeout: 60_000,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    // CLI stdout can contain generated credentials; never include it in failures.
    throw new Error(
      `${path.basename(executable)} ${args.slice(0, 2).join(" ")} failed`,
    );
  }
}

function hidden(body, name) {
  const match = body.match(new RegExp(`name="${name}" value="([^"]*)"`));
  assert.ok(match, `missing ${name} form field`);
  return parse(`<value>${match[1]}</value>`).documentElement.textContent;
}

function client(ca) {
  const cookies = new Map();
  return async (target, form, headers = {}) => {
    const url = new URL(target);
    const jar = cookies.get(url.host) ?? new Map();
    const data = form ? new URLSearchParams(form).toString() : undefined;
    return new Promise((resolve, reject) => {
      const request = https.request(
        url,
        {
          ca,
          agent: false,
          lookup: (_host, options, callback) =>
            options.all
              ? callback(null, [{ address: "127.0.0.1", family: 4 }])
              : callback(null, "127.0.0.1", 4),
          method: data ? "POST" : "GET",
          headers: {
            ...headers,
            Cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "),
            ...(data
              ? {
                  Origin: url.origin,
                  "Content-Type": "application/x-www-form-urlencoded",
                  "Content-Length": Buffer.byteLength(data),
                }
              : {}),
          },
        },
        (response) => {
          for (const item of response.headers["set-cookie"] ?? []) {
            const [name, ...value] = item.split(";", 1)[0].split("=");
            jar.set(name, value.join("="));
          }
          cookies.set(url.host, jar);
          let body = "";
          response.setEncoding("utf8");
          response.on("data", (chunk) => {
            body += chunk;
          });
          response.on("end", () =>
            resolve({
              status: response.statusCode,
              headers: response.headers,
              body,
            }),
          );
        },
      );
      request.setTimeout(10_000, () =>
        request.destroy(new Error("HTTP fixture timed out")),
      );
      request.on("error", reject);
      request.end(data);
    });
  };
}

test(
  "packaged MemberID with an independent Node-SAML SP",
  { skip: !distribution, timeout: 180_000 },
  async (t) => {
    assert.ok(
      path.isAbsolute(distribution),
      "MEMBERID_SAML_PACKAGE must be absolute",
    );
    const binaryName =
      process.platform === "win32" ? "memberid.exe" : "memberid";
    let executable = path.join(distribution, binaryName);
    const upgradedExecutable = executable;
    const build = readFileSync(path.join(distribution, "BUILDINFO"), "utf8");
    assert.ok(
      build.includes(
        `goos=${process.platform === "win32" ? "windows" : "linux"}\n`,
      ) && build.includes("cgo=0\n"),
    );
    const digest = createHash("sha256")
      .update(readFileSync(executable))
      .digest("hex");
    assert.ok(
      readFileSync(path.join(distribution, "SHA256SUMS"), "utf8")
        .split(/\r?\n/)
        .some(
          (line) =>
            line === `${digest}  ./${binaryName}` ||
            line === `${digest} *./${binaryName}`,
        ),
      "packaged executable checksum",
    );
    if (upgradeBaseline) {
      assert.ok(path.isAbsolute(upgradeBaseline));
      executable = path.join(upgradeBaseline, binaryName);
      const baselineHash = createHash("sha256")
        .update(readFileSync(executable))
        .digest("hex");
      assert.ok(
        readFileSync(path.join(upgradeBaseline, "SHA256SUMS"), "utf8")
          .split(/\r?\n/)
          .some(
            (line) =>
              line === `${baselineHash}  ./${binaryName}` ||
              line === `${baselineHash} *./${binaryName}`,
          ),
      );
    }

    const owner = randomBytes(6).toString("hex");
    const local = path.join(root, ".local");
    mkdirSync(local, { recursive: true });
    const directory = mkdtempSync(path.join(local, "saml-interop-"));
    const database = `memberid-saml-${owner}`;
    let databaseCreated = false;
    let processHandle;
    let edge;
    let logs = "";
    t.after(async () => {
      if (edge?.listening) await new Promise((resolve) => edge.close(resolve));
      if (
        processHandle &&
        processHandle.exitCode === null &&
        processHandle.signalCode === null
      ) {
        const exited = once(processHandle, "exit");
        processHandle.kill();
        await exited;
      }
      if (databaseCreated) {
        assert.equal(
          command("docker", [
            "inspect",
            "--format",
            '{{index .Config.Labels "memberid.saml-interop"}}',
            database,
          ]),
          owner,
          "database ownership",
        );
        command("docker", ["rm", "--force", "--volumes", database]);
      }
      assert.equal(path.dirname(directory), local, "fixture cleanup boundary");
      rmSync(directory, { recursive: true });
    });

    const authHost = `auth-saml-${owner}.memberid.localhost`;
    const spHost = `sp-saml-${owner}.memberid.localhost`;
    function certificate(name, extensions = []) {
      const key = path.join(directory, `${name}-key.pem`);
      const cert = path.join(directory, `${name}.pem`);
      command("openssl", [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        `/CN=MemberID synthetic ${name}`,
        "-keyout",
        key,
        "-out",
        cert,
        ...extensions,
      ]);
      return {
        key: readFileSync(key, "utf8"),
        cert: readFileSync(cert, "utf8"),
      };
    }
    const tls = certificate("tls", [
      "-addext",
      `subjectAltName=DNS:${authHost},DNS:${spHost}`,
    ]);
    const idpKeys = certificate("idp");
    const spKeys = certificate("sp");
    const sessions = new Map();
    let existingAccounts;
    let consumer;
    let issuer, spOrigin, acs;
    let upstreamPort;
    let lastFailure = "";
    edge = https.createServer(tls, async (request, response) => {
      response.setHeader("Cache-Control", "no-store");
      if (request.headers.host === new URL(issuer).host) {
        const proxy = http.request(
          {
            hostname: "127.0.0.1",
            agent: false,
            port: upstreamPort,
            path: request.url,
            method: request.method,
            headers: { ...request.headers, "x-forwarded-proto": "https" },
          },
          (result) => {
            response.writeHead(result.statusCode, result.headers);
            result.pipe(response);
          },
        );
        proxy.on("error", () => {
          response.writeHead(503).end();
        });
        request.pipe(proxy);
        return;
      }
      if (request.headers.host !== new URL(spOrigin).host) {
        response.writeHead(404).end();
        return;
      }
      try {
        const sid = request.headers.cookie?.match(
          /(?:^|; )sp-session=([^;]+)/,
        )?.[1];
        if (request.method === "GET" && request.url === "/login") {
          const location = await consumer.saml.getAuthorizeUrlAsync(
            "https://opaque.example.test/return",
          );
          sessions.delete(sid);
          response.setHeader(
            "Set-Cookie",
            "sp-session=; Secure; HttpOnly; SameSite=None; Path=/; Max-Age=0",
          );
          response.writeHead(302, { Location: location }).end();
        } else if (request.method === "POST" && request.url === "/acs") {
          let body = "";
          for await (const chunk of request) {
            body += chunk;
            if (body.length > 1_048_576) throw new Error("Oversized response");
          }
          const form = Object.fromEntries(new URLSearchParams(body));
          if (form.RelayState !== "https://opaque.example.test/return")
            throw new Error("RelayState mismatch");
          const profile = await consumer.consume(form);
          if (existingAccounts) {
            const account = existingAccounts.get(profile.nameID);
            if (!account) throw new Error("No existing application account");
            profile.accountId = account.id;
          }
          const session = randomBytes(24).toString("hex");
          sessions.set(session, profile);
          response.setHeader(
            "Set-Cookie",
            `sp-session=${session}; Secure; HttpOnly; SameSite=None; Path=/`,
          );
          response.writeHead(303, { Location: "/session" }).end();
        } else if (request.method === "GET" && request.url === "/session") {
          const profile = sessions.get(sid);
          response
            .writeHead(profile ? 200 : 401, {
              "Content-Type": "application/json",
            })
            .end(JSON.stringify(profile ?? {}));
        } else response.writeHead(404).end();
      } catch (error) {
        lastFailure = error.message;
        response.writeHead(400).end("SAML response rejected");
      }
    });
    for (let port = 19001; port <= 19009; port++) {
      try {
        await new Promise((resolve, reject) => {
          edge.once("error", reject);
          edge.listen(port, "127.0.0.1", () => {
            edge.removeListener("error", reject);
            resolve();
          });
        });
        issuer = `https://${authHost}:${port}`;
        spOrigin = `https://${spHost}:${port}`;
        break;
      } catch (error) {
        if (error.code !== "EADDRINUSE") throw error;
      }
    }
    assert.ok(issuer, "a free HTTPS port from 19001 through 19009 is required");
    acs = `${spOrigin}/acs`;
    const consumerOptions = {
      issuer: `${spOrigin}/metadata`,
      callbackUrl: acs,
      entryPoint: `${issuer}/saml/sso`,
      idpCert: idpKeys.cert,
      idpIssuer: `${issuer}/saml/metadata`,
      privateKey: spKeys.key,
    };
    consumer = createConsumer(consumerOptions);
    command("docker", [
      "run",
      "--detach",
      "--name",
      database,
      "--label",
      `memberid.saml-interop=${owner}`,
      "--tmpfs",
      "/var/lib/postgresql",
      "--publish",
      "127.0.0.1::5432",
      "--env",
      "POSTGRES_HOST_AUTH_METHOD=trust",
      postgres,
    ]);
    databaseCreated = true;
    let ready = false;
    for (let i = 0; i < 60; i++) {
      try {
        command("docker", [
          "exec",
          database,
          "pg_isready",
          // The image's temporary initialization server listens only on a
          // Unix socket. Wait for the final TCP listener used by MemberID.
          "--host",
          "127.0.0.1",
          "--username",
          "postgres",
        ]);
        ready = true;
        break;
      } catch {
        await sleep(200);
      }
    }
    assert.ok(ready, "disposable PostgreSQL startup");
    const databasePort = command("docker", ["port", database, "5432/tcp"])
      .split(":")
      .at(-1);
    const env = {
      ...process.env,
      MEMBERID_DATABASE_URL: `postgres://postgres@127.0.0.1:${databasePort}/postgres?sslmode=disable`,
    };
    const cli = (...args) => command(executable, args, env);
    let installation = path.join(directory, "installation");
    cli("config", "init", "--directory", installation, "--issuer", issuer);
    const configFile = path.join(installation, "memberid.json");
    const configuration = JSON.parse(readFileSync(configFile, "utf8"));
    configuration.saml = {
      enabled: true,
      signingKeyFile: "saml-key.pem",
      certificateFile: "saml.pem",
    };
    writeFileSync(configFile, JSON.stringify(configuration), { mode: 0o600 });
    writeFileSync(path.join(installation, "saml-key.pem"), idpKeys.key, {
      mode: 0o600,
    });
    writeFileSync(path.join(installation, "saml.pem"), idpKeys.cert, {
      mode: 0o600,
    });
    cli("database", "init");
    const organization = JSON.parse(
      cli("organization", "create", "--name", "Synthetic SAML organization"),
    );
    const member = JSON.parse(
      cli(
        "member",
        "create",
        "--organization",
        organization.id,
        "--name",
        "Synthetic SAML member",
      ),
    );
    const password = cli(
      "member",
      "set-password",
      "--organization",
      organization.id,
      "--member",
      member.id,
      "--username",
      "saml-fixture",
    );
    const oidcSecret = randomBytes(32).toString("hex");
    if (upgradeBaseline) {
      writeFileSync(
        path.join(installation, configuration.clientsFile),
        JSON.stringify([
          {
            client_id: "upgrade-client",
            secret_sha256: createHash("sha256")
              .update(oidcSecret)
              .digest("hex"),
            redirect_uris: [`${spOrigin}/oidc-callback`],
            subjectKind: "member",
            organizationId: organization.id,
            refresh: true,
          },
        ]),
        { mode: 0o600 },
      );
      const administrator = JSON.parse(
        cli(
          "member",
          "create",
          "--organization",
          organization.id,
          "--name",
          "Synthetic upgrade administrator",
        ),
      );
      cli(
        "member",
        "set-password",
        "--organization",
        organization.id,
        "--member",
        administrator.id,
        "--username",
        "upgrade-admin",
      );
      cli(
        "administrator",
        "grant",
        "--organization",
        organization.id,
        "--member",
        administrator.id,
      );
    }
    const spFile = path.join(directory, "registration.json");
    writeFileSync(
      spFile,
      JSON.stringify({
        id: "independent-sp",
        organizationId: organization.id,
        entityId: `${spOrigin}/metadata`,
        acsUrl: acs,
        enabled: true,
        signingCertificates: [spKeys.cert],
      }),
    );
    cli("saml", "sp", "apply", "--directory", installation, "--file", spFile);
    const probe = net.createServer();
    await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
    upstreamPort = probe.address().port;
    await new Promise((resolve) => probe.close(resolve));
    const browser = client(tls.cert);
    async function startProvider() {
      processHandle = spawn(
        executable,
        [
          "serve",
          "--directory",
          installation,
          "--listen",
          `127.0.0.1:${upstreamPort}`,
        ],
        { env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] },
      );
      processHandle.stdout.on("data", (chunk) => {
        logs += chunk;
      });
      processHandle.stderr.on("data", (chunk) => {
        logs += chunk;
      });
      for (let i = 0; i < 60; i++) {
        if ((await browser(`${issuer}/saml/metadata`)).status === 200) return;
        if (processHandle.exitCode !== null) break;
        await sleep(200);
      }
      assert.fail("packaged MemberID startup");
    }
    async function stopProvider() {
      const exited = once(processHandle, "exit");
      processHandle.kill();
      await exited;
      processHandle = undefined;
      assert.equal((await browser(`${issuer}/saml/metadata`)).status, 503);
    }
    await startProvider();

    async function responseForm() {
      const start = await browser(`${spOrigin}/login`);
      assert.equal(start.status, 302);
      const request = await browser(start.headers.location);
      assert.equal(request.status, 303, "signed Node-SAML request admission");
      let page = await browser(new URL(request.headers.location, issuer));
      assert.equal(page.status, 200);
      const submit = (action, extra) =>
        browser(`${issuer}/login`, {
          request: hidden(page.body, "request"),
          csrf: hidden(page.body, "csrf"),
          action,
          ...extra,
        });
      if (page.body.includes('name="password"')) {
        page = await submit("password", { username: "saml-fixture", password });
        assert.equal(page.status, 200, "password authentication");
      }
      const result = await submit("continue", {
        member: member.id,
        consent: "yes",
      });
      assert.equal(result.status, 200, "SAML issuance");
      assert.ok(result.headers["content-security-policy"].includes(spOrigin));
      assert.ok(
        !result.headers["content-security-policy"].includes(
          "opaque.example.test",
        ),
      );
      const form = {
        SAMLResponse: hidden(result.body, "SAMLResponse"),
        RelayState: hidden(result.body, "RelayState"),
      };
      assert.equal(form.RelayState, "https://opaque.example.test/return");
      return form;
    }

    await t.test(
      "login creates a consumer session and rejects repeated assertions",
      async () => {
        const form = await responseForm();
        assert.equal((await browser(acs, form)).status, 303);
        const session = await browser(`${spOrigin}/session`);
        assert.equal(session.status, 200);
        const profile = JSON.parse(session.body);
        assert.ok(profile.nameID && profile.inResponseTo);
        assert.equal(
          (await client(tls.cert)(acs, form)).status,
          400,
          "SP rejected ordinary replay",
        );
        // Restore only the request-cache entry to isolate assertion-ID replay
        // protection from request consumption. The assertion cache remains intact.
        await consumer.saml.cacheProvider.saveAsync(
          profile.inResponseTo,
          new Date().toISOString(),
        );
        assert.equal(
          (await client(tls.cert)(acs, form)).status,
          400,
          "SP rejected assertion replay even with a pending request",
        );
        assert.match(
          lastFailure,
          /replay|already.*(used|consumed)|already been/i,
        );
        assert.ok(
          !logs.includes(form.SAMLResponse) &&
            !logs.includes(profile.nameID) &&
            !logs.includes(password),
          "credentials and assertions absent from logs",
        );
      },
    );
    await t.test(
      "managed email requires release permission and retains the subject",
      async () => {
        const emailArgs = [
          "--organization",
          organization.id,
          "--member",
          member.id,
        ];
        const setEmail = (address, revision) =>
          JSON.parse(
            cli(
              "member",
              "email",
              "set",
              ...emailArgs,
              "--address",
              address,
              "--revision",
              String(revision),
            ),
          );
        const missing = JSON.parse(
          cli("member", "email", "inspect", ...emailArgs),
        );
        assert.equal(missing.address, "");
        assert.equal(missing.mailboxVerified, false);
        const saved = setEmail("managed@example.test", 0);
        assert.equal(saved.source, "administrator");
        assert.equal(saved.updatedBy, "installation-operator");
        assert.equal(saved.mailboxVerified, false);
        const session = async () => {
          assert.equal((await browser(acs, await responseForm())).status, 303);
          return JSON.parse((await browser(`${spOrigin}/session`)).body);
        };
        const before = await session();
        assert.equal(before.email, undefined, "unapproved email was omitted");
        const registration = JSON.parse(
          cli(
            "saml",
            "sp",
            "inspect",
            "--directory",
            installation,
            "--id",
            "independent-sp",
          ),
        );
        registration.attributes = ["Email"];
        writeFileSync(spFile, JSON.stringify(registration));
        cli(
          "saml",
          "sp",
          "apply",
          "--directory",
          installation,
          "--file",
          spFile,
        );
        const released = await session();
        assert.equal(released.email, "managed@example.test");
        assert.equal(released.nameID, before.nameID);
        setEmail("changed@example.test", 1);
        const changed = await session();
        assert.equal(changed.email, "changed@example.test");
        assert.equal(changed.nameID, before.nameID);
        setEmail("", 2);
        const cleared = await session();
        assert.equal(
          cleared.email,
          undefined,
          "missing email was not synthesized",
        );
        assert.equal(cleared.nameID, before.nameID);
      },
    );
    await t.test(
      "legacy NameID opens the existing account before and after restart",
      async () => {
        const legacyID = "old-account-42";
        const account = {
          id: "existing-account-7",
          savedWork: "retained business data",
        };
        existingAccounts = new Map([[legacyID, account]]);
        const file = path.join(directory, "legacy-sp.json");
        writeFileSync(
          file,
          JSON.stringify({
            id: "legacy-sp",
            organizationId: organization.id,
            entityId: `${spOrigin}/legacy-metadata`,
            acsUrl: acs,
            nameIdFormat: "unspecified",
            enabled: true,
            signingCertificates: [spKeys.cert],
          }),
        );
        const registration = JSON.parse(
          cli(
            "saml",
            "sp",
            "apply",
            "--directory",
            installation,
            "--file",
            file,
          ),
        );
        const args = [
          "--directory",
          installation,
          "--organization",
          organization.id,
          "--sp",
          "legacy-sp",
          "--member",
          member.id,
        ];
        const mapping = JSON.parse(
          cli(
            "saml",
            "nameid",
            "provision",
            ...args,
            "--value",
            legacyID,
            "--revision",
            String(registration.revision),
          ),
        );
        assert.equal(mapping.source, "legacy");
        const identifierFormat =
          "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
        consumer = createConsumer({
          ...consumerOptions,
          issuer: `${spOrigin}/legacy-metadata`,
          identifierFormat,
        });
        try {
          for (const restart of [false, true]) {
            if (restart) {
              await stopProvider();
              await startProvider();
            }
            assert.equal(
              (await browser(acs, await responseForm())).status,
              303,
            );
            const result = await browser(`${spOrigin}/session`);
            assert.equal(result.status, 200);
            const profile = JSON.parse(result.body);
            assert.equal(profile.nameID, legacyID);
            assert.equal(profile.nameIDFormat, identifierFormat);
            assert.equal(profile.accountId, account.id);
            assert.equal(existingAccounts.size, 1);
            assert.equal(
              existingAccounts.get(legacyID).savedWork,
              "retained business data",
            );
            assert.deepEqual(
              JSON.parse(cli("saml", "nameid", "inspect", ...args)),
              mapping,
            );
          }
        } finally {
          existingAccounts = undefined;
          consumer = createConsumer(consumerOptions);
        }
      },
    );
    await t.test(
      "concurrent responses create only one SP session",
      async () => {
        const form = await responseForm();
        const results = await Promise.all([
          client(tls.cert)(acs, form),
          client(tls.cert)(acs, form),
        ]);
        assert.deepEqual(results.map((r) => r.status).sort(), [303, 400]);
      },
    );

    const changes = {
      audience: [
        (d, s) => {
          s(
            "/p:Response/a:Assertion/a:Conditions/a:AudienceRestriction/a:Audience",
            d,
          )[0].textContent = "https://other.example.test";
        },
        /audience/i,
      ],
      recipient: [
        (d, s) => {
          s(
            "/p:Response/a:Assertion/a:Subject/a:SubjectConfirmation/a:SubjectConfirmationData",
            d,
          )[0].setAttribute("Recipient", `${acs}/other`);
        },
        /Recipient/,
      ],
      destination: [
        (d) => {
          d.documentElement.setAttribute("Destination", `${acs}/other`);
        },
        /Destination/,
      ],
      correlation: [
        (d) => {
          d.documentElement.setAttribute("InResponseTo", "_unknown");
        },
        /InResponseTo/,
      ],
      "subject correlation": [
        (d, s) => {
          s(
            "/p:Response/a:Assertion/a:Subject/a:SubjectConfirmation/a:SubjectConfirmationData",
            d,
          )[0].setAttribute("InResponseTo", "_other");
        },
        /InResponseTo/,
      ],
      expired: [
        (d, s) => {
          s("/p:Response/a:Assertion/a:Conditions", d)[0].setAttribute(
            "NotOnOrAfter",
            new Date(Date.now() - 300_000).toISOString(),
          );
        },
        /expired/i,
      ],
      future: [
        (d, s) => {
          s("/p:Response/a:Assertion/a:Conditions", d)[0].setAttribute(
            "NotBefore",
            new Date(Date.now() + 300_000).toISOString(),
          );
        },
        /not yet valid/i,
      ],
      "expired confirmation": [
        (d, s) => {
          s(
            "/p:Response/a:Assertion/a:Subject/a:SubjectConfirmation/a:SubjectConfirmationData",
            d,
          )[0].setAttribute(
            "NotOnOrAfter",
            new Date(Date.now() - 300_000).toISOString(),
          );
        },
        /expired|confirmation/i,
      ],
      issuer: [
        (d, s) => {
          s("/p:Response/a:Assertion/a:Issuer", d)[0].textContent =
            "https://unknown.example.test";
        },
        /issuer/i,
      ],
    };
    for (const [name, [change, message]] of Object.entries(changes)) {
      await t.test(
        `consumer rejects correctly signed ${name} violation`,
        async () => {
          const form = await responseForm();
          form.SAMLResponse = alterAndSign(
            form.SAMLResponse,
            change,
            idpKeys.key,
            idpKeys.cert,
          );
          assert.equal((await browser(acs, form)).status, 400);
          assert.match(
            lastFailure,
            message,
            "rejection must identify the constraint, not a broken test signature",
          );
          assert.equal((await browser(`${spOrigin}/session`)).status, 401);
        },
      );
    }
    await t.test("consumer rejects signature tampering", async () => {
      const form = await responseForm();
      const xml = Buffer.from(form.SAMLResponse, "base64").toString("utf8");
      form.SAMLResponse = Buffer.from(
        xml.replace(acs, `${acs}/tampered`),
      ).toString("base64");
      assert.equal((await browser(acs, form)).status, 400);
      assert.match(lastFailure, /signature/i);
      assert.equal((await browser(`${spOrigin}/session`)).status, 401);
    });
    await t.test(
      "supported baseline upgrades with stable identities and recovers with the old executable",
      { skip: !upgradeBaseline },
      async () => {
        const oldExecutable = executable;
        const pg = (sql) =>
          command("docker", [
            "exec",
            database,
            "psql",
            "--username",
            "postgres",
            "--dbname",
            "postgres",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",
            "--command",
            sql,
          ]);
        const snapshot = () =>
          Object.fromEntries(
            pg(
              "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename NOT IN ('memberid_schema','database_upgrades','feishu_memberships') ORDER BY tablename",
            )
              .split(/\r?\n/)
              .map((name) => {
                assert.match(name, /^[a-z_]+$/);
                return [
                  name,
                  pg(
                    `SELECT md5(coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text) FROM public.${name} t`,
                  ),
                ];
              }),
          );
        const sourceSchemaVersion = Number(
          pg("SELECT version FROM memberid_schema"),
        );
        assert.ok([26, 27].includes(sourceSchemaVersion));
        const previousUpgrades =
          sourceSchemaVersion === 26
            ? 0
            : Number(pg("SELECT count(*) FROM database_upgrades"));
        assert.equal((await browser(acs, await responseForm())).status, 303);
        const originalNameID = JSON.parse(
          (await browser(`${spOrigin}/session`)).body,
        ).nameID;
        const verifier = randomBytes(32).toString("base64url");
        const discovery = JSON.parse(
          (await browser(`${issuer}/.well-known/openid-configuration`)).body,
        );
        const authorization = new URL(discovery.authorization_endpoint);
        authorization.search = new URLSearchParams({
          client_id: "upgrade-client",
          redirect_uri: `${spOrigin}/oidc-callback`,
          response_type: "code",
          scope: "openid profile offline_access",
          state: "upgrade-state",
          nonce: "upgrade-nonce",
          code_challenge_method: "S256",
          code_challenge: createHash("sha256")
            .update(verifier)
            .digest("base64url"),
        }).toString();
        const start = await browser(authorization);
        const page = await browser(new URL(start.headers.location, issuer));
        const completed = await browser(`${issuer}/login`, {
          request: hidden(page.body, "request"),
          csrf: hidden(page.body, "csrf"),
          action: "continue",
          member: member.id,
          consent: "yes",
        });
        const redirected = await browser(
          new URL(completed.headers.location, issuer),
        );
        const callback = new URL(redirected.headers.location, issuer);
        assert.equal(callback.searchParams.get("state"), "upgrade-state");
        const authHeader = {
          Authorization: `Basic ${Buffer.from(`upgrade-client:${oidcSecret}`).toString("base64")}`,
        };
        const exchanged = await browser(
          discovery.token_endpoint,
          {
            grant_type: "authorization_code",
            code: callback.searchParams.get("code"),
            redirect_uri: `${spOrigin}/oidc-callback`,
            code_verifier: verifier,
          },
          authHeader,
        );
        assert.equal(exchanged.status, 200);
        const tokens = JSON.parse(exchanged.body);
        assert.ok(tokens.refresh_token);
        const claims = JSON.parse(
          Buffer.from(tokens.id_token.split(".")[1], "base64url").toString(),
        );
        assert.equal(claims.sub, member.id);
        await stopProvider();
        const before = snapshot();
        const pgDump = path.join(
          directory,
          process.platform === "win32" ? "pgdump.exe" : "pgdump",
        );
        command("go", [
          "build",
          "-o",
          pgDump,
          path.join(root, "internal", "interop", "saml", "pgdump"),
        ]);
        env.MEMBERID_TEST_PGDUMP_CONTAINER = database;
        executable = upgradedExecutable;
        const recovery = path.join(directory, "upgrade-recovery");
        const upgradeArgs = [
          "database",
          "upgrade",
          "--directory",
          installation,
          "--backup-directory",
          recovery,
          "--maintenance-confirmed",
          "--pg-dump",
          pgDump,
        ];
        const upgraded = JSON.parse(cli(...upgradeArgs));
        assert.equal(upgraded.upgraded, true);
        assert.equal(upgraded.currentVersion, 28);
        t.diagnostic("upgrade rehearsal: schema 28 committed");
        assert.deepEqual(snapshot(), before);
        assert.equal(JSON.parse(cli(...upgradeArgs)).upgraded, false);
        assert.equal(
          Number(pg("SELECT count(*) FROM database_upgrades")),
          previousUpgrades + 28 - sourceSchemaVersion,
        );
        cli("database", "backup-check", "--backup-directory", recovery);
        assert.throws(() => command(oldExecutable, ["database", "check"], env));
        await startProvider();
        const refreshed = await browser(
          discovery.token_endpoint,
          { grant_type: "refresh_token", refresh_token: tokens.refresh_token },
          authHeader,
        );
        assert.equal(refreshed.status, 200);
        const renewed = JSON.parse(
          Buffer.from(
            JSON.parse(refreshed.body).id_token.split(".")[1],
            "base64url",
          ).toString(),
        );
        assert.equal(renewed.sub, claims.sub);
        assert.equal(renewed.auth_time, claims.auth_time);
        t.diagnostic("upgrade rehearsal: original OIDC grant refreshed");
        assert.equal((await browser(acs, await responseForm())).status, 303);
        assert.equal(
          JSON.parse((await browser(`${spOrigin}/session`)).body).nameID,
          originalNameID,
        );
        await stopProvider();
        // Rehearse a failed deployment: restore the pre-upgrade set to a new DB
        // and directory; retain the upgraded database without reverse migration.
        command("docker", [
          "exec",
          database,
          "createdb",
          "--username",
          "postgres",
          "recovered26",
        ]);
        command("docker", [
          "cp",
          path.join(recovery, "database.dump"),
          `${database}:/tmp/upgrade-recovery.dump`,
        ]);
        command("docker", [
          "exec",
          database,
          "pg_restore",
          "--username",
          "postgres",
          "--dbname",
          "recovered26",
          "--no-owner",
          "--no-acl",
          "--exit-on-error",
          "--single-transaction",
          "/tmp/upgrade-recovery.dump",
        ]);
        command("docker", [
          "cp",
          path.join(root, "docs", "recovery-sessions.sql"),
          `${database}:/tmp/recovery-sessions.sql`,
        ]);
        command("docker", [
          "exec",
          database,
          "psql",
          "--username",
          "postgres",
          "--dbname",
          "recovered26",
          "--set",
          "ON_ERROR_STOP=1",
          "--file",
          "/tmp/recovery-sessions.sql",
        ]);
        installation = path.join(directory, "recovered26-installation");
        cpSync(path.join(recovery, "installation"), installation, {
          recursive: true,
          errorOnExist: true,
          force: false,
        });
        const oldURL = env.MEMBERID_DATABASE_URL;
        env.MEMBERID_DATABASE_URL = oldURL.replace(
          "/postgres?",
          "/recovered26?",
        );
        executable = oldExecutable;
        cli("database", "check");
        await startProvider();
        t.diagnostic("upgrade rehearsal: recovered source schema started");
        assert.equal(
          (
            await browser(
              discovery.token_endpoint,
              {
                grant_type: "refresh_token",
                refresh_token: tokens.refresh_token,
              },
              authHeader,
            )
          ).status,
          400,
        );
        assert.equal((await browser(acs, await responseForm())).status, 303);
        assert.equal(
          JSON.parse((await browser(`${spOrigin}/session`)).body).nameID,
          originalNameID,
        );
        await stopProvider();
        // Return to the preserved upgraded installation for remaining checks.
        installation = path.join(directory, "installation");
        env.MEMBERID_DATABASE_URL = oldURL;
        executable = upgradedExecutable;
        await startProvider();
      },
    );
    await t.test(
      "signing rollover, rollback and consistent backup restore preserve the SP account",
      async () => {
        const old = JSON.parse(
          cli("saml", "signing", "inspect", "--directory", installation),
        );
        assert.equal(old.status, "expiring");
        const jwks = JSON.parse(
          (await browser(`${issuer}/.well-known/jwks.json`)).body,
        );
        const login = async () => {
          assert.equal((await browser(acs, await responseForm())).status, 303);
          const session = await browser(`${spOrigin}/session`);
          assert.equal(session.status, 200);
          return JSON.parse(session.body).nameID;
        };
        const nameID = await login();

        // Quiesce the IdP and back up its database and protected files together.
        await stopProvider();
        const backup = path.join(directory, "protected-backup");
        cpSync(installation, backup, {
          recursive: true,
          errorOnExist: true,
          force: false,
        });
        command("docker", [
          "exec",
          database,
          "pg_dump",
          "--username",
          "postgres",
          "--format=custom",
          "--file=/tmp/saml-backup.dump",
          "postgres",
        ]);
        await startProvider();

        const next = certificate("next-idp");
        writeFileSync(path.join(installation, "next-key.pem"), next.key, {
          mode: 0o600,
        });
        writeFileSync(path.join(installation, "next.pem"), next.cert, {
          mode: 0o600,
        });
        const signing = (operation, ...args) =>
          cli(
            "saml",
            "signing",
            operation,
            "--directory",
            installation,
            ...args,
          );
        const candidateFlags = [
          "--key-file",
          "next-key.pem",
          "--certificate-file",
          "next.pem",
        ];
        const candidate = JSON.parse(signing("inspect", ...candidateFlags));
        const publicCertificate = signing(
          "export-certificate",
          ...candidateFlags,
        );
        assert.equal(
          new X509Certificate(publicCertificate).fingerprint256
            .replaceAll(":", "")
            .toLowerCase(),
          candidate.sha256,
        );
        assert.ok(!publicCertificate.includes("PRIVATE"));
        const fingerprint = async () => {
          const response = await browser(`${issuer}/saml/metadata`);
          assert.equal(response.status, 200);
          const certs = parse(response.body).getElementsByTagNameNS(
            "http://www.w3.org/2000/09/xmldsig#",
            "X509Certificate",
          );
          assert.equal(
            certs.length,
            1,
            "metadata publishes only the running signer",
          );
          return createHash("sha256")
            .update(Buffer.from(certs[0].textContent, "base64"))
            .digest("hex");
        };
        assert.equal(await fingerprint(), old.sha256);
        const originalConfiguration = readFileSync(configFile);
        assert.throws(() =>
          signing(
            "activate",
            "--key-file",
            "saml-key.pem",
            "--certificate-file",
            "next.pem",
            "--expected-sha256",
            old.sha256,
            "--backup-file",
            "rejected.json",
          ),
        );
        assert.ok(
          readFileSync(configFile).equals(originalConfiguration),
          "invalid candidate preserves configuration",
        );

        // Trust both public certificates before changing the configured signer.
        consumer = createConsumer({
          ...consumerOptions,
          idpCert: [idpKeys.cert, publicCertificate],
        });
        const pendingOld = await responseForm();
        const activated = JSON.parse(
          signing(
            "activate",
            ...candidateFlags,
            "--expected-sha256",
            old.sha256,
            "--backup-file",
            "before-rotation.json",
          ),
        );
        assert.equal(activated.restartRequired, true);
        assert.equal(activated.sha256, candidate.sha256);
        assert.equal(
          await fingerprint(),
          old.sha256,
          "file activation does not silently reload the running process",
        );
        const restart = async () => {
          const started = performance.now();
          await stopProvider();
          await startProvider();
          const elapsed = Math.ceil(performance.now() - started);
          assert.ok(
            elapsed < 30_000,
            "restart outage exceeds the fixture bound",
          );
          t.diagnostic(`signing restart outage: ${elapsed} ms`);
        };
        await restart();
        assert.equal(await fingerprint(), candidate.sha256);
        assert.equal(
          (await browser(acs, pendingOld)).status,
          303,
          "overlap accepts the old in-flight response after restart",
        );
        assert.equal(await login(), nameID);
        assert.deepEqual(
          JSON.parse((await browser(`${issuer}/.well-known/jwks.json`)).body),
          jwks,
        );

        // Rehearse a missed SP trust update and recover using the retained signer.
        consumer = createConsumer(consumerOptions);
        assert.equal((await browser(acs, await responseForm())).status, 400);
        assert.match(lastFailure, /signature/i);
        assert.equal((await browser(`${spOrigin}/session`)).status, 401);
        signing(
          "activate",
          "--key-file",
          "saml-key.pem",
          "--certificate-file",
          "saml.pem",
          "--expected-sha256",
          candidate.sha256,
          "--backup-file",
          "before-rollback.json",
        );
        await restart();
        assert.equal(await fingerprint(), old.sha256);
        assert.equal(await login(), nameID);

        signing(
          "activate",
          ...candidateFlags,
          "--expected-sha256",
          old.sha256,
          "--backup-file",
          "before-second-rotation.json",
        );
        consumer = createConsumer({
          ...consumerOptions,
          idpCert: publicCertificate,
        });
        await restart();
        assert.equal(await login(), nameID);
        const retired = await responseForm();
        retired.SAMLResponse = alterAndSign(
          retired.SAMLResponse,
          () => {},
          idpKeys.key,
          idpKeys.cert,
        );
        assert.equal(
          (await browser(acs, retired)).status,
          400,
          "retired signing key is no longer trusted",
        );
        assert.match(lastFailure, /signature/i);

        // Restore into a new owned database and directory; never overwrite the
        // current database or discard the installation being recovered from.
        await stopProvider();
        command("docker", [
          "exec",
          database,
          "createdb",
          "--username",
          "postgres",
          "restored",
        ]);
        command("docker", [
          "exec",
          database,
          "pg_restore",
          "--username",
          "postgres",
          "--exit-on-error",
          "--dbname",
          "restored",
          "/tmp/saml-backup.dump",
        ]);
        installation = path.join(directory, "restored-installation");
        cpSync(backup, installation, {
          recursive: true,
          errorOnExist: true,
          force: false,
        });
        env.MEMBERID_DATABASE_URL = `postgres://postgres@127.0.0.1:${databasePort}/restored?sslmode=disable`;
        consumer = createConsumer(consumerOptions);
        await startProvider();
        assert.equal(await fingerprint(), old.sha256);
        assert.equal(
          await login(),
          nameID,
          "consistent restore preserves the established SP account",
        );
        assert.deepEqual(
          JSON.parse((await browser(`${issuer}/.well-known/jwks.json`)).body),
          jwks,
        );
        assert.ok(
          !logs.includes("PRIVATE KEY") &&
            !logs.includes(next.key.trim()) &&
            !logs.includes(idpKeys.key.trim()),
          "signing private material absent from logs",
        );
      },
    );
    await t.test(
      "Member blocking stops pending issuance but preserves an existing SP session",
      async () => {
        const accepted = await responseForm();
        assert.equal((await browser(acs, accepted)).status, 303);
        const existing = await browser(`${spOrigin}/session`);
        assert.equal(existing.status, 200);

        // Start another IdP transaction using the authenticated browser, without
        // replacing its existing downstream application session.
        const start = await browser(
          await consumer.saml.getAuthorizeUrlAsync(
            "https://opaque.example.test/return",
          ),
        );
        assert.equal(start.status, 303);
        const page = await browser(new URL(start.headers.location, issuer));
        assert.equal(page.status, 200);
        assert.ok(
          page.body.includes(`value="${member.id}"`),
          "shared SSO offers the established Member",
        );
        cli(
          "member",
          "block",
          "--organization",
          organization.id,
          "--member",
          member.id,
        );
        const denied = await browser(`${issuer}/login`, {
          request: hidden(page.body, "request"),
          csrf: hidden(page.body, "csrf"),
          action: "continue",
          member: member.id,
          consent: "yes",
        });
        assert.equal(denied.status, 200);
        assert.ok(
          denied.body.includes("No eligible Member identity is available"),
          "the pending login must report the Member's ineligibility",
        );
        assert.ok(
          !denied.body.includes('name="SAMLResponse"'),
          "blocked Member must not receive an assertion",
        );
        const retained = await browser(`${spOrigin}/session`);
        assert.equal(retained.status, 200);
        assert.equal(
          JSON.parse(retained.body).nameID,
          JSON.parse(existing.body).nameID,
        );
      },
    );
    t.diagnostic(
      `Node-SAML 5.2.0; ${build.split("\n")[0]}; packaged binary SHA-256 ${digest}; HTTPS port ${new URL(issuer).port}`,
    );
  },
);
