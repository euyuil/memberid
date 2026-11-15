import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import {
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
  return async (target, form) => {
    const url = new URL(target);
    const jar = cookies.get(url.host) ?? new Map();
    const data = form ? new URLSearchParams(form).toString() : undefined;
    return new Promise((resolve, reject) => {
      const request = https.request(
        url,
        {
          ca,
          lookup: (_host, options, callback) =>
            options.all
              ? callback(null, [{ address: "127.0.0.1", family: 4 }])
              : callback(null, "127.0.0.1", 4),
          method: data ? "POST" : "GET",
          headers: {
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
    const executable = path.join(distribution, binaryName);
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
      if (processHandle && processHandle.exitCode === null) {
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
    consumer = createConsumer({
      issuer: `${spOrigin}/metadata`,
      callbackUrl: acs,
      entryPoint: `${issuer}/saml/sso`,
      idpCert: idpKeys.cert,
      idpIssuer: `${issuer}/saml/metadata`,
      privateKey: spKeys.key,
    });
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
    const installation = path.join(directory, "installation");
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
    const browser = client(tls.cert);
    ready = false;
    for (let i = 0; i < 60; i++) {
      if ((await browser(`${issuer}/saml/metadata`)).status === 200) {
        ready = true;
        break;
      }
      await sleep(200);
    }
    assert.ok(ready, "packaged MemberID startup");

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
