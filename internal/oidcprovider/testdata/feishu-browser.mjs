import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const fixture = JSON.parse(Buffer.concat(chunks));
const child = spawn(
  fixture.browser,
  [
    "--headless=new",
    "--disable-gpu",
    "--no-first-run",
    "--disable-background-networking",
    "--remote-debugging-port=0",
    "--remote-debugging-address=127.0.0.1",
    "--user-data-dir=" + fixture.profile,
    "--host-resolver-rules=MAP accounts.feishu.cn 127.0.0.1,MAP session.example.invalid 127.0.0.1",
    "about:blank",
  ],
  { windowsHide: true, stdio: "ignore" },
);
const exited = once(child, "exit");
let socket;
try {
  let port;
  for (let i = 0; !port && i < 150; i++) {
    try {
      port = parseInt(
        await readFile(join(fixture.profile, "DevToolsActivePort"), "utf8"),
        10,
      );
    } catch {
      await sleep(100);
    }
  }
  assert.ok(port, "browser startup");
  const targets = await (
    await fetch("http://127.0.0.1:" + port + "/json/list")
  ).json();
  socket = new WebSocket(
    targets.find((t) => t.type === "page").webSocketDebuggerUrl,
  );
  await once(socket, "open");
  const pending = new Map();
  let sequence = 0,
    authorizations = 0,
    secondOrigin = 0,
    code;
  const second = "https://session.example.invalid/login";
  function send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = ++sequence;
      const timer = setTimeout(
        () => reject(Error("browser timeout: " + method)),
        10000,
      );
      pending.set(id, (result) => {
        clearTimeout(timer);
        if (result.error) reject(Error(result.error.message));
        else resolve(result.result);
      });
      socket.send(JSON.stringify({ id, method, params }));
    });
  }
  const callbackPath =
    fixture.flow === "link"
      ? "/account/feishu/callback"
      : "/auth/feishu/callback";
  let providerReturn;
  socket.onmessage = async (event) => {
    const msg = JSON.parse(event.data);
    if (msg.id) {
      pending.get(msg.id)?.(msg);
      pending.delete(msg.id);
    } else if (msg.method === "Fetch.requestPaused") {
      const { requestId, request } = msg.params;
      const address = new URL(request.url);
      const redirect = (location) =>
        send("Fetch.fulfillRequest", {
          requestId,
          responseCode: 302,
          responseHeaders: [{ name: "Location", value: location }],
        });
      if (address.origin === "https://accounts.feishu.cn") {
        assert.equal(
          address.searchParams.get("redirect_uri"),
          fixture.issuer + callbackPath,
        );
        assert.equal(address.searchParams.get("code_challenge_method"), "S256");
        providerReturn = new URL(fixture.issuer + callbackPath);
        providerReturn.searchParams.set(
          "state",
          address.searchParams.get("state"),
        );
        providerReturn.searchParams.set("code", "synthetic-code");
        authorizations++;
        await redirect(second);
      } else if (request.url === second) {
        secondOrigin++;
        if (secondOrigin === 1) {
          await send("Fetch.fulfillRequest", {
            requestId,
            responseCode: 200,
            body: Buffer.from("Synthetic sign-in").toString("base64"),
          });
        } else {
          await redirect(providerReturn.href);
        }
      } else {
        assert.equal(address.origin + address.pathname, fixture.callback);
        assert.equal(address.searchParams.get("state"), "example-state");
        code = address.searchParams.get("code");
        await send("Fetch.fulfillRequest", {
          requestId,
          responseCode: 200,
          body: Buffer.from("Signed in").toString("base64"),
        });
      }
    }
  };
  await send("Fetch.enable", {
    patterns: [
      {
        urlPattern: "https://accounts.feishu.cn/open-apis/authen/v1/authorize*",
      },
      { urlPattern: second },
      { urlPattern: fixture.callback + "?*" },
    ],
  });
  for (const cookie of fixture.cookies ?? []) {
    await send("Network.setCookie", {
      url: fixture.issuer,
      name: cookie.Name,
      value: cookie.Value,
      path: "/",
    });
  }
  async function evaluate(expression) {
    const result = await send("Runtime.evaluate", {
      expression,
      returnByValue: true,
    });
    return result.result.value;
  }
  async function wait(expression, description) {
    for (let i = 0; i < 150; i++) {
      if (await evaluate(expression)) return;
      await sleep(100);
    }
    throw Error(description);
  }
  const button = fixture.flow === "link" ? "link" : "feishu";
  const selector = "document.querySelector('button[value=\"" + button + "\"]')";
  await send("Page.navigate", {
    url: new URL(fixture.entry, fixture.issuer).href,
  });
  await wait(
    selector + " && !" + selector + ".disabled",
    "initial form unavailable",
  );
  await evaluate(selector + ".click()");
  await wait(
    'document.body?.textContent.includes("Synthetic sign-in")',
    "provider navigation incomplete",
  );
  await evaluate("history.back()");
  const cancel = "document.querySelector('button[value=\"cancel\"]:enabled')";
  await wait(
    cancel + ' || document.querySelector("#resume")',
    "pending interaction unavailable after Back",
  );
  if (await evaluate('!!document.querySelector("#resume")'))
    await evaluate('document.querySelector("#resume").click()');
  await wait(cancel, "pending interaction cannot be canceled");
  await evaluate(cancel + ".click()");
  await wait(
    selector + " && !" + selector + ".disabled",
    "canceled interaction cannot restart",
  );
  await evaluate(selector + ".click()");
  if (fixture.flow === "link") {
    await wait(
      'document.body?.textContent.includes("Feishu is linked to this Member")',
      "linking callback incomplete",
    );
  } else {
    await wait(
      'document.querySelector(\'button[value="continue"]\') && document.querySelector("#member")',
      "sign-in callback incomplete",
    );
    await evaluate(
      'document.querySelector("[name=consent]").checked=true;document.querySelector(\'button[value="continue"]\').click()',
    );
    await wait(
      'document.body?.textContent.includes("Signed in")',
      "relying party callback incomplete",
    );
    assert.ok(code);
    process.stdout.write(code);
  }
  assert.equal(authorizations, 2);
  assert.equal(secondOrigin, 2);
} finally {
  if (socket?.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ id: 999999, method: "Browser.close" }));
    socket.close();
  }
  if (child.exitCode === null && child.signalCode === null) {
    await Promise.race([exited, sleep(3000)]);
    if (child.exitCode === null && child.signalCode === null) child.kill();
  }
}
