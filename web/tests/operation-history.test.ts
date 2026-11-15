import assert from "node:assert/strict"
import { test } from "node:test"
import {
  describeEvent,
  type ManagementEvent,
} from "../src/operation-history.ts"

const event: ManagementEvent = {
  id: 1,
  actor: "mbr_admin",
  organizationId: "org_example",
  memberId: "mbr_example",
  action: "member.update",
  changes: {},
  createdAt: "2026-11-15T09:39:02Z",
  snapshot: {
    actorName: "陈予",
    organizationName: "星河团队",
    targetName: "林晓",
  },
}

test("history uses recorded names and stable entity links", () => {
  const view = describeEvent(event)
  assert.equal(view.actorName, "陈予")
  assert.equal(view.organizationName, "星河团队")
  assert.equal(view.targetName, "林晓")
  assert.equal(view.targetURL, "/organizations/org_example/members/mbr_example")
  assert.equal(
    describeEvent({ ...event, actor: "installation-operator" }).actorName,
    "安装运维"
  )
  assert.equal(
    describeEvent({ ...event, actor: "installation-manager" }).actorName,
    "集成管理服务"
  )
})

test("combined updates retain each actual difference and ignore unchanged fields", () => {
  const view = describeEvent({
    ...event,
    changes: { displayName: "林晓 · 产品组", manualBlocked: true },
    previous: { displayName: "林晓", manualBlocked: false },
  })
  assert.equal(view.action, "重命名、封禁")
  assert.deepEqual(view.changes, ["林晓 → 林晓 · 产品组", "未封禁 → 封禁"])
  const unblock = describeEvent({
    ...event,
    changes: { displayName: "林晓", manualBlocked: false },
    previous: { displayName: "林晓", manualBlocked: true },
  })
  assert.equal(unblock.action, "解除封禁")
  // Removing the manual block does not establish eligibility or remove external blocks.
  assert.deepEqual(unblock.changes, ["封禁 → 未封禁"])
  assert.deepEqual(
    describeEvent({
      ...event,
      changes: { manualBlocked: false },
      previous: { manualBlocked: false },
    }).changes,
    []
  )
})

test("creation and incomplete historical records do not invent old values", () => {
  const creation = describeEvent({
    ...event,
    action: "member.create",
    changes: { displayName: "林晓" },
  })
  assert.equal(creation.action, "创建成员")
  assert.deepEqual(creation.changes, [])
  const legacy = describeEvent({
    ...event,
    snapshot: undefined,
    changes: { displayName: "旧记录中的姓名", manualBlocked: false },
  })
  assert.equal(legacy.actorName, "姓名未记录")
  assert.equal(legacy.targetName, "旧记录中的姓名")
  assert.deepEqual(legacy.changes, ["旧记录中的姓名", "未封禁"])
  assert.equal(
    describeEvent({ ...event, snapshot: undefined }).targetName,
    "名称未记录"
  )
})

test("provider changes identify the application and separate status from credentials", () => {
  const provider = {
    ...event,
    memberId: "",
    action: "provider.configure",
    changes: {
      providerId: "source_1",
      created: false,
      displayName: "员工登录",
      enabled: true,
      credentialsUpdated: false,
      authorizationStatus: "active",
    },
    previous: {
      displayName: "员工登录",
      enabled: false,
      authorizationStatus: "active",
    },
  }
  const view = describeEvent(provider)
  assert.equal(view.action, "启用登录")
  assert.deepEqual(view.changes, ["停用 → 启用"])
  assert.equal(
    view.targetURL,
    "/organizations/org_example/providers?providerId=source_1"
  )
  const rotation = describeEvent({
    ...provider,
    changes: { ...provider.changes, credentialsUpdated: true },
    previous: { ...provider.previous, enabled: true },
  })
  assert.equal(rotation.action, "更新凭据")
  assert.deepEqual(rotation.changes, ["凭据已更新"])
  const creation = describeEvent({
    ...provider,
    changes: { ...provider.changes, created: true },
    previous: {},
  })
  assert.equal(creation.action, "添加登录")
  assert.deepEqual(creation.changes, ["启用"])
})

test("organization and assignment changes use specific actions", () => {
  for (const [action, changes, previous, label, difference] of [
    [
      "organization.update",
      { status: "disabled" },
      { status: "enabled" },
      "停用组织",
      "启用 → 停用",
    ],
    [
      "administrator.update",
      { enabled: true },
      { enabled: false },
      "授予管理员",
      "普通成员 → 管理员",
    ],
    [
      "dingtalk.admission",
      { enabled: false },
      { enabled: true },
      "取消钉钉准入",
      "已设置 → 未设置",
    ],
  ] as const) {
    const view = describeEvent({ ...event, action, changes, previous })
    assert.equal(view.action, label)
    assert.deepEqual(view.changes, [difference])
  }
})
