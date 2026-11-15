const password = document.getElementById("generated-password")
const copy = document.getElementById("copy-password")
const notice = document.getElementById("save-note")

if (navigator.clipboard) {
  copy.hidden = false
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(password.value)
      notice.textContent = "已复制。请将密码保存到密码管理器。"
    } catch {
      password.select()
      notice.textContent = "请手动复制选中的密码。"
    }
  })
}

window.addEventListener("pagehide", () => {
  password.value = ""
  password.removeAttribute("value")
})
window.addEventListener("pageshow", (event) => {
  if (event.persisted) location.replace("/setup")
})
