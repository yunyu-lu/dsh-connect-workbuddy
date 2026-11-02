# dsh-connect-workbuddy Windows ACL 加固缺陷（3 条）：OWNER RIGHTS 假设 owner=当前用户，非自有目录把用户完全锁死

## 环境

| | |
|---|---|
| DSH 桌面版 | `0.2.1-rc.5` |
| `dsh-connect-workbuddy` | `5.18.0`（tag `v5.18.0`，SHA-256 与作者基准 6/6 一致）；引入提交 `d5183b2`（2026-10-31，`fix(#183)`），自 5.16.0 起随 npm 分发 |
| 系统 | Windows 11，账户 `luyuyu`（**非管理员日常令牌**） |
| 区域 | `cn` |

## 现象（一句话）

vault 目录 owner 是 `BUILTIN\Administrators` 时，`DIRECTORY_GRANTS` 里的 `*S-1-3-4`（OWNER RIGHTS）授予的是 **Administrators** 而非当前用户，叠加 `applyAcl` 的 `/inheritance:r` 删光继承 ACE 后，当前用户对 `~/.dsh/workbuddy-vault` **一分权限都没有**——stat/readdir/mkdir/write/rename 全部 EPERM。账号池卡片报「已保存的账号在本机已不存在」，用户被迫 takeown 才能恢复。

## 复现路径

1. `~/.dsh/workbuddy-vault`（或任一上层目录）在插件之外被提权进程创建/接管过 → owner = `BUILTIN\Administrators`。本机该目录创建于 10/27 04:14，早于加固代码存在的时间（10-31 随 5.16.0 发布）——当时 DSH 以提权令牌运行（本机存在 `RunLevel=Highest` 的免 UAC 启动任务），目录遂归 Administrators 所有。对照组：`global` 目录 owner=luyuyu，同版本同 ACL 却一切正常——这是决定性差异。
2. 插件 5.18.0 启动，`writeVaultEntry` → `protectCredentialDirectory(dirname(dir))` 对 vault root 执行加固。
3. `applyAcl` 跑 `icacls <dir> /inheritance:r /grant:r *S-1-3-4:(OI)(CI)(F) *S-1-5-18:... *S-1-5-32-544:...`。
4. 结果 DACL = `OWNER RIGHTS→Administrators` + SYSTEM + Administrators；owner 是 Administrators，所以 OWNER RIGHTS 命中它；当前用户既非 owner 也非管理员 → **全拒**。
5. UI 表现：账号池只剩桌面端扫描到的 1 个账号，钉住的那个账号显示「已保存的账号在本机已不存在」（`row.selectionLostHint`，`src/client/locales.ts:760`，渲染门控 `src/client/WorkBuddyCard.tsx:2299/3153`）。

修复前的 SDDL（脱敏后）：

```
O:BAG:...D:PAI(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)
```

`OW` = OWNER RIGHTS 命中的是 owner（Administrators），`D:PAI` = 继承已关。`luyuyu` 完全不在 ACL 里。

## 三个缺陷

### 缺陷 1（主因）：`DIRECTORY_GRANTS` 假设 owner == 当前用户

`src/windows-acl.ts:101`：

```ts
const DIRECTORY_GRANTS: readonly string[] = [
  `*${OWNER_RIGHTS_SID}:(OI)(CI)(F)`,   // S-1-3-4
  `*${SYSTEM_SID}:(OI)(CI)(F)`,
  `*${ADMINISTRATORS_SID}:(OI)(CI)(F)`,
]
```

OWNER RIGHTS（S-1-3-4）在授予时解析为「该对象的 owner」。`applyAcl`（`src/windows-acl.ts:206`）用 `/inheritance:r` 删掉继承 ACE（注释明说是为了去掉从 `~/.dsh` 继承的 `Everyone: FullControl`），于是用户唯一可能的权限通道就是 OWNER RIGHTS——它只在 owner == 当前用户时成立。目录不是插件自己创建时（owner 可为 Administrators），加固等于锁死。

**建议修复**：grant 列表追加一条「直接授予当前用户 SID」（可用 `*$(whoami 命令输出或 psutil home user sid)` / Node 侧 `os.userInfo().sid` 需自行取；或先用 PowerShell 读取 owner，若 owner ≠ 当前用户则**跳过加固并上报**而不是执行）。更稳妥的顺序：

1. 加固前 `Get-Acl` 读 owner；
2. owner ≠ 当前用户且非 Administrators 组成员身份时，改为 grant `当前用户:(OI)(CI)(F)` 显式条目替代 OWNER RIGHTS；
3. 或者干脆拒绝在 owner 异常的目录上启用 vault，转而 doctor 报错指引（好过静默锁死）。

### 缺陷 2（可观测性）：非 ENOENT 的 readdir 错误被静默吞掉

`src/auth.ts:1102` `readVaultEntries` 只把 ENOENT 当空目录，其余上抛——对。但调用方 `src/auth.ts:1684` `syncVault`：

```ts
try {
  entries = await readVaultEntries(dir)
} catch {
  // An unreadable vault must not take account discovery down ...
  return
}
```

catch 后直接 `return`，既不记日志也不上报状态。后果是权限故障被降级成「账号不存在」这种**方向相反的误导性文案**（用户以为要重新登录，实际是读不到）。本机实测：`syncVault` 静默跳过 → 只有桌面端扫到的账号可见 → `selectionLost()`（`src/auth.ts:1837`）判定钉住的账号丢失。

**建议修复**：至少把异常记入 status/hint（例如 `vaultUnreadable: 'EPERM ...'` 字段），UI 上区分「账号真的不在」与「vault 读不到」。`doctor` 是现成的上报通道。

### 缺陷 3（告警缺口）：doctor 的 `unverified`/`failed` 不产生 hint，也不拦截

`src/windows-acl.ts:137-149` 明确定义了 `unverified`（ACL 读不回）与 `failed`；`src/bin.ts:552` 附近的 hint 构造只覆盖 `state === 'exposed'` 一支：

```ts
...credentialAcl.flatMap(([region, entry]) => {
  if (entry.state !== 'exposed') return []
  ...
```

即加固**执行失败**（icacls 报错）或**读不回**（unverified）时，doctor 报告正文里只有一行 `Credential vault ACL (cn): unverified — ...`，不进 hints、不给出任何可执行动作。而本机这次事故恰恰属于加固"成功执行但结果错误"的形态（icacls 退出码 0，DACL 被换成了锁死形态）。三个状态里只有 `exposed` 会告警，覆盖恰好是反的：**exposed 只是"太宽"，而 unverified/failed/错误 owner 才是"可能锁死人"**。

**建议修复**：`state === 'failed' || state === 'unverified'` 时追加 hint；`inspectCredentialDirectory` 顺手校验 owner 是否为当前用户，owner 异常时给出 `takeown` 恢复指引。

## 已验证的恢复命令（供受影响用户参考）

管理员 PowerShell：

```powershell
takeown /F "C:\Users\<user>\.dsh\workbuddy-vault" /R /D Y
icacls "C:\Users\<user>\.dsh\workbuddy-vault" /reset /T
```

恢复后 vault root 与区域目录回到继承态（继承 `~/.dsh` 的用户 FullControl），两份账号凭据立即重新可见。注意 `/reset /T` 会同时去掉 5.18.0 想加的 restricted ACE——这是可接受的临时态（回到 issue #183 修复前的暴露形态），等插件修复后重新加固即可；两害相权，锁死比暴露更糟。

## 受控复现实验（A/B 对照，判定性）

在干净目录上直接复现锁死，证明 ACL 指纹与锁死结果之间是因果关系：

| 实验 | 目录 owner | 施加的 ACE | 普通（非提权）令牌下结果 |
|---|---|---|---|
| A | `luyuyu` | 逐字使用 5.16.0 tarball 中的 `/inheritance:r /grant:r *S-1-3-4:(OI)(CI)(F) *S-1-5-18:... *S-1-5-32-544:...` | stat OK，**写入 OK**（正常形态） |
| B | `BUILTIN\Administrators`（模拟 10/27 提权进程创建：UAC 提权建目录即得） | 同上，逐字相同 | **readdir EPERM、write EPERM，连 `icacls <dir>` 查看都被拒** |

实验 B 的 DACL 与本机 vault 事故现场完全一致（`OW`/`SY`/`BA` 三主体、继承已关）。恢复同样需要 `takeown /F` + `/reset /T`（非提权清理脚本第一步就 `Access is denied`，与用户遭遇一致）。对照组差异（A 正常 / B 锁死）唯一变量是 owner——坐实缺陷 1。

### 执行者与来源验证（四角度）

1. **唯一执行者扫描**：全量 `~/.dsh/profiles/desktop/node_modules`（数百包）扫描强签名 `S-1-3-4`/`OWNER RIGHTS`/`inheritance:r`，**仅 `dsh-connect-workbuddy` 携带**；另一命中 `dsh-our-free-model` 用的是显式 `${user}` grant（正确写法），反衬本缺陷。DSH 宿主 `resources/`（含 asar）与 dsh-purge 均无相关代码。
2. **版本回溯**：`npm pack dsh-connect-workbuddy@5.16.0` tarball 内 `lib/bin.js` + `lib/host-heartbeat-DpnLfJws.js` 含逐字相同命令串与注释 `WHY OWNER RIGHTS (S-1-3-4) RATHER THAN THE CURRENT USER`；上游 `src/windows-acl.ts` 仅一个提交 `d5183b2`（2026-10-31，`fix(#183)`）。
3. **时间线自洽**：该代码 10-31 才发布（5.16.0），vault 目录创建于 10/27 04:14——**当时加固代码尚不存在**，owner=Administrators 只能来自「DSH 当时以提权令牌运行」。本机存在计划任务 `noUAC.DeepSeekHarness`（`RunLevel=Highest`，免 UAC 静默提权启动 DSH），与时间线吻合。即：**10/27 提权运行的旧版插件创建目录 → 11/2 非提权运行的新版插件加固它 → 锁死**。
4. **受控复现**：上文 A/B 实验。

## 边界说明（排除宿主侧嫌疑）

- DSH 宿主主程序（`resources/app/dsh` 全量）与 dsh-purge 均无 `icacls`/`S-1-3-4` 相关代码，全部 8 个 DeepSeek Harness 进程以非提权 `luyuyu` 运行——锁死不可能是宿主或系统行为。
- 本机 `~/.dsh/profiles/desktop/node_modules` 下另有 8 个历史遗留的 Administrators-owner 目录（10/26–11/02，早于本次插件操作），与 WorkBuddy 无关，但同样印证了「DSH 家目录里存在非当前用户 owner 的目录」在真实机器上是常态而非孤例——这正是缺陷 1 的触发土壤。

## 请求

修复缺陷 1（owner 假设）为主，缺陷 2/3 为辅。5.18.0 用户遇到「账号已不存在」提示时，请先 `icacls` 查 vault 所有者再考虑重新登录。
