# Deepsidian

Deepsidian 是一个不依赖 Node.js、Python、本地服务或第三方运行库的 Obsidian AI Agent 插件。插件使用 Obsidian 自带 API，可以在桌面端和移动端运行。

## 当前功能

- DeepSeek BYOK，默认使用 `deepseek-v4-flash`
- OpenAI Chat Completions 兼容接口
- 聊天记录以 Markdown 保存在 Vault 内
- 可从输入框旁的文件夹按钮启用受限访问，Agent 只能递归访问选定目录
- 打开工作台时自动恢复上次对话，移动端标题栏可直接新建对话
- 完整系统提示词保存在 `deepsidian/System Prompt.md`，可在设置或 Obsidian 中直接修改
- 文件可按行分页读取，并返回总字符数、总行数和下一页起始行
- 可将 Obsidian 内的文件直接拖入输入框，自动转换为 Vault 文件引用
- API Key 可使用 Web Crypto 加密后保存在 Vault，供不同设备解锁
- 无遥测，无内置服务端，无第三方运行依赖

## 安装

将整个 `vault-agent-chat` 文件夹放到 Vault 的：

```text
.obsidian/plugins/vault-agent-chat/
```

目录中至少应包含：

```text
main.js
manifest.json
styles.css
```

重新加载 Obsidian，然后进入“设置 → 第三方插件”启用 **deepsidian**。

## 首次配置

1. 打开“设置 → deepsidian”。
2. 在 **API Key** 中创建或选择一个 SecretStorage 密钥。
3. Base URL 保持 `https://api.deepseek.com`。
4. 模型保持 `deepseek-v4-flash`。
5. 点击“开始测试”。
6. 通过左侧机器人图标或命令面板打开聊天。

默认情况下，密钥只保存在当前设备的 Obsidian SecretStorage 中，不会写入 `data.json` 或聊天记录。

如果希望跨设备使用，在设置里点击 **写入加密副本**。插件会使用浏览器内置 Web Crypto 执行 PBKDF2-SHA-256（310,000 次）和 AES-256-GCM 加密，密文保存在：

```text
deepsidian/Secrets/api-key.enc.json
```

同步密码可以留空，但复杂密码更能抵抗拿到密文后的离线猜测。密码本身不会写入 Vault。新设备第一次点击 **解锁此设备** 后，默认会将密码和解密出的 API Key 放进该设备的 SecretStorage，以后自动解锁；取消“在本设备安全记住密码”后则需要再次输入。

## 对话记录

默认保存在：

```text
deepsidian/Chats/
```

每次“新对话”会产生一个新的 Markdown 文件。记录包含用户消息、Agent 回复、思考过程和工具执行摘要，因此可以跟随你已有的 Vault 同步方式在设备间同步。聊天工作台左侧可以直接重新打开最近记录。

再次打开 Deepsidian 时会自动回到上次对话。移动端标题栏中，历史侧栏按钮旁的加号可显式开始新对话。

## 安全边界

- 禁止访问 Vault 配置目录。
- Agent 工具无法读取、列出、修改或删除 `deepsidian/Secrets` 加密密钥目录。
- Agent 工具无法读取或修改 `deepsidian/System Prompt.md`，提示词只能由用户编辑。
- 输入框旁的文件夹按钮可将 Agent 限制在一个选定目录内；读取、搜索、创建、修改、移动和删除都只能访问该目录及其子目录。
- 拒绝绝对路径和包含 `..` 的路径。
- 搜索、读取和写入都有大小或数量上限。
- 工具调用轮数有上限。
- 删除使用 Obsidian 的废纸篓偏好，不直接永久删除。
- 笔记内容被视为不可信数据，不能扩大 Agent 权限。

AI 请求会把当前问题、必要的最近对话以及 Agent 主动读取的笔记片段发送到你配置的模型服务。插件不包含遥测。

## 扩展工具

插件内部使用统一工具注册中心。其他代码可以调用插件实例的 `registerAgentTool(spec)` 注册工具，`spec` 需要包含：

- `definition`：OpenAI Function Tool 定义
- `risk`：`read`、`write` 或 `destructive`
- `execute(args)`：执行函数
- `preview(args)`：写入或危险操作的确认预览，可选

工具必须自行遵守移动端限制，不应依赖 Node.js、Electron、Shell 或桌面文件系统 API。

## 已知限制

- 当前版本使用非流式响应，以保证 Obsidian 桌面端与移动端行为一致。
- 大型 Vault 使用文字搜索，不包含向量数据库或本地嵌入模型。
- iOS/iPadOS 切到后台后，长任务可能被系统暂停。
