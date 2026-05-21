# 进度日志

## 当前已验证状态

- 仓库根目录：`/Users/tlx/APT系统`
- 标准启动路径：`./start.sh`
- 标准验证路径：`./init.sh`
- 当前最高优先级功能：APT 投标展示与验收原型闭环
- 当前 blocker：无；登录认证暂按用户要求延后

## 会话记录

### Session 001

- 日期：2026-05-20
- 本轮目标：把 Learn Harness Engineering 中文模板加入项目
- 已完成：新增根目录 harness 模板文件，并把 `init.sh` 调整为当前空项目可运行的占位入口
- 运行过的验证：`python3 -m json.tool feature_list.json`、`bash -n init.sh`、`./init.sh`
- 已记录证据：三项验证均退出码 0；`./init.sh` 打印当前目录并完成占位依赖同步、基础验证和启动命令输出
- 提交记录：未提交；当前 git 仓库尚无提交，工作区仍是未跟踪的初始项目文件
- 更新过的文件或工件：`AGENTS.md`、`CLAUDE.md`、`init.sh`、`feature_list.json`、`claude-progress.md`、`session-handoff.md`、`clean-state-checklist.md`、`evaluator-rubric.md`、`quality-document.md`
- 已知风险或未解决问题：真实项目命令和功能清单尚未填写
- 下一步最佳动作：确定项目技术栈后替换 `init.sh` 中的占位命令，并在 `feature_list.json` 中登记第一批真实功能

### Session 002

- 日期：2026-05-20
- 本轮目标：搭建自包含 FastAPI + SQLite + Vue 的 APT 投标展示与验收原型，跑通“上传样本 → 发现溯源 → 生成建议 → 指标达标展示”闭环
- 已完成：新增 `backend/` FastAPI 服务、`frontend/` Vue 3/Vite 前端、`data/graphs` 15 个图谱 HTML、`data/scenarios` 1000 条剧本 JSON；实现组织图谱、防护评估、发现溯源、画像评价四个模块；实现 DeepSeek/OpenAI 兼容 LLM 设置页和本地规则兜底建议
- 运行过的验证：`./init.sh`、`GET /api/overview`、`POST /api/analyze/demo`、`POST /api/analyze/upload`、`GET /api/evaluation`、浏览器访问 `http://localhost:5173/` 并切换组织图谱/防护评估/发现溯源/画像评价
- 已记录证据：`/api/overview` 返回图谱 15、方法 227、剧本 1000、武器 2482、资产 869；`/api/analyze/demo` 返回 320 条内置样本、发现准确度 93.75%、画像成功率 76.67%，两项均达标；浏览器验证第一个图谱 iframe、攻击路径、本地建议和评价指标均可见
- 提交记录：未提交；当前 git 仓库尚无提交，工作区仍是未跟踪的初始项目文件
- 更新过的文件或工件：`backend/`、`frontend/`、`data/graphs/`、`data/scenarios/`、`README.md`、`init.sh`、`start.sh`、`.gitignore`、`feature_list.json`、`claude-progress.md`
- 已知风险或未解决问题：PCAP 当前仅为入口占位；LLM 调用依赖用户配置 API Key 和网络，失败时使用本地规则；登录认证暂未实现，LLM Key 目前按用户要求只存 SQLite
- 下一步最佳动作：补登录认证和权限控制；根据真实流量样本扩展字段映射；将 PCAP 解析从占位升级为真实解析

### Session 003

- 日期：2026-05-20
- 本轮目标：按产品调整要求收敛验收话术、迁移 LLM 设置入口，并把防护评估改为 1000 条剧本库攻击路径浏览与筛选
- 已完成：移除侧边栏内嵌 LLM 设置，改为顶部“系统设置”入口和设置页内 LLM 设置；顶部概览只展示组织图谱、攻击方法、攻击剧本、攻击武器四项裸数字；侧边栏不再展示模块状态；画像评价页改为中性“识别概览/画像评价体系”；防护评估改为 1000 条剧本库路径分页浏览，支持资产和 MITRE 技术编号多选筛选，默认空态，点击路径后显示阶段详情、影响和单路径本地建议，LLM 增强改为手动触发
- 运行过的验证：`./init.sh`、`python3 -m py_compile backend/app/main.py`、`npm run build`、`GET /api/paths?page=1&page_size=2`、`GET /api/paths?assets=配电站&techniques=T1566.001&page=1&page_size=20`、`GET /api/paths/APT-SCRIPT-ELEC-0001/recommendations?llm=false`、浏览器访问 `http://127.0.0.1:5173/` 并验证组织图谱、防护评估、系统设置、画像评价
- 已记录证据：`/api/paths?page=1&page_size=2` 返回 `total=1000`、`page_size=2` 且路径不含 APT 归属和置信度字段；资产“配电站”+技术 `T1566.001` 筛选返回 `total=1`；单路径建议返回本地规则库 6 条建议；浏览器验证顶部只显示 4 个概览数字且不显示“指标可验收/>=/已加载”，防护评估默认 20 条路径和空态，选中路径后出现 6 条建议，系统设置页包含 LLM 设置，画像评价页不显示“验收指标/要求 >/达标/未计算”
- 提交记录：未提交；当前 git 仓库尚无提交，工作区仍是未跟踪的初始项目文件
- 更新过的文件或工件：`backend/app/main.py`、`frontend/src/App.vue`、`frontend/src/style.css`、`frontend/dist/`、`feature_list.json`、`claude-progress.md`
- 已知风险或未解决问题：真实 APT-剧本映射仍不存在，按本轮决策防护评估不展示 APT 筛选；PCAP 仍为占位；LLM Key 仍按既有方式保存在 SQLite；本轮为本地原型验证，未做移动端专项适配
- 下一步最佳动作：如需继续提高可信度，应补真实 APT-剧本映射或把剧本库来源字段化；若进入生产化，应补登录权限、密钥安全存储、PCAP 真实解析和自动化 UI 回归

### Session 004

- 日期：2026-05-20
- 本轮目标：收敛防护评估筛选，只保留合并后的资产场景域筛选；未配置 LLM 时点击增强给出明确提示
- 已完成：后端 `/api/paths` 的 `filters` 只返回资产场景域，不再返回技术编号；资产筛选从细分目标合并为 10 个电力场景域并按场景域匹配剧本；前端移除技术编号筛选和相关状态；未配置 LLM 时点击“LLM 增强”显示页面内提示，不再静默回退；后端对直接请求 `llm=true` 也返回未配置错误
- 运行过的验证：`./init.sh`、`.venv/bin/python -m py_compile backend/app/main.py`、`npm --prefix frontend run build`、`GET /api/paths?page=1&page_size=2`、`GET /api/paths?assets=变电站域&page=1&page_size=20`、`GET /api/paths?assets=调度控制域&page=1&page_size=20`、`GET /api/paths/APT-SCRIPT-ELEC-0001/recommendations?llm=true`、浏览器访问 `http://127.0.0.1:5174/` 验证防护评估筛选与 LLM 提示
- 已记录证据：`/api/paths?page=1&page_size=2` 返回 `total=1000`、`page_size=2` 且 `filters` 只包含 10 个资产场景域；变电站域筛选返回 `total=110`，调度控制域筛选返回 `total=258`；未配置 LLM 请求增强返回 HTTP 400 和“LLM 未配置，请到系统设置启用并填写 API Key”；浏览器验证防护评估不显示“技术编号”，资产筛选显示 10 个场景域，点击未配置的 LLM 增强出现页面内提示且建议来源保持本地规则库；配置 dummy LLM 后不显示未配置提示并走增强请求失败回退
- 提交记录：未提交；当前 git 仓库尚无提交，工作区仍是未跟踪的初始项目文件
- 更新过的文件或工件：`backend/app/main.py`、`frontend/src/App.vue`、`frontend/src/style.css`、`frontend/dist/`、`feature_list.json`、`claude-progress.md`
- 已知风险或未解决问题：真实 LLM 联网生成未验证，本轮只验证未配置提示和已配置失败回退；真实 APT-剧本映射和 PCAP 解析仍沿用既有风险
- 下一步最佳动作：若进入生产化，应补登录权限、密钥安全存储、PCAP 真实解析和自动化 UI 回归

### Session 005

- 日期：2026-05-20
- 本轮目标：按 AGENTS.md 完成首次 git commit
- 已完成：确认仓库根目录、读取 `claude-progress.md` 和 `feature_list.json`、检查最近提交状态、运行标准验证入口，并把 Vim swap 临时文件加入 `.gitignore`
- 运行过的验证：`pwd`、`git log --oneline -5`、`./init.sh`、`rg` 敏感字段检查、`git status --short --ignored`
- 已记录证据：当前仓库路径为 `/Users/tlx/APT系统`；`git log --oneline -5` 返回当前 `main` 分支尚无提交；`./init.sh` 完成后端依赖同步、前端依赖同步、`backend/app` 编译和 `npm build`，退出码 0；敏感字段检查仅命中代码字段名、占位配置和样例数据，未发现真实密钥；`.venv/`、`frontend/node_modules/`、`frontend/dist/`、`data/apt_system.sqlite3` 和 swap 文件均不会进入提交；`git diff --cached --check` 报告已暂存图谱 HTML 和剧本 JSON 中存在批量尾随空白，因这些是既有生成/数据工件且 `./init.sh` 已验证可读，本轮不做全量格式重写
- 提交记录：本轮创建首次提交
- 更新过的文件或工件：`.gitignore`、`claude-progress.md`
- 已知风险或未解决问题：沿用 Session 004 风险；真实 LLM 联网生成、真实 APT-剧本映射、PCAP 真实解析和生产级登录权限仍未完成
- 下一步最佳动作：如继续生产化，应按优先级补登录权限、密钥安全存储、PCAP 真实解析和自动化 UI 回归

### Session 006

- 日期：2026-05-21
- 本轮目标：优化防护评估攻击路径里的资产筛选框和整体工作台式布局
- 已完成：将资产原生多选框改为 10 个资产域标签按钮，支持多选、取消选中和清空筛选；左侧路径浏览面板拆为筛选区、路径列表区和分页区；路径行稳定为编号、资产、场景摘要三段式；右侧路径详情头部增加独立文案和 LLM 操作区布局
- 运行过的验证：`./init.sh`、`npm --prefix frontend run build`、`GET /api/paths?page=1&page_size=2`、`GET /api/paths?assets=变电站域,调度控制域&page=1&page_size=2`、`GET /api/paths/APT-SCRIPT-ELEC-0001/recommendations?llm=true`、用户人工浏览器验证防护评估页
- 已记录证据：`npm --prefix frontend run build` 退出码 0；`/api/paths?page=1&page_size=2` 返回 10 个资产域 filters 和 total=1000；`/api/paths?assets=变电站域,调度控制域&page=1&page_size=2` 返回 total=368；未配置 LLM 增强仍返回 HTTP 400 和未配置提示；用户人工验证标签多选、取消、清空交互，服务日志显示对应 `/api/paths` 请求均为 200
- 提交记录：本轮创建提交
- 更新过的文件或工件：`frontend/src/App.vue`、`frontend/src/style.css`、`feature_list.json`、`claude-progress.md`
- 已知风险或未解决问题：真实 LLM 联网生成、真实 APT-剧本映射、PCAP 真实解析和生产级登录权限仍未完成；本轮不改后端筛选规则
- 下一步最佳动作：如继续生产化，应按优先级补登录权限、密钥安全存储、PCAP 真实解析和自动化 UI 回归
