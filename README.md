# APT 投标展示与验收原型

自包含原型系统，覆盖组织图谱、防护评估、发现溯源、画像评价四个模块。

## 技术栈

- 后端：FastAPI + SQLite
- 前端：Vue 3 + Vite
- 数据：15 个图谱 HTML、1000 条攻击剧本 JSON、内置 320 条演示流量事件

## 启动

```bash
./init.sh
./start.sh
```

访问：

- 前端：http://127.0.0.1:5173
- 后端：http://127.0.0.1:8000
- 接口文档：http://127.0.0.1:8000/docs

## 上传样本字段

CSV/JSON 支持字段：

```text
timestamp, src_ip, dst_ip, protocol, dst_port, event_type, asset, technique, tool, severity, label, expected_apt
```

`label` 可选值为 `APT` / `BENIGN`；`expected_apt` 可为空。无标签样本只做发现与溯源展示，带标签样本参与准确度和画像成功率计算。

PCAP 当前保留入口，占位待后续实现真实解析。
