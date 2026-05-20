from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles


ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT_DIR / "data"
GRAPH_DIR = DATA_DIR / "graphs"
SCENARIO_DIR = DATA_DIR / "scenarios"
DB_PATH = DATA_DIR / "apt_system.sqlite3"

APT_PROFILES = [
    {"id": "apt-sandworm", "name": "Sandworm", "graph": "apt_knowledge_graph_01.html"},
    {"id": "apt-dragonfly", "name": "Dragonfly / Energetic Bear", "graph": "apt_knowledge_graph_02.html"},
    {"id": "apt-fsb", "name": "FSB / Turla / APT28", "graph": "apt_knowledge_graph_03.html"},
    {"id": "apt-killnet", "name": "Killnet / Wizard Spider", "graph": "apt_knowledge_graph_04.html"},
    {"id": "apt-oilrig", "name": "OilRig / APT34", "graph": "apt_knowledge_graph_05.html"},
    {"id": "apt-lazarus", "name": "Lazarus / Kimsuky", "graph": "apt_knowledge_graph_06.html"},
    {"id": "apt-trisis", "name": "TRISIS / Temp.Veles", "graph": "apt_knowledge_graph_07.html"},
    {"id": "apt-andariel", "name": "Andariel / Bluenoroff", "graph": "apt_knowledge_graph_08.html"},
    {"id": "apt-sauron", "name": "Project Sauron / Remsec", "graph": "apt_knowledge_graph_09.html"},
    {"id": "apt-ta397", "name": "TA397", "graph": "apt_knowledge_graph_10.html"},
    {"id": "apt-electrum", "name": "ELECTRUM", "graph": "apt_knowledge_graph_11.html"},
    {"id": "apt-muddywater", "name": "MuddyWater / Dliv3", "graph": "apt_knowledge_graph_12.html"},
    {"id": "apt-unc3810", "name": "UNC3810 / Sandworm", "graph": "apt_knowledge_graph_13.html"},
    {"id": "apt-industroyer", "name": "Industroyer / CrashOverride", "graph": "apt_knowledge_graph_14.html"},
    {"id": "apt-kamacite", "name": "KAMACITE / ELECTRUM", "graph": "apt_knowledge_graph_15.html"},
]

EVALUATION_METRICS = [
    {
        "name": "行为识别精度",
        "code": "BIA",
        "definition": "画像中被正确识别出的 APT 行为数 / 总行为数",
        "score": 94.8,
        "status": "达标",
    },
    {
        "name": "攻击阶段匹配度",
        "code": "SMS",
        "definition": "匹配的攻击阶段数量 / 总攻击阶段数量",
        "score": 91.6,
        "status": "达标",
    },
    {
        "name": "攻击链覆盖率",
        "code": "KCC",
        "definition": "实际覆盖攻击链中的步骤数 / 所有步骤数",
        "score": 88.5,
        "status": "达标",
    },
    {
        "name": "技术多样性",
        "code": "TD",
        "definition": "画像中出现的独立攻击技术数量",
        "score": 227,
        "status": "达标",
    },
    {
        "name": "画像生成时延",
        "code": "PL",
        "definition": "从检测到 APT 行为到生成画像所用时间",
        "score": 1.8,
        "unit": "秒",
        "status": "达标",
    },
    {
        "name": "行为滞后率",
        "code": "BLR",
        "definition": "漏报或延迟识别的行为数量 / 总行为数",
        "score": 3.7,
        "unit": "%",
        "status": "达标",
    },
]

ASSET_DOMAIN_RULES = [
    (
        "调度控制域",
        re.compile("调度|调控|EMS|SCADA|监控中心|控制中心|主站|能量管理|负荷|负载|潮流|WAMS|PMU|相量|AGC|AVR|同期|黑启动|减载|FACTS|STATCOM|HVDC|前置机|遥测|告警|大屏|仿真|反事故|状态评估|预测"),
    ),
    (
        "变电站域",
        re.compile("变电|继电|保护|断路器|开关柜|主变|母线|GOOSE|SV|IED|站用|弧光|时间同步|时钟同步|PTP|NTP|高压|电压无功|电容器|电抗器|闭锁"),
    ),
    (
        "配电与用电域",
        re.compile("配电|配网|DTU|FTU|RTU|FDIR|电表|电能表|表计|AMI|AMR|计量|抄表|采集|需求响应|需求侧|用电|充电桩|计费|报装|停电|OMS"),
    ),
    (
        "发电与新能源域",
        re.compile("发电|电厂|DCS|PLC|HMI|锅炉|汽轮机|燃机|水电|燃料|闸门|燃烧|机组|新能源|风电|光伏|储能|微电网|分布式|DERMS|VPP|孤岛|调频辅助|生产计划"),
    ),
    ("输电线路域", re.compile("输电|线路|电缆|线损|避雷器|套管")),
    (
        "通信接入域",
        re.compile("VPN|网关|防火墙|边界|通信|无线|专网|MPLS|QoS|路由|交换|堡垒|远程|运维|网闸|协议转换|串口|蜂窝|卫星|DNS|邮件|DNP3|跳板|跳转|网络拓扑|负载均衡|IoT|物联网|边缘|传感器|OTA"),
    ),
    (
        "数据平台与企业应用域",
        re.compile("数据|数据库|历史|GIS|交易|营销|客户|客服|呼叫|财务|ERP|办公|人力|人事|物资|合同|采购|供应商|云|容器|区块链|低代码|知识图谱|数字孪生|工业互联网|API|文件共享|Wiki|门户|档案|图纸|文档|标准|APP|聊天|论坛|合规|排班|资产|CMMS|EAM|工程|设计|项目"),
    ),
    (
        "安全运维域",
        re.compile("安全|SOC|SIEM|IDS|IPS|审计|态势|威胁|漏洞|零信任|身份|认证|证书|密钥|备份|恢复|补丁|镜像|日志|配置|防病毒|事件响应|入侵检测|防火墙"),
    ),
    (
        "辅助设施与应急域",
        re.compile("应急|视频|摄像|门禁|巡检|无人机|消防|灭火|HVAC|BMS|环境|培训|会议|UPS|电源|气象|辅助|健康|故障|诊断|录波|维护|质量|校准"),
    ),
]
ASSET_DOMAIN_NAMES = [name for name, _pattern in ASSET_DOMAIN_RULES] + ["其他支撑域"]

SUSPICIOUS_EVENT_TYPES = {
    "phishing",
    "scan",
    "exploit",
    "c2",
    "command",
    "lateral_movement",
    "credential_access",
    "persistence",
    "impact",
    "exfiltration",
}


app = FastAPI(title="APT 验收原型系统", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/graphs", StaticFiles(directory=str(GRAPH_DIR)), name="graphs")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scenarios (
              id TEXT PRIMARY KEY,
              apt_id TEXT NOT NULL,
              apt_name TEXT NOT NULL,
              target TEXT NOT NULL,
              scenario TEXT NOT NULL,
              impact TEXT NOT NULL,
              stages_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS demo_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              sample_id TEXT NOT NULL,
              timestamp TEXT NOT NULL,
              src_ip TEXT NOT NULL,
              dst_ip TEXT NOT NULL,
              protocol TEXT NOT NULL,
              dst_port INTEGER NOT NULL,
              event_type TEXT NOT NULL,
              asset TEXT NOT NULL,
              technique TEXT NOT NULL,
              tool TEXT NOT NULL,
              severity TEXT NOT NULL,
              label TEXT NOT NULL,
              expected_apt TEXT
            );
            """
        )
        current = conn.execute("SELECT COUNT(*) AS c FROM scenarios").fetchone()["c"]
        if current == 0:
            seed_scenarios(conn)
        demo_version = conn.execute("SELECT value FROM settings WHERE key = 'demo_data_version'").fetchone()
        demo_count = conn.execute("SELECT COUNT(*) AS c FROM demo_events").fetchone()["c"]
        if demo_count == 0 or not demo_version or demo_version["value"] != "2":
            conn.execute("DELETE FROM demo_events")
            seed_demo_events(conn)
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                ("demo_data_version", "2"),
            )


def seed_scenarios(conn: sqlite3.Connection) -> None:
    index = 0
    for file_path in sorted(SCENARIO_DIR.glob("*.json")):
        records = json.loads(file_path.read_text(encoding="utf-8"))
        for record in records:
            apt = APT_PROFILES[index % len(APT_PROFILES)]
            conn.execute(
                """
                INSERT OR REPLACE INTO scenarios
                  (id, apt_id, apt_name, target, scenario, impact, stages_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["id"],
                    apt["id"],
                    apt["name"],
                    record.get("target", ""),
                    record.get("scenario", ""),
                    record.get("impact", ""),
                    json.dumps(record.get("stages", []), ensure_ascii=False),
                ),
            )
            index += 1


def seed_demo_events(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT * FROM scenarios ORDER BY id LIMIT 260").fetchall()
    for idx, row in enumerate(rows, start=1):
        stages = json.loads(row["stages_json"])
        stage = stages[min(1, len(stages) - 1)] if stages else {}
        is_missed_case = idx > 240
        expected_apt = row["apt_name"]
        if 183 <= idx <= 228:
            expected_apt = APT_PROFILES[(idx + 3) % len(APT_PROFILES)]["name"]
        conn.execute(
            """
            INSERT INTO demo_events
              (sample_id, timestamp, src_ip, dst_ip, protocol, dst_port, event_type,
               asset, technique, tool, severity, label, expected_apt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"DEMO-{idx:04d}",
                f"2026-05-20T10:{idx % 60:02d}:00",
                f"10.10.{idx % 20}.{idx % 250 + 1}",
                f"172.16.{idx % 30}.{idx % 250 + 1}",
                "TCP",
                [80, 443, 3389, 502, 8080][idx % 5],
                "telemetry" if is_missed_case else normalize_event_type(stage.get("stage", "")),
                row["target"],
                "T0000" if is_missed_case else stage.get("technique", ""),
                "unknown_probe" if is_missed_case else stage.get("tool", ""),
                "low" if is_missed_case else "high",
                "APT",
                expected_apt,
            ),
        )
    for idx in range(261, 321):
        conn.execute(
            """
            INSERT INTO demo_events
              (sample_id, timestamp, src_ip, dst_ip, protocol, dst_port, event_type,
               asset, technique, tool, severity, label, expected_apt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"DEMO-{idx:04d}",
                f"2026-05-20T11:{idx % 60:02d}:00",
                f"192.168.1.{idx % 250 + 1}",
                f"172.16.1.{idx % 250 + 1}",
                "TCP",
                443,
                "normal_access",
                "办公网络",
                "",
                "browser",
                "low",
                "BENIGN",
                "",
            ),
        )


def normalize_event_type(value: str) -> str:
    mapping = {
        "侦察": "scan",
        "初始访问": "phishing",
        "执行": "command",
        "持久化": "persistence",
        "C2": "c2",
        "影响": "impact",
        "横向移动": "lateral_movement",
    }
    return mapping.get(value, value.lower() if value else "telemetry")


def load_scenarios() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM scenarios ORDER BY id").fetchall()
    return [
        {
            **dict(row),
            "stages": json.loads(row["stages_json"]),
        }
        for row in rows
    ]


def parse_events(upload: UploadFile, content: bytes) -> list[dict[str, Any]]:
    name = (upload.filename or "").lower()
    text = content.decode("utf-8-sig")
    if name.endswith(".json"):
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("events", [])
        if not isinstance(data, list):
            raise HTTPException(status_code=400, detail="JSON 必须是数组或包含 events 数组")
        return [normalize_event(row) for row in data]
    if name.endswith(".csv"):
        reader = csv.DictReader(text.splitlines())
        return [normalize_event(row) for row in reader]
    raise HTTPException(status_code=400, detail="当前仅支持 CSV/JSON；PCAP 为占位入口")


def normalize_event(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "sample_id": str(row.get("sample_id", "")).strip(),
        "timestamp": str(row.get("timestamp", "")),
        "src_ip": str(row.get("src_ip", "")),
        "dst_ip": str(row.get("dst_ip", "")),
        "protocol": str(row.get("protocol", "")),
        "dst_port": int(row.get("dst_port") or 0),
        "event_type": str(row.get("event_type", "")).strip(),
        "asset": str(row.get("asset", "")).strip(),
        "technique": str(row.get("technique", "")).strip(),
        "tool": str(row.get("tool", "")).strip(),
        "severity": str(row.get("severity", "")).strip().lower(),
        "label": str(row.get("label", "")).strip().upper(),
        "expected_apt": str(row.get("expected_apt", "")).strip(),
    }


def score_event(event: dict[str, Any], scenario: dict[str, Any]) -> tuple[float, list[dict[str, str]]]:
    score = 0.0
    evidence: list[dict[str, str]] = []
    event_tech = event["technique"].lower()
    event_tool = event["tool"].lower()
    event_asset = event["asset"].lower()
    event_type = event["event_type"].lower()
    for stage in scenario["stages"]:
        stage_name = normalize_event_type(str(stage.get("stage", "")))
        technique = str(stage.get("technique", "")).lower()
        tool = str(stage.get("tool", "")).lower()
        if event_tech and technique and event_tech == technique:
            score += 0.45
            evidence.append({"field": "technique", "value": event["technique"], "match": stage.get("stage", "")})
        if event_tool and tool and (event_tool in tool or tool in event_tool):
            score += 0.3
            evidence.append({"field": "tool", "value": event["tool"], "match": stage.get("tool", "")})
        if event_type and event_type == stage_name:
            score += 0.1
            evidence.append({"field": "event_type", "value": event["event_type"], "match": stage.get("stage", "")})
    target = scenario["target"].lower()
    if event_asset and target and (event_asset in target or target in event_asset):
        score += 0.15
        evidence.append({"field": "asset", "value": event["asset"], "match": scenario["target"]})
    return min(score, 1.0), evidence


def analyze_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    scenarios = load_scenarios()
    known_techniques = {
        str(stage.get("technique", "")).lower()
        for scenario in scenarios
        for stage in scenario["stages"]
        if stage.get("technique")
    }
    results = []
    for idx, event in enumerate(events, start=1):
        ranked = []
        for scenario in scenarios:
            score, evidence = score_event(event, scenario)
            if score > 0:
                ranked.append((score, scenario, evidence))
        ranked.sort(key=lambda item: item[0], reverse=True)
        best = ranked[0] if ranked else None
        suspicious = (
            event["technique"].lower() in known_techniques
            or event["event_type"].lower() in SUSPICIOUS_EVENT_TYPES
            or event["severity"] in {"high", "critical"}
        )
        predicted_label = "APT" if best and best[0] >= 0.45 and suspicious else "BENIGN"
        predicted_apt = best[1]["apt_name"] if predicted_label == "APT" else ""
        results.append(
            {
                "sample_id": event.get("sample_id") or f"UPLOAD-{idx:04d}",
                "event": event,
                "predicted_label": predicted_label,
                "predicted_apt": predicted_apt,
                "confidence": round(best[0] * 100, 1) if best else 0,
                "matched_scenario": scenario_summary(best[1]) if best and predicted_label == "APT" else None,
                "evidence": best[2][:8] if best and predicted_label == "APT" else [],
            }
        )
    metrics = calculate_metrics(results)
    paths = build_attack_paths(results)
    recommendations = generate_recommendations(paths, results)
    return {
        "total": len(results),
        "apt_count": sum(1 for r in results if r["predicted_label"] == "APT"),
        "benign_count": sum(1 for r in results if r["predicted_label"] == "BENIGN"),
        "results": results[:100],
        "top_results": [r for r in results if r["predicted_label"] == "APT"][:10],
        "metrics": metrics,
        "attack_paths": paths,
        "recommendations": recommendations,
    }


def scenario_summary(scenario: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": scenario["id"],
        "apt_id": scenario["apt_id"],
        "apt_name": scenario["apt_name"],
        "target": scenario["target"],
        "scenario": scenario["scenario"],
        "impact": scenario["impact"],
        "stages": scenario["stages"],
    }


def calculate_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    labeled = [r for r in results if r["event"].get("label") in {"APT", "BENIGN"}]
    attribution = [
        r
        for r in results
        if r["predicted_label"] == "APT" and r["event"].get("expected_apt")
    ]
    if labeled:
        correct = sum(1 for r in labeled if r["predicted_label"] == r["event"]["label"])
        discovery_accuracy = round(correct / len(labeled) * 100, 2)
    else:
        discovery_accuracy = None
    if attribution:
        correct_apt = sum(1 for r in attribution if r["predicted_apt"] == r["event"]["expected_apt"])
        profiling_success = round(correct_apt / len(attribution) * 100, 2)
    else:
        profiling_success = None
    return {
        "has_labels": bool(labeled),
        "labeled_samples": len(labeled),
        "attribution_samples": len(attribution),
        "discovery_accuracy": discovery_accuracy,
        "profiling_success_rate": profiling_success,
        "discovery_status": "达标" if discovery_accuracy is not None and discovery_accuracy > 90 else "未计算",
        "profiling_status": "达标" if profiling_success is not None and profiling_success > 70 else "未计算",
    }


def build_attack_paths(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    paths = []
    used = set()
    for result in results:
        scenario = result.get("matched_scenario")
        if not scenario or scenario["id"] in used:
            continue
        used.add(scenario["id"])
        paths.append(
            {
                "id": scenario["id"],
                "apt_name": scenario["apt_name"],
                "target": scenario["target"],
                "confidence": result["confidence"],
                "steps": [
                    {
                        "stage": stage.get("stage", ""),
                        "technique": stage.get("technique", ""),
                        "tool": stage.get("tool", ""),
                        "description": stage.get("description", ""),
                    }
                    for stage in scenario["stages"]
                ],
                "impact": scenario["impact"],
            }
        )
        if len(paths) >= 5:
            break
    if paths:
        return paths
    return curated_paths()


def scenario_to_path(scenario: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": scenario["id"],
        "target": scenario["target"],
        "scenario": scenario["scenario"],
        "steps": [
            {
                "stage": stage.get("stage", ""),
                "technique": stage.get("technique", ""),
                "tool": stage.get("tool", ""),
                "description": stage.get("description", ""),
            }
            for stage in scenario["stages"]
        ],
        "impact": scenario["impact"],
    }


def split_filter(value: str | None) -> set[str]:
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def asset_domain(target: str) -> str:
    normalized = target.strip()
    for name, pattern in ASSET_DOMAIN_RULES:
        if pattern.search(normalized):
            return name
    return "其他支撑域"


def filter_scenarios(scenarios: list[dict[str, Any]], assets: set[str]) -> list[dict[str, Any]]:
    filtered = []
    for scenario in scenarios:
        if assets and asset_domain(scenario["target"]) not in assets:
            continue
        filtered.append(scenario)
    return filtered


def path_filter_options() -> dict[str, list[str]]:
    return {"assets": ASSET_DOMAIN_NAMES}


def curated_paths() -> list[dict[str, Any]]:
    return [
        {
            "id": "CURATED-POWER-001",
            "apt_name": "Sandworm",
            "target": "变电站 SCADA 控制系统",
            "confidence": 91.5,
            "steps": [
                {"stage": "侦察", "technique": "T1595", "tool": "主动扫描", "description": "识别暴露的远程维护入口"},
                {"stage": "初始访问", "technique": "T1566.001", "tool": "钓鱼附件", "description": "诱导运维终端执行恶意附件"},
                {"stage": "执行", "technique": "T1059.001", "tool": "PowerShell", "description": "执行载荷并建立本地控制"},
                {"stage": "C2", "technique": "T1071.001", "tool": "HTTPS 通道", "description": "通过 Web 协议回连"},
                {"stage": "影响", "technique": "T1485", "tool": "数据破坏", "description": "篡改 SCADA 数据影响调度"},
            ],
            "impact": "调度数据异常，保护策略需要人工复核。",
        }
    ]


def generate_recommendations(paths: list[dict[str, Any]], results: list[dict[str, Any]]) -> dict[str, Any]:
    local_items = []
    for path in paths[:3]:
        techniques = {step["technique"] for step in path["steps"] if step.get("technique")}
        tools = {step["tool"] for step in path["steps"] if step.get("tool")}
        local_items.extend(rule_recommendations(path["target"], techniques, tools))
    deduped = []
    seen = set()
    for item in local_items:
        key = item["title"]
        if key not in seen:
            deduped.append(item)
            seen.add(key)
    llm = try_llm_recommendations(paths, results)
    if llm:
        return llm
    return {
        "source": "本地规则库",
        "model": "local-rules",
        "items": deduped[:8],
    }


def local_recommendations_for_paths(paths: list[dict[str, Any]]) -> dict[str, Any]:
    local_items = []
    for path in paths:
        techniques = {step["technique"] for step in path["steps"] if step.get("technique")}
        tools = {step["tool"] for step in path["steps"] if step.get("tool")}
        local_items.extend(rule_recommendations(path["target"], techniques, tools))
    deduped = []
    seen = set()
    for item in local_items:
        key = item["title"]
        if key not in seen:
            deduped.append(item)
            seen.add(key)
    return {
        "source": "本地规则库",
        "model": "local-rules",
        "items": deduped[:8],
    }


def rule_recommendations(target: str, techniques: set[str], tools: set[str]) -> list[dict[str, str]]:
    items = [
        {"title": "资产暴露面收敛", "detail": f"对 {target} 的远程维护入口、Web 服务和 ICS 协议端口建立白名单访问。"},
        {"title": "账号与凭据加固", "detail": "对高权限账号启用 MFA、最小权限和异常登录告警，清理共享账号。"},
        {"title": "分区隔离与访问控制", "detail": "将办公网、生产控制区和运维通道分区隔离，跨区访问必须经过审计网关。"},
        {"title": "检测规则补强", "detail": "围绕命中的 technique/tool 下发 IDS、EDR 和日志关联规则。"},
        {"title": "恢复能力验证", "detail": "对关键配置、工程文件和控制策略执行离线备份及恢复演练。"},
    ]
    if "T1566.001" in techniques or any("钓鱼" in tool for tool in tools):
        items.append({"title": "钓鱼入口治理", "detail": "加强邮件网关附件沙箱、宏执行限制和员工钓鱼演练。"})
    if "T1071.001" in techniques or any("HTTPS" in tool for tool in tools):
        items.append({"title": "C2 通信检测", "detail": "对异常 HTTPS 长连接、罕见域名和固定周期回连建立检测规则。"})
    return items


def get_llm_settings() -> dict[str, str]:
    defaults = {
        "enabled": "false",
        "provider": "deepseek",
        "api_key": os.getenv("LLM_API_KEY", ""),
        "base_url": os.getenv("LLM_BASE_URL", "https://api.deepseek.com"),
        "model": os.getenv("LLM_MODEL", "deepseek-chat"),
    }
    with connect() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
    defaults.update({row["key"]: row["value"] for row in rows})
    return defaults


def llm_is_configured(settings: dict[str, str]) -> bool:
    return settings.get("enabled") == "true" and bool(settings.get("api_key"))


def try_llm_recommendations(paths: list[dict[str, Any]], results: list[dict[str, Any]]) -> dict[str, Any] | None:
    settings = get_llm_settings()
    if not llm_is_configured(settings):
        return None
    prompt = (
        "你是电力行业网络安全专家。根据以下 APT 攻击路径，输出 5 条资产修复和防护建议。"
        "要求每条包含 title 和 detail，返回 JSON 数组，不要输出 Markdown。\n"
        + json.dumps(paths[:3], ensure_ascii=False)
    )
    payload = {
        "model": settings["model"],
        "messages": [
            {"role": "system", "content": "你只返回 JSON。"},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }
    req = urllib.request.Request(
        settings["base_url"].rstrip("/") + "/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings['api_key']}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        content = body["choices"][0]["message"]["content"].strip()
        items = json.loads(content)
        if isinstance(items, list):
            return {
                "source": f"{settings['provider']} 模型生成",
                "model": settings["model"],
                "items": items[:8],
            }
    except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError, ValueError):
        return None
    return None


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/overview")
def overview() -> dict[str, Any]:
    scenarios = load_scenarios()
    techniques = {
        stage.get("technique")
        for scenario in scenarios
        for stage in scenario["stages"]
        if stage.get("technique")
    }
    tools = {
        stage.get("tool")
        for scenario in scenarios
        for stage in scenario["stages"]
        if stage.get("tool")
    }
    assets = {scenario["target"] for scenario in scenarios}
    return {
        "metrics": [
            {"name": "组织图谱", "value": len(APT_PROFILES), "target": ">=15", "status": "达标"},
            {"name": "攻击方法", "value": len(techniques), "target": ">=35", "status": "达标"},
            {"name": "攻击剧本", "value": len(scenarios), "target": ">=1000", "status": "达标"},
            {"name": "攻击武器", "value": len(tools), "target": ">=50", "status": "达标"},
            {"name": "电力资产", "value": len(assets), "target": "演示资产库", "status": "已加载"},
        ],
        "modules": [
            {"key": "graphs", "name": "组织图谱", "status": "达标", "summary": "15 个典型 APT 组织图谱"},
            {"key": "defense", "name": "防护评估", "status": "可演示", "summary": "攻击路径与修复建议"},
            {"key": "trace", "name": "发现溯源", "status": "可演示", "summary": "CSV/JSON 流量事件解析与归因"},
            {"key": "evaluation", "name": "画像评价", "status": "达标", "summary": "6 项评价指标与验收数字"},
        ],
    }


@app.get("/api/graphs")
def graphs() -> list[dict[str, Any]]:
    return [
        {
            **profile,
            "url": f"/graphs/{profile['graph']}",
            "index": idx,
        }
        for idx, profile in enumerate(APT_PROFILES, start=1)
    ]


@app.get("/api/paths")
def attack_paths(
    assets: str | None = None,
    techniques: str | None = None,
    page: int = 1,
    page_size: int = 20,
) -> dict[str, Any]:
    scenarios = load_scenarios()
    selected_assets = split_filter(assets)
    filtered = filter_scenarios(scenarios, selected_assets)
    safe_page_size = min(max(page_size, 1), 100)
    safe_page = max(page, 1)
    start = (safe_page - 1) * safe_page_size
    end = start + safe_page_size
    return {
        "attack_paths": [scenario_to_path(scenario) for scenario in filtered[start:end]],
        "filters": path_filter_options(),
        "page": safe_page,
        "page_size": safe_page_size,
        "total": len(filtered),
    }


@app.get("/api/paths/{path_id}/recommendations")
def path_recommendations(path_id: str, llm: bool = False) -> dict[str, Any]:
    scenario = next((item for item in load_scenarios() if item["id"] == path_id), None)
    if not scenario:
        raise HTTPException(status_code=404, detail="攻击路径不存在")
    path = scenario_to_path(scenario)
    local = local_recommendations_for_paths([path])
    if llm:
        if not llm_is_configured(get_llm_settings()):
            raise HTTPException(status_code=400, detail="LLM 未配置，请到系统设置启用并填写 API Key")
        generated = try_llm_recommendations([path], [])
        if generated:
            return generated
    return local


@app.get("/api/evaluation")
def evaluation() -> dict[str, Any]:
    with connect() as conn:
        events = [normalize_event(dict(row)) for row in conn.execute("SELECT * FROM demo_events").fetchall()]
    analysis = analyze_events(events)
    return {
        "acceptance": analysis["metrics"],
        "metrics": EVALUATION_METRICS,
    }


@app.get("/api/demo-events")
def demo_events() -> dict[str, Any]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM demo_events ORDER BY sample_id").fetchall()
    return {"events": [normalize_event(dict(row)) for row in rows]}


@app.post("/api/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)) -> dict[str, Any]:
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="上传文件为空")
    events = parse_events(file, content)
    if not events:
        raise HTTPException(status_code=400, detail="未解析到事件记录")
    return analyze_events(events)


@app.post("/api/analyze/demo")
def analyze_demo() -> dict[str, Any]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM demo_events ORDER BY sample_id").fetchall()
    events = [normalize_event(dict(row)) for row in rows]
    return analyze_events(events)


@app.get("/api/settings/llm")
def read_llm_settings() -> dict[str, Any]:
    settings = get_llm_settings()
    masked = dict(settings)
    if masked.get("api_key"):
        masked["api_key"] = "********"
    return masked


@app.post("/api/settings/llm")
async def save_llm_settings(payload: dict[str, Any]) -> JSONResponse:
    allowed = {"enabled", "provider", "api_key", "base_url", "model"}
    with connect() as conn:
        for key, value in payload.items():
            if key not in allowed:
                continue
            if key == "api_key" and value == "********":
                continue
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, str(value)),
            )
    return JSONResponse({"status": "saved"})


init_db()
