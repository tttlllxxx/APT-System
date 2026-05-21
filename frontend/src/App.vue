<template>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">APT</div>
        <div>
          <h1>攻击画像原型</h1>
        </div>
      </div>

      <nav class="module-nav">
        <button
          v-for="module in modules"
          :key="module.key"
          :class="{ active: activeModule === module.key }"
          @click="activeModule = module.key"
        >
          <span>{{ module.name }}</span>
        </button>
      </nav>
    </aside>

    <main class="content">
      <header class="topbar">
        <div>
          <h2>{{ currentModuleTitle }}</h2>
        </div>
        <button class="settings-button" :class="{ active: activeModule === 'settings' }" @click="openSettings">
          系统设置
        </button>
      </header>

      <section v-if="activeModule !== 'settings'" class="metric-strip">
        <div v-for="metric in visibleOverviewMetrics" :key="metric.name" class="metric-cell">
          <span>{{ metric.name }}</span>
          <strong>{{ metric.value }}</strong>
        </div>
      </section>

      <section v-if="activeModule === 'graphs'" class="module-body graph-layout">
        <div class="graph-list">
          <button
            v-for="graph in graphs"
            :key="graph.id"
            :class="{ active: selectedGraph?.id === graph.id }"
            @click="selectedGraph = graph"
          >
            <strong>{{ String(graph.index).padStart(2, '0') }}</strong>
            <span>{{ graph.name }}</span>
          </button>
        </div>
        <div class="graph-frame-wrap">
          <iframe v-if="selectedGraph" :src="selectedGraph.url" title="APT 组织图谱"></iframe>
        </div>
      </section>

      <section v-if="activeModule === 'defense'" class="module-body defense-layout">
        <div class="panel path-browser">
          <div class="panel-head path-browser-head">
            <div>
              <h3>攻击路径</h3>
              <p>按资产场景域浏览剧本库</p>
            </div>
          </div>

          <div class="filter-section">
            <div class="section-title">
              <span>资产域筛选</span>
              <em>{{ assetFilterSummary }}</em>
            </div>
            <div class="asset-filter-chips" aria-label="资产域筛选">
              <button
                v-for="asset in defense.filters.assets"
                :key="asset"
                class="asset-chip"
                :class="{ active: isAssetSelected(asset) }"
                @click="toggleAssetFilter(asset)"
              >
                {{ asset }}
              </button>
            </div>
            <button class="small clear-filter" :disabled="!selectedAssets.length" @click="clearPathFilters">
              清空筛选
            </button>
          </div>

          <div class="path-list-head">
            <span>路径列表</span>
            <em>共 {{ defense.total }} 条路径</em>
          </div>

          <div class="path-list">
            <button
              v-for="path in defense.attack_paths"
              :key="path.id"
              class="path-row"
              :class="{ active: selectedPath?.id === path.id }"
              @click="selectAttackPath(path)"
            >
              <strong class="path-id">{{ path.id }}</strong>
              <span class="path-target">{{ path.target }}</span>
              <em class="path-scenario">{{ path.scenario }}</em>
            </button>
          </div>

          <div class="pager">
            <button class="small" :disabled="defense.page <= 1" @click="changePathPage(defense.page - 1)">
              上一页
            </button>
            <span>{{ defense.page }} / {{ totalPathPages }}</span>
            <button
              class="small"
              :disabled="defense.page >= totalPathPages"
              @click="changePathPage(defense.page + 1)"
            >
              下一页
            </button>
          </div>
        </div>

        <div class="panel path-detail">
          <template v-if="selectedPath">
            <div class="panel-head path-detail-head">
              <div class="path-copy">
                <h3>{{ selectedPath.target }}</h3>
                <p>{{ selectedPath.scenario }}</p>
              </div>
              <div class="llm-action">
                <button class="small" @click="loadPathRecommendations(true)" :disabled="recommendationsLoading">
                  LLM 增强
                </button>
                <p v-if="llmNotice" class="inline-alert">{{ llmNotice }}</p>
              </div>
            </div>

            <ol class="stage-list">
              <li v-for="step in selectedPath.steps" :key="`${selectedPath.id}-${step.stage}-${step.technique}`">
                <b>{{ step.stage }}</b>
                <span>{{ step.technique }}</span>
                <em>{{ step.tool }}</em>
                <p>{{ step.description }}</p>
              </li>
            </ol>

            <div class="impact-block">
              <strong>影响</strong>
              <p>{{ selectedPath.impact }}</p>
            </div>

            <div class="advice-head">
              <h3>资产修复与防护建议</h3>
              <span class="source-tag">{{ pathRecommendations.source || '本地规则库' }}</span>
            </div>
            <article v-for="item in pathRecommendations.items" :key="item.title" class="advice-item">
              <h4>{{ item.title }}</h4>
              <p>{{ item.detail }}</p>
            </article>
          </template>
          <div v-else class="empty-state">
            <h3>选择一条攻击路径</h3>
            <p>点击左侧路径后查看阶段详情、影响范围和对应的资产修复与防护建议。</p>
          </div>
        </div>
      </section>

      <section v-if="activeModule === 'trace'" class="module-body trace-layout">
        <div class="panel upload-panel">
          <h3>流量事件输入</h3>
          <div class="upload-box">
            <input ref="fileInput" type="file" accept=".csv,.json,.pcap" @change="handleFileChange" />
            <button class="primary" @click="uploadSelectedFile">上传并分析</button>
            <button @click="runDemoAnalysis">使用内置样本</button>
          </div>
        </div>

        <div class="analysis-grid" v-if="analysis">
          <div class="panel score-panel">
            <h3>识别结果</h3>
            <div class="score-row">
              <span>总样本</span><strong>{{ analysis.total }}</strong>
            </div>
            <div class="score-row">
              <span>APT 命中</span><strong>{{ analysis.apt_count }}</strong>
            </div>
            <div class="score-row">
              <span>发现准确度</span><strong>{{ formatMetric(analysis.metrics.discovery_accuracy) }}</strong>
            </div>
            <div class="score-row">
              <span>画像成功率</span><strong>{{ formatMetric(analysis.metrics.profiling_success_rate) }}</strong>
            </div>
          </div>

          <div class="panel evidence-panel">
            <h3>溯源证据链</h3>
            <article v-for="result in analysis.top_results" :key="result.sample_id" class="evidence-item">
              <div>
                <strong>{{ result.sample_id }}</strong>
                <span>{{ result.predicted_apt }} · {{ result.confidence }}%</span>
              </div>
              <p>{{ result.matched_scenario?.scenario }}</p>
              <ul>
                <li v-for="item in result.evidence" :key="`${result.sample_id}-${item.field}-${item.value}`">
                  {{ item.field }}={{ item.value }} 命中 {{ item.match }}
                </li>
              </ul>
            </article>
          </div>
        </div>
      </section>

      <section v-if="activeModule === 'evaluation'" class="module-body evaluation-layout">
        <div class="panel acceptance-panel">
          <h3>识别概览</h3>
          <div class="acceptance-grid">
            <div>
              <span>APT 攻击发现准确度</span>
              <strong>{{ formatMetric(evaluation.acceptance?.discovery_accuracy) }}</strong>
            </div>
            <div>
              <span>APT 组织画像成功率</span>
              <strong>{{ formatMetric(evaluation.acceptance?.profiling_success_rate) }}</strong>
            </div>
          </div>
        </div>
        <div class="panel">
          <h3>画像评价体系</h3>
          <div class="metric-table">
            <div class="metric-row header">
              <span>指标</span><span>定义</span><span>演示值</span>
            </div>
            <div v-for="metric in evaluation.metrics" :key="metric.code" class="metric-row">
              <span>{{ metric.name }} / {{ metric.code }}</span>
              <span>{{ metric.definition }}</span>
              <strong>{{ metric.score }}{{ metric.unit || '%' }}</strong>
            </div>
          </div>
        </div>
      </section>

      <section v-if="activeModule === 'settings'" class="module-body settings-layout">
        <div class="settings-menu">
          <button :class="{ active: activeSettingsPanel === 'llm' }" @click="activeSettingsPanel = 'llm'">
            LLM 设置
          </button>
        </div>
        <div v-if="activeSettingsPanel === 'llm'" class="panel settings-content">
          <h3>LLM 设置</h3>
          <div class="settings-form">
            <label class="checkbox-row">
              <input type="checkbox" v-model="llmForm.enabled" />
              <span>启用增强</span>
            </label>
            <label>
              <span>Provider</span>
              <input v-model="llmForm.provider" />
            </label>
            <label>
              <span>Base URL</span>
              <input v-model="llmForm.base_url" />
            </label>
            <label>
              <span>Model</span>
              <input v-model="llmForm.model" />
            </label>
            <label>
              <span>API Key</span>
              <input v-model="llmForm.api_key" type="password" placeholder="DeepSeek API Key" />
            </label>
            <button class="primary small" @click="saveLlmSettings">保存设置</button>
            <p class="hint">无 Key 或调用失败时使用本地规则库。</p>
          </div>
        </div>
        <div v-else class="panel settings-empty">
          <h3>选择设置项</h3>
          <p>点击左侧设置项后查看和编辑对应配置。</p>
        </div>
      </section>
    </main>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'

const activeModule = ref('graphs')
const activeSettingsPanel = ref(null)
const overview = ref({ modules: [], metrics: [] })
const graphs = ref([])
const selectedGraph = ref(null)
const defense = ref({ attack_paths: [], filters: { assets: [] }, page: 1, page_size: 20, total: 0 })
const selectedAssets = ref([])
const selectedPath = ref(null)
const pathRecommendations = ref({ source: '', items: [] })
const recommendationsLoading = ref(false)
const llmNotice = ref('')
const analysis = ref(null)
const evaluation = ref({ acceptance: {}, metrics: [] })
const selectedFile = ref(null)
const llmForm = ref({
  enabled: false,
  provider: 'deepseek',
  base_url: 'https://api.deepseek.com',
  model: 'deepseek-chat',
  api_key: ''
})

const defaultModules = [
  { key: 'graphs', name: '组织图谱', summary: '' },
  { key: 'defense', name: '防护评估', summary: '' },
  { key: 'trace', name: '发现溯源', summary: '' },
  { key: 'evaluation', name: '画像评价', summary: '' }
]
const modules = computed(() => {
  if (!overview.value.modules.length) return defaultModules
  return overview.value.modules.map(({ key, name, summary }) => ({ key, name, summary }))
})
const currentModuleTitle = computed(() => {
  if (activeModule.value === 'settings') return '系统设置'
  return modules.value.find(item => item.key === activeModule.value)?.name || ''
})
const visibleOverviewMetrics = computed(() => (
  overview.value.metrics || []
).filter(metric => metric.name !== '电力资产'))
const totalPathPages = computed(() => Math.max(1, Math.ceil(defense.value.total / defense.value.page_size)))
const assetFilterSummary = computed(() => {
  const scope = selectedAssets.value.length ? `已选 ${selectedAssets.value.length} 个资产域` : '全部资产域'
  return `${scope} / 共 ${defense.value.total} 条路径`
})
const llmConfigured = computed(() => (
  llmForm.value.enabled && Boolean(llmForm.value.api_key)
))

async function api(path, options) {
  const response = await fetch(path, options)
  if (!response.ok) {
    const error = await response.json().catch(() => ({}))
    throw new Error(error.detail || `请求失败：${response.status}`)
  }
  return response.json()
}

async function loadBaseData() {
  overview.value = await api('/api/overview')
  graphs.value = await api('/api/graphs')
  selectedGraph.value = graphs.value[0]
}

function defenseQuery(page = defense.value.page) {
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(defense.value.page_size)
  })
  if (selectedAssets.value.length) params.set('assets', selectedAssets.value.join(','))
  return params.toString()
}

async function loadDefense(page = defense.value.page) {
  defense.value = await api(`/api/paths?${defenseQuery(page)}`)
}

async function applyPathFilters() {
  selectedPath.value = null
  pathRecommendations.value = { source: '', items: [] }
  llmNotice.value = ''
  await loadDefense(1)
}

function isAssetSelected(asset) {
  return selectedAssets.value.includes(asset)
}

async function toggleAssetFilter(asset) {
  if (isAssetSelected(asset)) {
    selectedAssets.value = selectedAssets.value.filter(item => item !== asset)
  } else {
    selectedAssets.value = [...selectedAssets.value, asset]
  }
  await applyPathFilters()
}

async function clearPathFilters() {
  selectedAssets.value = []
  await applyPathFilters()
}

async function changePathPage(page) {
  selectedPath.value = null
  pathRecommendations.value = { source: '', items: [] }
  llmNotice.value = ''
  await loadDefense(page)
}

async function selectAttackPath(path) {
  selectedPath.value = path
  llmNotice.value = ''
  await loadPathRecommendations(false)
}

async function loadPathRecommendations(useLlm) {
  if (!selectedPath.value) return
  if (useLlm && !llmConfigured.value) {
    llmNotice.value = 'LLM 未配置，请到系统设置启用并填写 API Key。'
    return
  }
  recommendationsLoading.value = true
  try {
    llmNotice.value = ''
    pathRecommendations.value = await api(`/api/paths/${selectedPath.value.id}/recommendations?llm=${useLlm ? 'true' : 'false'}`)
  } catch (error) {
    if (useLlm && error.message.includes('LLM 未配置')) {
      llmNotice.value = error.message
      return
    }
    throw error
  } finally {
    recommendationsLoading.value = false
  }
}

async function loadEvaluation() {
  evaluation.value = await api('/api/evaluation')
}

async function loadLlmSettings() {
  const settings = await api('/api/settings/llm')
  llmForm.value = {
    enabled: settings.enabled === 'true' || settings.enabled === true,
    provider: settings.provider || 'deepseek',
    base_url: settings.base_url || 'https://api.deepseek.com',
    model: settings.model || 'deepseek-chat',
    api_key: settings.api_key || ''
  }
}

async function saveLlmSettings() {
  await api('/api/settings/llm', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ...llmForm.value,
      enabled: llmForm.value.enabled ? 'true' : 'false'
    })
  })
}

function openSettings() {
  activeModule.value = 'settings'
  activeSettingsPanel.value = null
}

function handleFileChange(event) {
  selectedFile.value = event.target.files?.[0] || null
}

async function uploadSelectedFile() {
  if (!selectedFile.value) return
  const formData = new FormData()
  formData.append('file', selectedFile.value)
  analysis.value = await api('/api/analyze/upload', {
    method: 'POST',
    body: formData
  })
}

async function runDemoAnalysis() {
  analysis.value = await api('/api/analyze/demo', { method: 'POST' })
}

function formatMetric(value) {
  if (value === null || value === undefined) return '-'
  return `${value}%`
}

onMounted(async () => {
  await loadBaseData()
  await Promise.all([loadDefense(), loadEvaluation(), loadLlmSettings()])
})
</script>
