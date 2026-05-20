<template>
  <div class="tool-panel">
    <h2>端口探测</h2>
    <div class="card">
      <div class="form-group">
        <label>地址列表（每行一个 IP:端口）</label>
        <textarea v-model="addresses" rows="6" placeholder="192.168.1.1:22&#10;10.0.0.1:80&#10;8.8.8.8:443" class="input-field" style="font-family: monospace;"></textarea>
      </div>
      <div class="form-group">
        <label>超时（秒）</label>
        <select v-model="timeout" class="input-field" style="max-width:200px">
          <option :value="3">3 秒</option>
          <option :value="5">5 秒</option>
          <option :value="10">10 秒</option>
        </select>
      </div>
      <div class="btn-group">
        <button @click="startProbe" class="btn btn-primary" :disabled="loading">
          {{ loading ? '探测中...' : '开始探测' }}
        </button>
        <button @click="clear" class="btn btn-secondary" :disabled="loading">清空</button>
      </div>

      <div v-if="results.length" class="result-section">
        <div class="result-header">
          <span>探测结果</span>
          <span class="result-summary">
            开放 <span class="status-ok">{{ openCount }}</span> /
            关闭 <span class="status-fail">{{ closeCount }}</span> /
            共 {{ results.length }} 个
          </span>
        </div>
        <div class="probe-results">
          <div v-for="(r, i) in results" :key="i" :class="['probe-item', r.open ? 'probe-ok' : 'probe-fail']">
            <div class="probe-item-header">
              <span :class="['probe-status', r.open ? 'dot-ok' : 'dot-fail']">●</span>
              <span class="probe-addr">{{ r.address }}</span>
              <span class="probe-latency" v-if="r.open && r.latency">{{ r.latency }}</span>
              <span class="probe-label" :class="r.open ? 'label-ok' : 'label-fail'">{{ r.open ? '开放' : '关闭' }}</span>
            </div>
            <div v-if="r.error" class="probe-error">{{ r.error }}</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, inject } from 'vue'
import { apiPost } from '../api.js'

const showToast = inject('showToast')

const addresses = ref('')
const timeout = ref(5)
const loading = ref(false)
const results = ref([])

const openCount = computed(() => results.value.filter(r => r.open).length)
const closeCount = computed(() => results.value.filter(r => !r.open).length)

async function startProbe() {
  if (!addresses.value.trim()) {
    showToast('请输入地址列表')
    return
  }
  loading.value = true
  results.value = []
  try {
    const res = await apiPost('/api/network/port-probe', {
      addresses: addresses.value,
      timeout: timeout.value,
    })
    if (res.code === 0) {
      results.value = res.data || []
    } else {
      showToast(res.message)
    }
  } catch (e) {
    showToast('请求失败')
  } finally {
    loading.value = false
  }
}

function clear() {
  addresses.value = ''
  results.value = []
}
</script>

<style scoped>
.result-section {
  margin-top: 1rem;
}
.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.6rem;
  font-weight: 600;
  font-size: 0.9rem;
}
.result-summary {
  font-weight: 400;
  font-size: 0.82rem;
  color: var(--text-secondary);
}
.status-ok { color: #16a34a; }
.status-fail { color: #dc2626; }
.probe-results {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}
.probe-item {
  padding: 0.6rem 0.8rem;
  border-radius: 6px;
  border: 1px solid var(--border);
}
.probe-ok {
  background: #f0fdf4;
  border-color: #bbf7d0;
}
.probe-fail {
  background: #fef2f2;
  border-color: #fecaca;
}
.probe-item-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.probe-status {
  font-size: 0.7rem;
}
.dot-ok { color: #16a34a; }
.dot-fail { color: #dc2626; }
.probe-addr {
  font-weight: 600;
  font-family: monospace;
  font-size: 0.88rem;
}
.probe-latency {
  color: #16a34a;
  font-size: 0.82rem;
  font-family: monospace;
}
.probe-label {
  margin-left: auto;
  font-size: 0.78rem;
  font-weight: 600;
  padding: 0.1rem 0.5rem;
  border-radius: 4px;
}
.label-ok {
  background: #dcfce7;
  color: #16a34a;
}
.label-fail {
  background: #fee2e2;
  color: #dc2626;
}
.probe-error {
  margin-top: 0.3rem;
  font-size: 0.78rem;
  color: #dc2626;
  padding-left: 1.2rem;
}
</style>
