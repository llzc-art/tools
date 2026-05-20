<template>
  <div class="tool-panel">
    <h2>Ping 测试</h2>
    <div class="card">
      <div class="form-group">
        <label>IP 地址列表（每行一个）</label>
        <textarea v-model="ips" rows="6" placeholder="192.168.1.1&#10;10.0.0.1&#10;8.8.8.8" class="input-field" style="font-family: monospace;"></textarea>
      </div>
      <div class="form-row">
        <div class="form-group" style="flex:1">
          <label>Ping 次数</label>
          <select v-model="count" class="input-field">
            <option :value="1">1 次</option>
            <option :value="3">3 次</option>
            <option :value="5">5 次</option>
          </select>
        </div>
        <div class="form-group" style="flex:1">
          <label>超时（秒）</label>
          <select v-model="timeout" class="input-field">
            <option :value="3">3 秒</option>
            <option :value="5">5 秒</option>
            <option :value="10">10 秒</option>
          </select>
        </div>
      </div>
      <div class="btn-group">
        <button @click="startPing" class="btn btn-primary" :disabled="loading">
          {{ loading ? '测试中...' : '开始测试' }}
        </button>
        <button @click="clear" class="btn btn-secondary" :disabled="loading">清空</button>
      </div>

      <div v-if="results.length" class="result-section">
        <div class="result-header">
          <span>测试结果</span>
          <span class="result-summary">
            成功 <span class="status-ok">{{ successCount }}</span> /
            失败 <span class="status-fail">{{ failCount }}</span> /
            共 {{ results.length }} 个
          </span>
        </div>
        <div class="ping-results">
          <div v-for="(r, i) in results" :key="i" :class="['ping-item', r.alive ? 'ping-ok' : 'ping-fail']">
            <div class="ping-item-header">
              <span :class="['ping-status', r.alive ? 'dot-ok' : 'dot-fail']">●</span>
              <span class="ping-ip">{{ r.ip }}</span>
              <span class="ping-latency" v-if="r.alive && r.latency">{{ r.latency }}</span>
              <span class="ping-label" :class="r.alive ? 'label-ok' : 'label-fail'">{{ r.alive ? '可达' : '不可达' }}</span>
            </div>
            <div v-if="r.error" class="ping-error">{{ r.error }}</div>
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

const ips = ref('')
const count = ref(3)
const timeout = ref(5)
const loading = ref(false)
const results = ref([])

const successCount = computed(() => results.value.filter(r => r.alive).length)
const failCount = computed(() => results.value.filter(r => !r.alive).length)

async function startPing() {
  if (!ips.value.trim()) {
    showToast('请输入 IP 地址')
    return
  }
  loading.value = true
  results.value = []
  try {
    const res = await apiPost('/api/network/ping', {
      ips: ips.value,
      count: count.value,
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
  ips.value = ''
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
.ping-results {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}
.ping-item {
  padding: 0.6rem 0.8rem;
  border-radius: 6px;
  border: 1px solid var(--border);
}
.ping-ok {
  background: #f0fdf4;
  border-color: #bbf7d0;
}
.ping-fail {
  background: #fef2f2;
  border-color: #fecaca;
}
.ping-item-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.ping-status {
  font-size: 0.7rem;
}
.dot-ok { color: #16a34a; }
.dot-fail { color: #dc2626; }
.ping-ip {
  font-weight: 600;
  font-family: monospace;
  font-size: 0.88rem;
}
.ping-latency {
  color: #16a34a;
  font-size: 0.82rem;
  font-family: monospace;
}
.ping-label {
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
.ping-error {
  margin-top: 0.3rem;
  font-size: 0.78rem;
  color: #dc2626;
  padding-left: 1.2rem;
}
.form-row {
  display: flex;
  gap: 1rem;
}
</style>
