<template>
  <div class="tool-panel">
    <h2>IP 查询 / CIDR 计算</h2>
    <div class="card">
      <div class="form-group">
        <label>输入 IP 地址或 CIDR</label>
        <input v-model="input" placeholder="如: 192.168.1.1 或 192.168.1.0/24" class="input-field" />
      </div>
      <div class="btn-group">
        <button @click="lookup" class="btn btn-primary">IP 查询</button>
        <button @click="cidr" class="btn btn-secondary">CIDR 计算</button>
      </div>
      <div v-if="result" class="result-box">
        <div class="result-label">{{ resultLabel }}</div>
        <div class="parsed-info">
          <div v-for="(v, k) in result" :key="k" class="parsed-row">
            <span class="parsed-key">{{ k }}:</span>
            <span class="parsed-val" @click="copy(String(v))">{{ v }}</span>
          </div>
        </div>
        <div class="result-hint">点击值可复制</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'
import { apiPost, copyToClipboard } from '../api.js'

const showToast = inject('showToast')

function copy(text) {
  copyToClipboard(text).then(ok => showToast(ok ? '已复制到剪贴板' : '复制失败'))
}

const input = ref('')
const result = ref(null)
const resultLabel = ref('')

async function lookup() {
  const res = await apiPost('/api/ip/lookup', { ip: input.value })
  if (res.code === 0) {
    const d = res.data
    result.value = {
      'IP 地址': d.ip,
      '版本': d.version,
      'IPv4': d.is_ipv4 ? '是' : '否',
      'IPv6': d.is_ipv6 ? '是' : '否',
    }
    resultLabel.value = 'IP 查询结果'
  } else showToast(res.message)
}

async function cidr() {
  const res = await apiPost('/api/ip/cidr', { cidr: input.value })
  if (res.code === 0) {
    const d = res.data
    result.value = {
      'CIDR': d.cidr,
      '网络地址': d.network,
      '子网掩码': d.mask,
      '起始 IP': d.first_ip,
      '结束 IP': d.last_ip,
      '可用主机数': d.host_count,
    }
    resultLabel.value = 'CIDR 计算结果'
  } else showToast(res.message)
}
</script>
