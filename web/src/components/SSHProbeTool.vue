<template>
  <div class="tool-panel">
    <h2>SSH 连通性探测</h2>
    <div class="card">
      <div class="form-row">
        <div class="form-group" style="flex:2">
          <label>主机地址</label>
          <input v-model="host" placeholder="如: 192.168.1.1 或 example.com" class="input-field" />
        </div>
        <div class="form-group" style="flex:1">
          <label>SSH 端口</label>
          <input v-model.number="port" type="number" placeholder="22" class="input-field" />
        </div>
        <div class="form-group" style="flex:1">
          <label>超时（秒）</label>
          <select v-model="timeout" class="input-field">
            <option :value="5">5 秒</option>
            <option :value="10">10 秒</option>
            <option :value="15">15 秒</option>
            <option :value="30">30 秒</option>
          </select>
        </div>
      </div>

      <div class="form-group">
        <label>认证方式</label>
        <div class="auth-tabs">
          <button :class="['auth-tab', authType === 'password' ? 'active' : '']" @click="authType = 'password'">密码认证</button>
          <button :class="['auth-tab', authType === 'key' ? 'active' : '']" @click="authType = 'key'">密钥认证</button>
        </div>
      </div>

      <template v-if="authType === 'password'">
        <div class="form-row">
          <div class="form-group" style="flex:1">
            <label>用户名</label>
            <input v-model="username" placeholder="root" class="input-field" />
          </div>
          <div class="form-group" style="flex:1">
            <label>密码</label>
            <input v-model="password" type="password" placeholder="输入密码" class="input-field" />
          </div>
        </div>
      </template>

      <template v-if="authType === 'key'">
        <div class="form-group">
          <label>用户名</label>
          <input v-model="username" placeholder="root" class="input-field" style="max-width:300px" />
        </div>
        <div class="form-group">
          <label>SSH 私钥</label>
          <textarea v-model="privateKey" rows="6" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;...&#10;-----END OPENSSH PRIVATE KEY-----" class="input-field" style="font-family: monospace; font-size: 0.8rem;"></textarea>
        </div>
      </template>

      <div class="btn-group">
        <button @click="startProbe" class="btn btn-primary" :disabled="loading">
          {{ loading ? '探测中...' : '开始探测' }}
        </button>
      </div>

      <div v-if="result" class="result-section">
        <div class="result-header">探测结果</div>
        <div :class="['ssh-result-card', result.reachable ? 'ssh-ok' : 'ssh-fail']">
          <div class="ssh-main">
            <span :class="['ssh-status-dot', result.reachable ? 'dot-ok' : 'dot-fail']">●</span>
            <span class="ssh-host">{{ result.host }}:{{ result.port }}</span>
            <span class="ssh-label" :class="result.reachable ? 'label-ok' : 'label-fail'">
              {{ result.reachable ? '端口可达' : '端口不可达' }}
            </span>
          </div>

          <div v-if="result.banner" class="ssh-detail">
            <span class="ssh-detail-key">SSH Banner:</span>
            <span class="ssh-detail-val">{{ result.banner }}</span>
          </div>

          <template v-if="result.reachable && authType !== 'none'">
            <div class="ssh-detail">
              <span class="ssh-detail-key">认证结果:</span>
              <span :class="result.auth_ok ? 'label-ok' : 'label-fail'" class="ssh-auth-label">
                {{ result.auth_ok ? '认证成功' : '认证失败' }}
              </span>
            </div>
          </template>

          <div v-if="result.error" class="ssh-error">
            {{ result.error }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'
import { apiPost } from '../api.js'

const showToast = inject('showToast')

const host = ref('')
const port = ref(22)
const timeout = ref(10)
const authType = ref('password')
const username = ref('')
const password = ref('')
const privateKey = ref('')
const loading = ref(false)
const result = ref(null)

async function startProbe() {
  if (!host.value.trim()) {
    showToast('请输入主机地址')
    return
  }
  if (authType.value === 'password' && !username.value) {
    showToast('请输入用户名')
    return
  }
  if (authType.value === 'key' && !username.value) {
    showToast('请输入用户名')
    return
  }
  if (authType.value === 'key' && !privateKey.value.trim()) {
    showToast('请输入 SSH 私钥')
    return
  }

  loading.value = true
  result.value = null
  try {
    const body = {
      host: host.value,
      port: port.value || 22,
      timeout: timeout.value,
    }
    if (authType.value !== 'none') {
      body.username = username.value
      body.auth_type = authType.value
    }
    if (authType.value === 'password') {
      body.password = password.value
    }
    if (authType.value === 'key') {
      body.private_key = privateKey.value
    }

    const res = await apiPost('/api/network/ssh-probe', body)
    if (res.code === 0) {
      result.value = res.data
    } else {
      showToast(res.message)
    }
  } catch (e) {
    showToast('请求失败')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.form-row {
  display: flex;
  gap: 1rem;
}
.auth-tabs {
  display: flex;
  gap: 0.4rem;
}
.auth-tab {
  padding: 0.4rem 0.8rem;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: white;
  cursor: pointer;
  font-size: 0.82rem;
  transition: all 0.15s;
}
.auth-tab:hover {
  border-color: var(--primary);
  color: var(--primary);
}
.auth-tab.active {
  background: var(--primary);
  color: white;
  border-color: var(--primary);
}
.result-section {
  margin-top: 1rem;
}
.result-header {
  font-weight: 600;
  font-size: 0.9rem;
  margin-bottom: 0.6rem;
}
.ssh-result-card {
  padding: 1rem;
  border-radius: 8px;
  border: 1px solid var(--border);
}
.ssh-ok {
  background: #f0fdf4;
  border-color: #bbf7d0;
}
.ssh-fail {
  background: #fef2f2;
  border-color: #fecaca;
}
.ssh-main {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.ssh-status-dot {
  font-size: 0.8rem;
}
.dot-ok { color: #16a34a; }
.dot-fail { color: #dc2626; }
.ssh-host {
  font-weight: 700;
  font-family: monospace;
  font-size: 0.95rem;
}
.ssh-label {
  margin-left: auto;
  font-size: 0.78rem;
  font-weight: 600;
  padding: 0.15rem 0.6rem;
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
.ssh-detail {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 0.6rem;
  font-size: 0.85rem;
}
.ssh-detail-key {
  color: var(--text-secondary);
  min-width: 80px;
}
.ssh-detail-val {
  font-family: monospace;
  color: var(--text);
  word-break: break-all;
}
.ssh-auth-label {
  font-weight: 600;
}
.ssh-error {
  margin-top: 0.6rem;
  font-size: 0.82rem;
  color: #dc2626;
  padding: 0.4rem 0.6rem;
  background: #fff1f2;
  border-radius: 4px;
}
</style>
