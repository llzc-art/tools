<template>
  <div class="tool-panel">
    <h2>🛡️ 非对称加密</h2>
    <div class="card">
      <div class="form-group">
        <label>选择算法</label>
        <div class="algo-group">
          <button
            v-for="a in algos"
            :key="a.id"
            @click="selectAlgo(a.id)"
            :class="['algo-btn', algo === a.id ? 'algo-btn-active' : '']"
          >
            <span class="algo-icon">{{ a.icon }}</span>
            <span class="algo-name">{{ a.name }}</span>
          </button>
        </div>
      </div>

      <!-- Tab: 加密解密 / 签名验签 -->
      <div class="form-group">
        <label>操作</label>
        <div class="algo-group">
          <button
            v-for="t in tabs"
            :key="t.id"
            @click="tab = t.id"
            :class="['algo-btn', tab === t.id ? 'algo-btn-active' : '']"
          >{{ t.name }}</button>
        </div>
      </div>

      <!-- 加密/解密 -->
      <template v-if="tab === 'encrypt' || tab === 'decrypt'">
        <div class="form-group">
          <label>操作类型</label>
          <div class="algo-group">
            <button
              @click="tab = 'encrypt'"
              :class="['algo-btn', tab === 'encrypt' ? 'algo-btn-active' : '']"
            >加密</button>
            <button
              @click="tab = 'decrypt'"
              :class="['algo-btn', tab === 'decrypt' ? 'algo-btn-active' : '']"
            >解密</button>
          </div>
        </div>

        <div v-if="algo === 'rsa'" class="form-group">
          <label>填充模式</label>
          <div class="algo-group">
            <button
              v-for="p in encryptPaddings"
              :key="p.id"
              @click="encPadding = p.id"
              :class="['algo-btn', encPadding === p.id ? 'algo-btn-active' : '']"
            >{{ p.name }}</button>
          </div>
        </div>

        <div class="form-group">
          <label>{{ tab === 'encrypt' ? '明文' : '密文 (Hex)' }}</label>
          <textarea
            v-model="input"
            :placeholder="tab === 'encrypt' ? '输入要加密的明文' : '输入要解密的密文(Hex格式)'"
            class="input-textarea"
            rows="3"
          ></textarea>
        </div>

        <div class="form-group">
          <label>{{ tab === 'encrypt' ? '公钥 (PEM)' : '私钥 (PEM)' }}</label>
          <textarea
            v-model="pemKey"
            :placeholder="tab === 'encrypt' ? '粘贴公钥 PEM' : '粘贴私钥 PEM'"
            class="input-textarea mono"
            rows="5"
          ></textarea>
        </div>

        <button @click="doCrypt" class="btn btn-primary" :disabled="!input.trim() || !pemKey.trim()">
          {{ tab === 'encrypt' ? '加密' : '解密' }}
        </button>

        <div v-if="cryptOutput" class="result-box">
          <div class="result-label">{{ tab === 'encrypt' ? '密文' : '明文' }}</div>
          <div class="result-value" @click="copy(cryptOutput)">{{ cryptOutput }}</div>
          <div class="result-hint">点击复制</div>
        </div>
      </template>

      <!-- 签名/验签 -->
      <template v-if="tab === 'sign' || tab === 'verify'">
        <div class="form-group">
          <label>操作类型</label>
          <div class="algo-group">
            <button
              @click="tab = 'sign'"
              :class="['algo-btn', tab === 'sign' ? 'algo-btn-active' : '']"
            >签名</button>
            <button
              @click="tab = 'verify'"
              :class="['algo-btn', tab === 'verify' ? 'algo-btn-active' : '']"
            >验签</button>
          </div>
        </div>

        <div v-if="algo === 'rsa'" class="form-group">
          <label>签名填充</label>
          <div class="algo-group">
            <button
              v-for="p in signPaddings"
              :key="p.id"
              @click="signPadding = p.id"
              :class="['algo-btn', signPadding === p.id ? 'algo-btn-active' : '']"
            >{{ p.name }}</button>
          </div>
        </div>

        <div class="form-group">
          <label>原文</label>
          <textarea v-model="input" placeholder="输入要签名/验签的原文" class="input-textarea" rows="3"></textarea>
        </div>

        <div class="form-group" v-if="tab === 'sign'">
          <label>私钥 (PEM)</label>
          <textarea v-model="pemKey" placeholder="粘贴私钥 PEM" class="input-textarea mono" rows="5"></textarea>
        </div>

        <div class="form-group" v-if="tab === 'verify'">
          <label>公钥 (PEM)</label>
          <textarea v-model="pemKey" placeholder="粘贴公钥 PEM" class="input-textarea mono" rows="5"></textarea>
        </div>

        <div class="form-group" v-if="tab === 'verify'">
          <label>签名 (Hex)</label>
          <textarea v-model="signature" placeholder="输入签名(Hex格式)" class="input-textarea" rows="2"></textarea>
        </div>

        <button
          @click="doSign"
          class="btn btn-primary"
          :disabled="!input.trim() || !pemKey.trim() || (tab === 'verify' && !signature.trim())"
        >
          {{ tab === 'sign' ? '签名' : '验签' }}
        </button>

        <div v-if="signOutput" class="result-box">
          <div class="result-label">签名结果</div>
          <div class="result-value" @click="copy(signOutput)">{{ signOutput }}</div>
          <div class="result-hint">点击复制</div>
        </div>

        <div v-if="verifyResult !== null" class="result-box" :style="{borderColor: verifyResult ? '#22c55e' : '#ef4444'}">
          <div class="result-label">{{ verifyResult ? '验签通过' : '验签失败' }}</div>
          <div class="result-value" :style="{color: verifyResult ? '#22c55e' : '#ef4444'}">{{ verifyResult ? '签名有效' : '签名无效' }}</div>
        </div>
      </template>
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

const algo = ref('rsa')
const tab = ref('encrypt')
const input = ref('')
const pemKey = ref('')
const signature = ref('')
const cryptOutput = ref('')
const signOutput = ref('')
const verifyResult = ref(null)
const encPadding = ref('pkcs1v15')
const signPadding = ref('pkcs1v15')

const algos = [
  { id: 'rsa', name: 'RSA', icon: '🔐' },
  { id: 'sm2', name: 'SM2', icon: '🇨🇳' },
]

const encryptPaddings = [
  { id: 'pkcs1v15', name: 'PKCS1v15' },
  { id: 'oaep', name: 'OAEP' },
]

const signPaddings = [
  { id: 'pkcs1v15', name: 'PKCS1v15' },
  { id: 'pss', name: 'PSS' },
]

const tabs = [
  { id: 'encrypt', name: '加密' },
  { id: 'decrypt', name: '解密' },
  { id: 'sign', name: '签名' },
  { id: 'verify', name: '验签' },
]

function selectAlgo(id) {
  algo.value = id
  cryptOutput.value = ''
  signOutput.value = ''
  verifyResult.value = null
}

async function doCrypt() {
  const endpoint = tab.value === 'encrypt' ? '/api/asymmetric/encrypt' : '/api/asymmetric/decrypt'
  const res = await apiPost(endpoint, { algo: algo.value, input: input.value, key: pemKey.value, padding: encPadding.value })
  if (res.code === 0) cryptOutput.value = res.data.output
  else showToast(res.message)
}

async function doSign() {
  if (tab.value === 'sign') {
    const res = await apiPost('/api/asymmetric/sign', { algo: algo.value, input: input.value, key: pemKey.value, padding: signPadding.value })
    if (res.code === 0) {
      signOutput.value = res.data.signature
      verifyResult.value = null
    } else showToast(res.message)
  } else {
    const res = await apiPost('/api/asymmetric/verify', { algo: algo.value, input: input.value, signature: signature.value, key: pemKey.value, padding: signPadding.value })
    if (res.code === 0) {
      verifyResult.value = res.data.valid
      signOutput.value = ''
    } else showToast(res.message)
  }
}
</script>

<style scoped>
.algo-group {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.algo-btn {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.5rem 1rem;
  border: 1.5px solid var(--border);
  border-radius: 8px;
  background: white;
  cursor: pointer;
  font-size: 0.875rem;
  color: var(--text);
  transition: all 0.2s;
}

.algo-btn:hover {
  border-color: var(--primary);
  color: var(--primary);
  background: #f8f7ff;
}

.algo-btn-active {
  border-color: var(--primary);
  background: var(--primary);
  color: white;
}

.algo-btn-active:hover {
  background: var(--primary-hover, #4338ca);
  color: white;
}

.algo-icon { font-size: 1rem; }
.algo-name { font-weight: 500; }

.key-value {
  white-space: pre-wrap;
  word-break: break-all;
  font-family: monospace;
  font-size: 0.8rem;
  max-height: 200px;
  overflow-y: auto;
}

.mono {
  font-family: monospace;
  font-size: 0.82rem;
}
</style>
