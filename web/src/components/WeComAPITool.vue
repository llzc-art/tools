<template>
  <div class="tool-panel">
    <h2>企业微信 API 调试</h2>
    <div class="card">
      <div class="section-title">凭证配置</div>
      <div class="auth-grid">
        <div class="auth-field"><span class="auth-label">CorpID（企业ID）</span><input v-model="corpId" class="input-field" placeholder="ww1234567890abcdef" /></div>
        <div class="auth-field"><span class="auth-label">CorpSecret（应用Secret）</span><input v-model="corpSecret" type="password" class="input-field" placeholder="Corp Secret" /></div>
      </div>
      <div class="token-row">
        <button @click="getToken" class="btn btn-outline" :disabled="tokenLoading">{{ tokenLoading ? '获取中...' : '获取 Access Token' }}</button>
        <div v-if="accessToken" class="token-display">
          <input v-model="accessToken" class="input-field token-input" readonly @click="$event.target.select()" />
          <span v-if="tokenExpires" class="token-expire">{{ tokenExpires }}s</span>
        </div>
      </div>

      <div class="section-title" style="margin-top:1.2rem">API 调试</div>
      <div class="form-group"><label>接口</label>
        <select v-model="selectedApiId" @change="onApiChange" class="input-field">
          <option value="">请选择接口</option>
          <optgroup v-for="cat in apiCategories" :key="cat" :label="cat">
            <option v-for="api in getApisByCategory(cat)" :key="api.id" :value="api.id">{{ api.name }}</option>
          </optgroup>
        </select>
      </div>
      <div class="form-row">
        <div class="form-group" style="flex:1;min-width:90px"><label>方法</label>
          <select v-model="method" class="input-field"><option>GET</option><option>POST</option></select>
        </div>
        <div class="form-group" style="flex:5"><label>请求路径</label><input v-model="apiPath" class="input-field" placeholder="/cgi-bin/..." /></div>
      </div>
      <div class="form-group"><label>Query 参数 <span class="hint">(每行 Key=Value)</span></label>
        <textarea v-model="queryParams" rows="3" class="input-field mono" placeholder="department_id=1&#10;fetch_child=1"></textarea>
      </div>
      <div class="form-group"><label>请求体 <span class="hint">(JSON)</span></label>
        <textarea v-model="reqBody" rows="6" class="input-field mono" placeholder='{ "touser": "UserID" }'></textarea>
      </div>
      <div class="btn-group">
        <button @click="sendRequest" class="btn btn-primary" :disabled="loading">{{ loading ? '请求中...' : '发送请求' }}</button>
        <button @click="formatBody" class="btn btn-outline">格式化</button>
      </div>
      <div v-if="resp" class="result-section">
        <div class="result-header"><span>响应结果</span><span :class="['status-badge', resp.status_code<400?'badge-ok':'badge-fail']">{{ resp.status_code }}</span><span class="duration-badge">{{ resp.duration }}ms</span><span class="size-badge">{{ formatSize(resp.size) }}</span></div>
        <pre class="resp-body" v-html="formatJSON(resp.body)"></pre>
      </div>
      <div v-if="error" class="error-msg">{{ error }}</div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { apiGet, apiPost } from '../api.js'

const corpId = ref(''), corpSecret = ref(''), accessToken = ref(''), tokenExpires = ref(0), tokenLoading = ref(false)
const apis = ref([]), selectedApiId = ref(''), method = ref('GET'), apiPath = ref('/cgi-bin/')
const queryParams = ref(''), reqBody = ref(''), loading = ref(false), resp = ref(null), error = ref('')
const BASE_URL = ref('https://qyapi.weixin.qq.com')

const apiCategories = computed(() => [...new Set(apis.value.map(a => a.category))])
function getApisByCategory(cat) { return apis.value.filter(a => a.category === cat) }
async function loadAPIs() { const r = await apiGet('/api/integration/wecom/apis'); if (r.code===0) { const d=r.data; apis.value=d.apis||d; if(d.base_url)BASE_URL.value=d.base_url } }
function onApiChange() { const a = apis.value.find(x=>x.id===selectedApiId.value); if(a){apiPath.value=a.path;method.value=a.method} }

async function getToken() {
  if(!corpId.value||!corpSecret.value){error.value='请填写 CorpID 和 CorpSecret';return}
  tokenLoading.value=true;error.value=''
  try{
    const r=await apiPost('/api/integration/wecom/token',{corp_id:corpId.value,corp_secret:corpSecret.value})
    if(r.code===0&&r.data){const b=JSON.parse(r.data.body||'{}');if(b.access_token){accessToken.value=b.access_token;tokenExpires.value=b.expires_in||0}else{error.value=b.errmsg||'获取Token失败'}}
    else error.value=r.message
  }catch{error.value='请求失败'}finally{tokenLoading.value=false}
}

function buildURL() {
  let url = BASE_URL + apiPath.value
  const params = new URLSearchParams()
  if(accessToken.value) params.set('access_token',accessToken.value)
  if(queryParams.value.trim()) for(const line of queryParams.value.split('\n')){const i=line.indexOf('=');if(i>0)params.set(line.substring(0,i).trim(),line.substring(i+1).trim())}
  const ps=params.toString();if(ps)url+='?'+ps;return url
}

async function sendRequest() {
  loading.value=true;resp.value=null;error.value=''
  try{
    const r=await apiPost('/api/integration/wecom/call',{method:method.value,url:buildURL(),headers:{'Content-Type':'application/json'},body:reqBody.value,timeout:30})
    if(r.code===0)resp.value=r.data;else error.value=r.message
  }catch{error.value='请求失败'}finally{loading.value=false}
}
function formatBody(){try{reqBody.value=JSON.stringify(JSON.parse(reqBody.value),null,2)}catch{}}
function formatJSON(s){try{return escapeHtml(JSON.stringify(JSON.parse(s),null,2))}catch{return escapeHtml(s)}}
function escapeHtml(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function formatSize(b){return b<1024?b+'B':b<1048576?(b/1024).toFixed(1)+'KB':(b/1048576).toFixed(1)+'MB'}
onMounted(()=>loadAPIs())
</script>

<style scoped>
.auth-grid{display:grid;grid-template-columns:1fr 1fr;gap:.8rem}
.auth-field{display:flex;flex-direction:column;gap:.3rem}
.auth-label{font-size:.78rem;color:var(--text-secondary);font-weight:500}
.section-title{font-size:.88rem;font-weight:600;margin-bottom:.5rem;color:var(--text)}
.token-row{display:flex;align-items:center;gap:.8rem;margin-top:.6rem;flex-wrap:wrap}
.token-display{display:flex;align-items:center;gap:.4rem;flex:1;min-width:200px}
.token-input{flex:1;font-family:monospace;font-size:.8rem}
.token-expire{font-size:.75rem;color:var(--text-secondary);background:#f1f5f9;padding:.1rem .4rem;border-radius:3px}
.hint{font-size:.75rem;color:var(--text-secondary);font-weight:400}
.mono{font-family:monospace;font-size:.82rem}
.btn-group{display:flex;gap:.5rem}
.result-section{margin-top:1rem;border-top:1px solid var(--border);padding-top:1rem}
.result-header{display:flex;align-items:center;gap:.6rem;font-weight:600;font-size:.9rem;margin-bottom:.6rem}
.status-badge{font-size:.78rem;font-weight:700;padding:.15rem .5rem;border-radius:4px}
.badge-ok{background:#dcfce7;color:#16a34a}.badge-fail{background:#fee2e2;color:#dc2626}
.duration-badge,.size-badge{font-size:.75rem;color:var(--text-secondary);background:#f1f5f9;padding:.1rem .4rem;border-radius:3px}
.resp-body{background:#1e293b;color:#e2e8f0;padding:1rem;border-radius:8px;font-size:.82rem;line-height:1.5;overflow-x:auto;max-height:500px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}
.error-msg{margin-top:.8rem;padding:.6rem .8rem;background:#fef2f2;color:#dc2626;border-radius:6px;font-size:.85rem}
@media(max-width:640px){.auth-grid{grid-template-columns:1fr}}
</style>
