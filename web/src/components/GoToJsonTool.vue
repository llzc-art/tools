<template>
  <div class="tool-panel">
    <h2>🐹 Go Struct → JSON 测试数据</h2>

    <div class="card">
      <div class="form-group">
        <label>Go Struct 定义（支持多结构体嵌套）</label>
        <textarea
          v-model="structInput"
          class="input-textarea"
          placeholder="type User struct {
    Name string `json:&quot;name&quot;`
    Body *Body  `json:&quot;body&quot;`
}

type Body struct {
    Body1 string `json:&quot;body1&quot;`
}"
          @input="generate"
        ></textarea>
      </div>

      <div class="form-row">
        <div class="form-group half">
          <label>数组长度</label>
          <input v-model.number="arrayLength" type="number" min="1" max="10" class="input-text" @input="generate" />
        </div>
        <div class="form-group half">
          <label>生成数量</label>
          <input v-model.number="count" type="number" min="1" max="10" class="input-text" @input="generate" />
        </div>
      </div>

      <div class="form-group">
        <label>JSON 命名格式</label>
        <select v-model="namingFormat" class="input-select" @change="generate">
          <option value="camel">camelCase (userName)</option>
          <option value="snake">snake_case (user_name)</option>
          <option value="pascal">PascalCase (UserName)</option>
          <option value="original">保持原样</option>
        </select>
      </div>
    </div>

    <div v-if="jsonOutput" class="card">
      <div class="output-header">
        <span>JSON 测试数据</span>
        <div class="btn-group">
          <button class="btn btn-sm" @click="copyOutput">📋 复制</button>
          <button class="btn btn-sm btn-outline" @click="formatOutput">格式化</button>
        </div>
      </div>
      <pre class="code-block">{{ jsonOutput }}</pre>
    </div>

    <div v-if="error" class="error-box">{{ error }}</div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'

const showToast = inject('showToast')

const structInput = ref('')
const arrayLength = ref(3)
const count = ref(1)
const namingFormat = ref('original')
const jsonOutput = ref('')
const error = ref('')

// 命名转换函数
function toCamelCase(str) {
  return str.replace(/_([a-z])/g, (_, c) => c.toUpperCase())
            .replace(/^([A-Z])/, (_, c) => c.toLowerCase())
}

function toSnakeCase(str) {
  return str.replace(/([A-Z])/g, '_$1').toLowerCase().replace(/^_/, '')
}

function toPascalCase(str) {
  return str.replace(/(^|_)(\w)/g, (_, __, c) => c.toUpperCase())
}

function convertFieldName(name) {
  switch (namingFormat.value) {
    case 'camel': return toCamelCase(name)
    case 'snake': return toSnakeCase(name)
    case 'pascal': return toPascalCase(name)
    default: return name
  }
}

function randomString() {
  const names = ['张三', '李四', '王五', '赵六', 'Alice', 'Bob', 'Charlie', 'David']
  const strs = ['测试', '示例', '数据', '内容', 'Hello', 'World', 'Test', 'Demo']
  const pick = (arr) => arr[Math.floor(Math.random() * arr.length)]
  return Math.random() > 0.5 ? pick(names) : pick(strs) + randomInt(1, 100)
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

function randomFloat(min, max) {
  return parseFloat((Math.random() * (max - min) + min).toFixed(2))
}

function randomBool() {
  return Math.random() > 0.5
}

// 提取 JSON tag
function extractJsonTag(line) {
  const match = line.match(/`json:"([^"]+)(?:,omitempty)?"`/)
  return match ? match[1] : null
}

// 解析所有结构体定义
function parseAllStructs(text) {
  const structs = new Map()
  const lines = text.split('\n')
  
  let currentStruct = null
  let currentFields = []
  
  lines.forEach(line => {
    const trimmed = line.trim()
    
    // 开始新结构体
    const structMatch = trimmed.match(/^type\s+(\w+)\s+struct\s*\{/)
    if (structMatch) {
      currentStruct = structMatch[1]
      currentFields = []
      return
    }
    
    // 结构体结束
    if (trimmed === '}' && currentStruct) {
      structs.set(currentStruct, currentFields)
      currentStruct = null
      currentFields = []
    }
    
    // 解析字段
    if (currentStruct && trimmed && !trimmed.startsWith('//')) {
      // 匹配 "类型 字段名" 格式（如：Dept MyStructDept）
      const fieldMatch = trimmed.match(/^(\w+)\s+(\w+)/)
      if (fieldMatch) {
        const fieldType = fieldMatch[2]  // 第二个是类型
        const fieldName = fieldMatch[1]  // 第一个是字段名
        const jsonName = extractJsonTag(trimmed) || fieldName
        currentFields.push({ type: fieldType, name: fieldName, jsonName })
      }
    }
  })
  
  return structs
}

// 判断类型是否为自定义结构体
function isCustomStruct(type, structs) {
  const baseType = type.replace(/^\*+/, '').replace(/^\[\]/, '')
  return structs.has(baseType)
}

function getGoType(type) {
  const t = type.replace(/^\*+/, '').toLowerCase()
  if (t === 'string') return 'string'
  if (t.startsWith('int')) return 'int'
  if (t.startsWith('uint')) return 'int'
  if (t.startsWith('float') || t === 'double') return 'float'
  if (t === 'bool') return 'bool'
  if (t === 'byte') return 'string'
  if (t === 'rune') return 'string'
  if (t === 'time.time') return 'time'
  return 'unknown'
}

function generateValue(type, structs, visited = new Set()) {
  const baseType = type.replace(/^\*+/, '')
  const isPointer = type.startsWith('*')
  const isSlice = type.startsWith('[]')
  const cleanType = baseType.replace(/^\[\]/, '')
  
  // 防止循环引用
  if (visited.has(cleanType)) {
    return null
  }
  
  const newVisited = new Set(visited)
  newVisited.add(cleanType)
  
  // 检查是否为自定义结构体
  if (structs.has(cleanType)) {
    if (isSlice) {
      return Array.from({ length: arrayLength.value }, () => 
        generateStructValue(cleanType, structs, newVisited)
      )
    }
    const value = generateStructValue(cleanType, structs, newVisited)
    return isPointer && value !== null ? value : (value || null)
  }
  
  const t = getGoType(type)
  
  switch (t) {
    case 'string': return randomString()
    case 'int': return randomInt(1, 100)
    case 'float': return randomFloat(1, 100)
    case 'bool': return randomBool()
    case 'time': return new Date().toISOString()
    default: return null
  }
}

function generateStructValue(structName, structs, parentVisited = new Set()) {
  const fields = structs.get(structName)
  if (!fields) return null
  
  const obj = {}
  fields.forEach(field => {
    const jsonName = convertFieldName(field.jsonName)
    // 为每个嵌套结构体创建新的访问集合，包含父结构体
    const newVisited = new Set(parentVisited)
    newVisited.add(structName)
    obj[jsonName] = generateValue(field.type, structs, newVisited)
  })
  return obj
}

function generateMainObject(structs) {
  if (structs.size === 0) return {}
  
  // 找到主结构体（假设是第一个定义的）
  const mainStruct = structs.keys().next().value
  return generateStructValue(mainStruct, structs)
}

function generate() {
  error.value = ''
  jsonOutput.value = ''

  if (!structInput.value.trim()) return

  try {
    const structs = parseAllStructs(structInput.value)
    if (structs.size === 0) {
      error.value = '未找到有效的结构体定义'
      return
    }
    
    const results = []
    for (let i = 0; i < count.value; i++) {
      results.push(generateMainObject(structs))
    }
    jsonOutput.value = JSON.stringify(count.value === 1 ? results[0] : results, null, 2)
  } catch (e) {
    error.value = '生成失败: ' + e.message
  }
}

function copyOutput() {
  if (!jsonOutput.value) return
  navigator.clipboard.writeText(jsonOutput.value).then(() => {
    showToast('已复制到剪贴板')
  })
}

function formatOutput() {
  if (!jsonOutput.value) return
  try {
    const parsed = JSON.parse(jsonOutput.value)
    jsonOutput.value = JSON.stringify(parsed, null, 2)
  } catch (e) {
    error.value = '格式化失败'
  }
}
</script>

<style scoped>
.input-textarea {
  min-height: 200px;
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.85rem;
}

.btn-group {
  display: flex;
  gap: 0.4rem;
}

.output-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
  font-weight: 600;
  font-size: 0.88rem;
}

.code-block {
  background: #1e293b;
  color: #e2e8f0;
  padding: 1rem;
  border-radius: 8px;
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.82rem;
  line-height: 1.5;
  overflow-x: auto;
  white-space: pre;
  max-height: 400px;
  overflow-y: auto;
}
</style>