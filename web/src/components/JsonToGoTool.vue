<template>
  <div class="tool-panel">
    <h2>🐹 JSON → Go Struct</h2>

    <div class="card">
      <div class="form-group">
        <div class="label-row">
          <label>JSON 输入</label>
          <button class="btn btn-sm btn-outline" @click="formatJson">格式化</button>
        </div>
        <textarea
          v-model="jsonInput"
          class="input-textarea"
          placeholder='{"name": "张三", "body": {"body1": "hello"}}'
          @input="convert"
        ></textarea>
      </div>

      <div class="form-group">
        <label>结构体名</label>
        <input v-model="structName" type="text" class="input-text" placeholder="User" @input="convert" />
      </div>

      <div class="options-row">
        <label class="checkbox-label">
          <input type="checkbox" v-model="useOmitempty" @change="convert" />
          <span>JSON omitempty</span>
        </label>
        <label class="checkbox-label">
          <input type="checkbox" v-model="camelCase" @change="convert" />
          <span>驼峰命名</span>
        </label>
        <label class="checkbox-label">
          <input type="checkbox" v-model="nestedStruct" @change="convert" />
          <span>嵌套结构体</span>
        </label>
      </div>
    </div>

    <div v-if="goOutput" class="card">
      <div class="output-header">
        <span>Go 代码</span>
        <button class="btn btn-sm" @click="copyOutput">📋 复制</button>
      </div>
      <pre class="code-block">{{ goOutput }}</pre>
    </div>

    <div v-if="error" class="error-box">{{ error }}</div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'

const showToast = inject('showToast')

const jsonInput = ref('')
const structName = ref('MyStruct')
const useOmitempty = ref(true)
const camelCase = ref(true)
const nestedStruct = ref(true)
const goOutput = ref('')
const error = ref('')

function convert() {
  error.value = ''
  goOutput.value = ''

  if (!jsonInput.value.trim()) return

  let json
  try {
    json = JSON.parse(jsonInput.value)
  } catch (e) {
    error.value = 'JSON 格式错误: ' + e.message
    return
  }

  if (typeof json !== 'object' || json === null) {
    error.value = '请输入有效的 JSON 对象'
    return
  }

  goOutput.value = generateGoStruct(json, structName.value || 'MyStruct')
}

function toPascalCase(str) {
  return str.replace(/_([a-z])/g, (_, c) => c.toUpperCase())
            .replace(/^([a-z])/, (_, c) => c.toUpperCase())
}

function toGoName(key) {
  if (camelCase.value) {
    return key.replace(/_([a-z])/g, (_, c) => c.toUpperCase())
              .replace(/^([a-z])/, (_, c) => c.toUpperCase())
  }
  return key.replace(/^([a-z])/, (_, c) => c.toUpperCase())
}

function getGoType(value, key) {
  if (value === null) return 'interface{}'
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]interface{}'
    const itemType = getGoType(value[0], key)
    return `[]${itemType}`
  }
  switch (typeof value) {
    case 'string': return 'string'
    case 'boolean': return 'bool'
    case 'number':
      if (Number.isInteger(value)) return 'int'
      return 'float64'
    default: return 'interface{}'
  }
}

function getNestedTypeName(parentName, fieldName) {
  return parentName + toPascalCase(fieldName)
}

function isNestedObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function generateGoStruct(json, name) {
  const indent = '  '
  const lines = []
  const structMap = new Map()

  // 递归生成所有结构体
  function collectStructs(obj, structName) {
    structMap.set(structName, { fields: [] })

    Object.entries(obj).forEach(([key, value]) => {
      const fieldName = toGoName(key)
      let fieldType
      const tag = key

      if (isNestedObject(value)) {
        // 嵌套对象
        const nestedName = getNestedTypeName(structName, fieldName)
        fieldType = nestedName
        // 递归收集嵌套结构体
        collectStructs(value, nestedName)
      } else if (Array.isArray(value) && value.length > 0 && isNestedObject(value[0])) {
        // 数组中的嵌套对象
        const nestedName = getNestedTypeName(structName, fieldName)
        fieldType = `[]${nestedName}`
        // 递归收集嵌套结构体
        collectStructs(value[0], nestedName)
      } else {
        // 普通类型
        fieldType = getGoType(value, key)
        
        // 数组处理
        if (Array.isArray(value) && value.length > 0) {
          const itemType = getGoType(value[0], key)
          if (itemType !== 'interface{}') {
            fieldType = `[]${itemType}`
          }
        }
      }

      structMap.get(structName).fields.push({
        name: fieldName,
        type: fieldType,
        tag: tag
      })
    })
  }

  collectStructs(json, name)

  // 按依赖顺序生成代码（先子结构体后主结构体）
  const sortedNames = []
  function addStructAndDependencies(structName) {
    const struct = structMap.get(structName)
    if (!struct) return

    struct.fields.forEach(field => {
      const nestedMatch = field.type.match(/^(\w+)$/)
      const arrayNestedMatch = field.type.match(/^\[\](\w+)$/)
      
      if (nestedMatch && structMap.has(nestedMatch[1]) && nestedMatch[1] !== structName) {
        addStructAndDependencies(nestedMatch[1])
      }
      if (arrayNestedMatch && structMap.has(arrayNestedMatch[1])) {
        addStructAndDependencies(arrayNestedMatch[1])
      }
    })

    if (!sortedNames.includes(structName)) {
      sortedNames.push(structName)
    }
  }

  addStructAndDependencies(name)

  // 生成代码
  sortedNames.forEach(sName => {
    const struct = structMap.get(sName)
    lines.push(`type ${sName} struct {`)
    
    struct.fields.forEach(field => {
      const tag = `json:"${field.tag}"`
      const omitempty = useOmitempty.value ? ',omitempty' : ''
      lines.push(`${indent}${field.name} ${field.type} \`${tag}${omitempty}\``)
    })
    
    lines.push('}')
    lines.push('')
  })

  return lines.join('\n').trim()
}

function copyOutput() {
  if (!goOutput.value) return
  navigator.clipboard.writeText(goOutput.value).then(() => {
    showToast('已复制到剪贴板')
  })
}

function formatJson() {
  if (!jsonInput.value.trim()) return
  try {
    const parsed = JSON.parse(jsonInput.value)
    jsonInput.value = JSON.stringify(parsed, null, 2)
    convert()
  } catch (e) {
    error.value = 'JSON 格式错误: ' + e.message
  }
}
</script>

<style scoped>
.input-textarea {
  min-height: 180px;
  font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.85rem;
}

.label-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.25rem;
}

.label-row label {
  margin-bottom: 0;
}

.options-row {
  display: flex;
  gap: 1.5rem;
  flex-wrap: wrap;
  margin-top: 0.5rem;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.85rem;
  cursor: pointer;
}

.checkbox-label input {
  cursor: pointer;
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
}
</style>