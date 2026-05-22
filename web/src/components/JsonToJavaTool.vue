<template>
  <div class="tool-panel">
    <h2>☕ JSON → Java 类</h2>

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

      <div class="form-row">
        <div class="form-group half">
          <label>类名</label>
          <input v-model="className" type="text" class="input-text" placeholder="User" @input="convert" />
        </div>
        <div class="form-group half">
          <label>包名</label>
          <input v-model="packageName" type="text" class="input-text" placeholder="com.example" @input="convert" />
        </div>
      </div>

      <div class="options-row">
        <label class="checkbox-label">
          <input type="checkbox" v-model="useLombok" @change="convert" />
          <span>使用 Lombok (@Data)</span>
        </label>
        <label class="checkbox-label">
          <input type="checkbox" v-model="useJackson" @change="convert" />
          <span>Jackson 注解</span>
        </label>
        <label class="checkbox-label">
          <input type="checkbox" v-model="nestedClass" @change="convert" />
          <span>嵌套类</span>
        </label>
      </div>
    </div>

    <div v-if="javaOutput" class="card">
      <div class="output-header">
        <span>Java 代码</span>
        <button class="btn btn-sm" @click="copyOutput">📋 复制</button>
      </div>
      <pre class="code-block">{{ javaOutput }}</pre>
    </div>

    <div v-if="error" class="error-box">{{ error }}</div>
  </div>
</template>

<script setup>
import { ref, inject } from 'vue'

const showToast = inject('showToast')

const jsonInput = ref('')
const className = ref('MyClass')
const packageName = ref('')
const useLombok = ref(true)
const useJackson = ref(false)
const nestedClass = ref(true)
const javaOutput = ref('')
const error = ref('')

function convert() {
  error.value = ''
  javaOutput.value = ''

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

  javaOutput.value = generateJava(json)
}

function toPascalCase(str) {
  return str.replace(/_([a-z])/g, (_, c) => c.toUpperCase())
            .replace(/^([a-z])/, (_, c) => c.toUpperCase())
}

function getJavaType(value) {
  if (value === null) return 'Object'
  if (Array.isArray(value)) {
    if (value.length === 0) return 'List<Object>'
    const itemType = getJavaType(value[0])
    return `List<${itemType}>`
  }
  switch (typeof value) {
    case 'string': return 'String'
    case 'boolean': return 'Boolean'
    case 'number':
      if (Number.isInteger(value)) return 'Integer'
      return 'Double'
    default: return 'Object'
  }
}

function getNestedClassName(parentName, fieldName) {
  return parentName + toPascalCase(fieldName)
}

function isNestedObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function generateJava(json) {
  const name = className.value || 'MyClass'
  const pkg = packageName.value ? `package ${packageName.value};\n\n` : ''
  const classMap = new Map()
  const lines = []

  // 递归生成所有类
  function collectClasses(obj, className) {
    classMap.set(className, { fields: [] })

    Object.entries(obj).forEach(([key, value]) => {
      const fieldName = key.charAt(0).toLowerCase() + key.slice(1)
      let fieldType
      const jsonKey = key

      if (isNestedObject(value)) {
        // 嵌套对象
        const nestedName = getNestedClassName(className, toPascalCase(key))
        fieldType = nestedName
        collectClasses(value, nestedName)
      } else if (Array.isArray(value) && value.length > 0 && isNestedObject(value[0])) {
        // 数组中的嵌套对象
        const nestedName = getNestedClassName(className, toPascalCase(key))
        fieldType = `List<${nestedName}>`
        collectClasses(value[0], nestedName)
      } else {
        // 普通类型
        fieldType = getJavaType(value)
        
        // 数组处理
        if (Array.isArray(value) && value.length > 0) {
          const itemType = getJavaType(value[0])
          if (itemType !== 'Object') {
            fieldType = `List<${itemType}>`
          }
        }
      }

      classMap.get(className).fields.push({
        name: fieldName,
        type: fieldType,
        jsonKey: jsonKey
      })
    })
  }

  collectClasses(json, name)

  // 生成导入语句
  const imports = ['import java.util.List;']
  if (useLombok.value) {
    imports.push('import lombok.Data;')
  }
  if (useJackson.value) {
    imports.push('import com.fasterxml.jackson.annotation.JsonProperty;')
  }

  // 按依赖顺序生成代码
  const sortedNames = []
  function addClassAndDependencies(classN) {
    const cls = classMap.get(classN)
    if (!cls) return

    cls.fields.forEach(field => {
      const isClass = classMap.has(field.type) && field.type !== classN
      const isListClass = field.type.startsWith('List<') && classMap.has(field.type.replace('List<', '').replace('>', ''))
      
      if (isClass) {
        addClassAndDependencies(field.type)
      }
      if (isListClass) {
        addClassAndDependencies(field.type.replace('List<', '').replace('>', ''))
      }
    })

    if (!sortedNames.includes(classN)) {
      sortedNames.push(classN)
    }
  }

  addClassAndDependencies(name)

  // 生成主类代码
  sortedNames.forEach(cName => {
    const cls = classMap.get(cName)
    
    if (useLombok.value) {
      lines.push('@Data')
    }
    lines.push(`public class ${cName} {`)
    
    cls.fields.forEach(field => {
      if (useJackson.value) {
        lines.push(`    @JsonProperty("${field.jsonKey}")`)
      }
      lines.push(`    private ${field.type} ${field.name};`)
    })
    
    lines.push('}')
    lines.push('')
  })

  return pkg + imports.join('\n') + '\n\n' + lines.join('\n')
}

function copyOutput() {
  if (!javaOutput.value) return
  navigator.clipboard.writeText(javaOutput.value).then(() => {
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