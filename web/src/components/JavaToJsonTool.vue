<template>
  <div class="tool-panel">
    <h2>☕ Java 类 → JSON 测试数据</h2>

    <div class="card">
      <div class="form-group">
        <label>Java 类定义（支持多类嵌套，各种格式）</label>
        <textarea
          v-model="fieldsInput"
          class="input-textarea"
          placeholder="// 支持各种访问修饰符和格式
public class User {
    private String name;
    protected Integer age;
    public boolean active;
    String address;  // 默认访问权限
    final String id = &quot;&quot;;
    
    // 嵌套类
    @Data
    private MyBody body;
}

class MyBody {
    String body1;
    List&lt;String&gt; tags;
    Map&lt;String, Object&gt; meta;
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

const fieldsInput = ref('')
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

// 解析所有类字段
function parseAllClasses(text) {
  const classes = new Map()
  const lines = text.split('\n')
  
  // 当前类名（默认为主类）
  let currentClass = 'MainClass'
  let currentFields = []
  
  // 用于检测字段定义的常见关键字
  const typeKeywords = ['String', 'Integer', 'Int', 'Long', 'Double', 'Float', 'Boolean', 'Short', 'Byte', 'Character', 'Object', 'List', 'ArrayList', 'Map', 'HashMap', 'Set', 'HashSet', 'Date', 'LocalDate', 'LocalDateTime', 'BigDecimal', 'Timestamp']
  
  // 判断是否为已知类型
  function isKnownType(type) {
    return typeKeywords.some(kw => type.toLowerCase().includes(kw.toLowerCase())) ||
           type.match(/^[A-Z]/) ||
           type.includes('<')
  }
  
  // 解析单行字段
  function parseField(trimmed) {
    // 跳过空行和注释
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
      return null
    }
    
    // 跳过方法定义等
    if (trimmed.match(/^\w+\s*\(/)) {
      return null
    }
    
    let fieldType = null
    let fieldName = null
    
    // 先判断是否有访问修饰符
    const hasModifier = trimmed.match(/^(private|protected|public|final|static)\s+/)
    
    if (hasModifier) {
      // 有修饰符: 修饰符 类型 字段名
      const parts = trimmed.split(/\s+/)
      const modifiers = ['private', 'protected', 'public', 'final', 'static']
      
      // 找到第一个不是修饰符的词作为类型开始
      let typeStartIndex = -1
      for (let i = 0; i < parts.length; i++) {
        if (!modifiers.includes(parts[i])) {
          typeStartIndex = i
          break
        }
      }
      
      if (typeStartIndex >= 0) {
        // 最后一部分是字段名
        fieldName = parts[parts.length - 1].replace(/;$/, '')
        // 中间是类型
        fieldType = parts.slice(typeStartIndex, parts.length - 1).join(' ')
      }
    } else {
      // 无修饰符: 尝试 "类型 字段名"
      // 从后往前找，找到第一个不是类型的词作为字段名
      const parts = trimmed.replace(/;$/, '').split(/\s+/)
      for (let i = parts.length - 1; i >= 0; i--) {
        const part = parts[i]
        // 如果这个词是类型的一部分，继续
        if (isKnownType(part) || part.match(/^[A-Z]/) || part.includes('<') || part.includes('>')) {
          continue
        }
        // 这个词是字段名
        fieldName = part.replace(/,$/, '')
        fieldType = parts.slice(0, i).join(' ')
        break
      }
    }
    
    if (fieldType && fieldName && isKnownType(fieldType)) {
      // 清理字段名
      fieldName = fieldName.replace(/;$/, '').replace(/,$/, '')
      // 过滤掉明显的非字段内容
      if (!['class', 'interface', 'enum', 'if', 'for', 'while', 'switch', 'try', 'catch'].includes(fieldName)) {
        return { type: fieldType, name: fieldName }
      }
    }
    
    return null
  }
  
  lines.forEach(line => {
    const trimmed = line.trim()
    
    // 检测新类定义（包括内部类）
    const classMatch = trimmed.match(/(?:public|private|protected)?\s*(?:static\s*)?class\s+(\w+)/)
    if (classMatch) {
      // 保存上一个类
      if (currentFields.length > 0) {
        classes.set(currentClass, currentFields)
      }
      currentClass = classMatch[1]
      currentFields = []
      return
    }
    
    // 跳过注解行
    if (trimmed.startsWith('@')) {
      return
    }
    
    // 解析字段
    const field = parseField(trimmed)
    if (field) {
      currentFields.push(field)
    }
  })
  
  // 保存最后一个类
  if (currentFields.length > 0) {
    classes.set(currentClass, currentFields)
  }
  
  return classes
}

// 判断类型是否为自定义类
function isCustomClass(type, classes) {
  const baseType = type.replace(/^List</, '').replace(/>$/, '').replace(/</, '')
  return classes.has(baseType)
}

function getJavaType(type) {
  const t = type.toLowerCase()
  if (t.includes('string') || t.includes('str')) return 'string'
  if (t.includes('int') || t.includes('integer') || t.includes('long') || t.includes('short')) return 'int'
  if (t.includes('double') || t.includes('float') || t.includes('decimal')) return 'float'
  if (t.includes('bool') || t.includes('boolean')) return 'bool'
  if (t.includes('date')) return 'time'
  return 'unknown'
}

function generateValue(type, classes, visited = new Set()) {
  const baseType = type.replace(/^List</, '').replace(/>$/, '').replace(/</, '')
  const isList = type.includes('List')
  
  // 防止循环引用
  if (visited.has(baseType)) {
    return isList ? [] : null
  }
  
  const newVisited = new Set(visited)
  newVisited.add(baseType)
  
  // 检查是否为自定义类
  if (classes.has(baseType)) {
    if (isList) {
      return Array.from({ length: arrayLength.value }, () => 
        generateClassValue(baseType, classes, newVisited)
      )
    }
    return generateClassValue(baseType, classes, newVisited)
  }
  
  const t = getJavaType(type)
  
  switch (t) {
    case 'string': return randomString()
    case 'int': return randomInt(1, 100)
    case 'float': return randomFloat(1, 100)
    case 'bool': return randomBool()
    case 'time': return new Date().toISOString()
    default: return null
  }
}

function generateClassValue(className, classes, parentVisited = new Set()) {
  const fields = classes.get(className)
  if (!fields) return null
  
  const obj = {}
  fields.forEach(field => {
    const jsonName = convertFieldName(field.name)
    // 为每个嵌套类创建新的访问集合，包含父类
    const newVisited = new Set(parentVisited)
    newVisited.add(className)
    obj[jsonName] = generateValue(field.type, classes, newVisited)
  })
  return obj
}

function generateMainObject(classes) {
  if (classes.size === 0) return {}
  
  // 找到主类（假设是第一个定义的）
  const mainClass = classes.keys().next().value
  return generateClassValue(mainClass, classes)
}

function generate() {
  error.value = ''
  jsonOutput.value = ''

  if (!fieldsInput.value.trim()) return

  try {
    const classes = parseAllClasses(fieldsInput.value)
    if (classes.size === 0) {
      error.value = '未找到有效的类定义'
      return
    }
    
    const results = []
    for (let i = 0; i < count.value; i++) {
      results.push(generateMainObject(classes))
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