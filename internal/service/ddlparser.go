package service

import (
	"fmt"
	"regexp"
	"strings"
)

// ColumnDef 列定义
type ColumnDef struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Nullable      bool   `json:"nullable"`
	DefaultValue  string `json:"default_value"`
	Comment       string `json:"comment"`
	IsPrimaryKey  bool   `json:"is_primary_key"`
	AutoIncrement bool   `json:"auto_increment"`
}

// IndexDef 索引定义
type IndexDef struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
	Unique  bool     `json:"unique"`
	Type    string   `json:"type"` // PRIMARY, UNIQUE, INDEX, FULLTEXT
}

// ForeignKeyDef 外键定义
type ForeignKeyDef struct {
	Name       string   `json:"name"`
	Columns    []string `json:"columns"`
	RefTable   string   `json:"ref_table"`
	RefColumns []string `json:"ref_columns"`
}

// TableDef 表定义
type TableDef struct {
	Name        string          `json:"name"`
	Schema      string          `json:"schema"`
	Comment     string          `json:"comment"`
	Columns     []ColumnDef     `json:"columns"`
	Indexes     []IndexDef      `json:"indexes"`
	ForeignKeys []ForeignKeyDef `json:"foreign_keys"`
	Engine      string          `json:"engine"`
	Charset     string          `json:"charset"`
}

// DDLParseResult 解析结果
type DDLParseResult struct {
	Tables              []TableDef `json:"tables"`
	MermaidClassDiagram string     `json:"mermaid_class_diagram"`
	HTMLTables          string     `json:"html_tables"`
	MarkdownTables      string     `json:"markdown_tables"`
	TableCount          int        `json:"table_count"`
	SkippedCount        int        `json:"skipped_count"`
}

// DDLParserService DDL解析服务
type DDLParserService struct{}

// NewDDLParserService 构造函数
func NewDDLParserService() *DDLParserService {
	return &DDLParserService{}
}

// Parse 解析DDL语句
func (s *DDLParserService) Parse(ddl string) (*DDLParseResult, error) {
	ddl = strings.TrimSpace(ddl)
	if ddl == "" {
		return nil, fmt.Errorf("DDL语句不能为空")
	}

	tables, skipped := s.parseTables(ddl)
	if len(tables) == 0 {
		return nil, fmt.Errorf("未找到有效的 CREATE TABLE 语句")
	}

	result := &DDLParseResult{
		Tables:              tables,
		MermaidClassDiagram: s.generateMermaidClassDiagram(tables),
		HTMLTables:          s.generateHTMLTables(tables),
		MarkdownTables:      s.generateMarkdownTables(tables),
		TableCount:          len(tables),
		SkippedCount:        skipped,
	}

	return result, nil
}

// parseTables 解析所有 CREATE TABLE 语句，返回解析结果和跳过的语句数
func (s *DDLParserService) parseTables(ddl string) ([]TableDef, int) {
	var tables []TableDef
	skipped := 0

	statements := splitDDLStatements(ddl)

	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}

		// 移除 SQL 注释行
		stmt = removeSQLComments(stmt)
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}

		upper := strings.ToUpper(stmt)

		// 只处理 CREATE TABLE，其他语句全部跳过
		if !isCreateTable(upper) {
			skipped++
			continue
		}

		table := s.parseCreateTable(stmt)
		if table.Name != "" {
			tables = append(tables, table)
		}
	}

	return tables, skipped
}

// isCreateTable 判断是否为 CREATE TABLE 语句
func isCreateTable(upper string) bool {
	// 精确匹配 CREATE TABLE，排除 CREATE INDEX/UNIQUE INDEX 等
	return strings.HasPrefix(upper, "CREATE TABLE ") ||
		strings.HasPrefix(upper, "CREATE TABLE\t") ||
		strings.HasPrefix(upper, "CREATE  TABLE ")
}

// removeSQLComments 移除 SQL 风格注释
func removeSQLComments(stmt string) string {
	var lines []string
	for _, line := range strings.Split(stmt, "\n") {
		trimmed := strings.TrimSpace(line)
		// 跳过纯注释行
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		// 移除行内注释 (不在引号内的情况)
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, " ")
}

// splitDDLStatements 按分号分割DDL语句，处理引号内的分号
func splitDDLStatements(ddl string) []string {
	var statements []string
	var current strings.Builder
	inSingleQuote := false
	inDoubleQuote := false
	inBacktick := false

	for _, ch := range ddl {
		switch {
		case ch == '\'' && !inDoubleQuote && !inBacktick:
			inSingleQuote = !inSingleQuote
		case ch == '"' && !inSingleQuote && !inBacktick:
			inDoubleQuote = !inDoubleQuote
		case ch == '`' && !inSingleQuote && !inDoubleQuote:
			inBacktick = !inBacktick
		case ch == ';' && !inSingleQuote && !inDoubleQuote && !inBacktick:
			statements = append(statements, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(ch)
	}

	remaining := strings.TrimSpace(current.String())
	if remaining != "" {
		statements = append(statements, remaining)
	}

	return statements
}

// parseCreateTable 解析单条 CREATE TABLE 语句
func (s *DDLParserService) parseCreateTable(stmt string) TableDef {
	table := TableDef{
		Columns:     []ColumnDef{},
		Indexes:     []IndexDef{},
		ForeignKeys: []ForeignKeyDef{},
	}

	// 提取表名（支持 schema.table 格式）
	table.Schema, table.Name = extractSchemaTableName(stmt)
	if table.Name == "" {
		return table
	}

	// 提取括号内的列定义部分（使用对应表名后的第一个括号）
	body := extractCreateTableBody(stmt)
	if body == "" {
		return table
	}

	// 提取表选项（ENGINE, CHARSET, COMMENT 等）
	s.parseTableOptions(stmt, &table)

	// 解析括号内的各定义项
	definitions := splitDefinitions(body)
	primaryKeyColumns := []string{}

	for _, def := range definitions {
		def = strings.TrimSpace(def)
		if def == "" {
			continue
		}

		upper := strings.ToUpper(def)

		// 跳过 CHECK 约束
		if strings.HasPrefix(upper, "CHECK ") {
			continue
		}

		// CONSTRAINT xxx PRIMARY KEY (...) - 提取主键
		if strings.HasPrefix(upper, "CONSTRAINT ") && strings.Contains(upper, "PRIMARY KEY") {
			cols := extractColumnList(def, "PRIMARY KEY")
			primaryKeyColumns = append(primaryKeyColumns, cols...)
			// 提取约束名
			constraintName := extractConstraintName(def)
			table.Indexes = append(table.Indexes, IndexDef{
				Name:    constraintName,
				Columns: cols,
				Unique:  true,
				Type:    "PRIMARY",
			})
			continue
		}

		// CONSTRAINT xxx FOREIGN KEY (...)
		if strings.HasPrefix(upper, "CONSTRAINT ") && strings.Contains(upper, "FOREIGN KEY") {
			fk := s.parseConstraintFK(def)
			if fk != nil {
				table.ForeignKeys = append(table.ForeignKeys, *fk)
			}
			continue
		}

		// 跳过其他 CONSTRAINT（UNIQUE 等）
		if strings.HasPrefix(upper, "CONSTRAINT ") {
			continue
		}

		// 主键（直接 PRIMARY KEY 形式）
		if strings.HasPrefix(upper, "PRIMARY KEY") {
			cols := extractColumnList(def, "PRIMARY KEY")
			primaryKeyColumns = append(primaryKeyColumns, cols...)
			table.Indexes = append(table.Indexes, IndexDef{
				Name:    "PRIMARY",
				Columns: cols,
				Unique:  true,
				Type:    "PRIMARY",
			})
			continue
		}

		// 外键
		if strings.HasPrefix(upper, "FOREIGN KEY") {
			fk := s.parseForeignKey(def)
			if fk != nil {
				table.ForeignKeys = append(table.ForeignKeys, *fk)
			}
			continue
		}

		// 唯一索引
		if strings.HasPrefix(upper, "UNIQUE KEY") || strings.HasPrefix(upper, "UNIQUE INDEX") {
			idx := s.parseIndex(def, "UNIQUE")
			table.Indexes = append(table.Indexes, idx)
			continue
		}

		// 索引
		if strings.HasPrefix(upper, "INDEX ") || strings.HasPrefix(upper, "KEY ") {
			idx := s.parseIndex(def, "INDEX")
			table.Indexes = append(table.Indexes, idx)
			continue
		}

		// 全文索引
		if strings.HasPrefix(upper, "FULLTEXT ") {
			idx := s.parseIndex(def, "FULLTEXT")
			table.Indexes = append(table.Indexes, idx)
			continue
		}

		// 列定义
		col := s.parseColumnDef(def)
		if col.Name != "" {
			table.Columns = append(table.Columns, col)
		}
	}

	// 标记主键列
	primaryKeySet := make(map[string]bool)
	for _, col := range primaryKeyColumns {
		primaryKeySet[strings.ToLower(stripQuotes(col))] = true
	}
	for i := range table.Columns {
		name := strings.ToLower(stripQuotes(table.Columns[i].Name))
		if primaryKeySet[name] {
			table.Columns[i].IsPrimaryKey = true
		}
	}

	return table
}

// extractSchemaTableName 从 CREATE TABLE 语句提取 schema 和 table 名
// 支持: "schema"."table", `schema`.`table`, schema.table
func extractSchemaTableName(stmt string) (schema, table string) {
	// 去掉 CREATE TABLE [IF NOT EXISTS]
	cleaned := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`).ReplaceAllString(stmt, "")
	cleaned = strings.TrimSpace(cleaned)

	// 一直读到括号或空格之前
	var namePart strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(cleaned); i++ {
		ch := cleaned[i]
		if ch == '(' && !inQuote {
			break
		}
		if ch == ' ' && !inQuote {
			break
		}
		if (ch == '"' || ch == '`' || ch == '\'') && (!inQuote || quoteChar == ch) {
			if inQuote {
				inQuote = false
			} else {
				inQuote = true
				quoteChar = ch
			}
			continue
		}
		namePart.WriteByte(ch)
	}

	fullName := stripQuotes(namePart.String())

	// 按 . 分割 schema 和 table
	if idx := strings.LastIndex(fullName, "."); idx >= 0 {
		schema = strings.TrimSpace(fullName[:idx])
		table = strings.TrimSpace(fullName[idx+1:])
	} else {
		schema = ""
		table = strings.TrimSpace(fullName)
	}

	return schema, table
}

// extractCreateTableBody 提取 CREATE TABLE 语句中表定义括号内的内容
func extractCreateTableBody(stmt string) string {
	// 找到 CREATE TABLE 之后的第一个 ( ，避免被 INDEX 定义中的括号干扰
	re := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[^\(]+\(`)
	loc := re.FindStringIndex(stmt)
	if loc == nil {
		return ""
	}
	// loc[1] 是 ( 之后的位置，即括号内容的起始
	start := loc[1] - 1 // ( 的位置

	depth := 0
	for i := start; i < len(stmt); i++ {
		switch stmt[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return stmt[start+1 : i]
			}
		}
	}
	return ""
}

// extractConstraintName 提取约束名
func extractConstraintName(def string) string {
	re := regexp.MustCompile(`(?i)CONSTRAINT\s+[` + "`" + `"']?(\w+)[` + "`" + `"']?`)
	matches := re.FindStringSubmatch(def)
	if len(matches) >= 2 {
		return matches[1]
	}
	return "PRIMARY"
}

// parseConstraintFK 解析 CONSTRAINT xxx FOREIGN KEY 形式的外键
func (s *DDLParserService) parseConstraintFK(def string) *ForeignKeyDef {
	fk := &ForeignKeyDef{}

	// 提取约束名
	fk.Name = extractConstraintName(def)

	// FOREIGN KEY (col) REFERENCES table(col)
	fkRe := regexp.MustCompile(`(?i)FOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s+[` + "`" + `"']?([\w.]+)[` + "`" + `"']?\s*\(([^)]+)\)`)
	matches := fkRe.FindStringSubmatch(def)
	if len(matches) < 4 {
		return nil
	}

	fk.Columns = parseColumnNames(matches[1])
	fullRef := matches[2]
	// 去掉可能的 schema 前缀
	if idx := strings.LastIndex(fullRef, "."); idx >= 0 {
		fk.RefTable = fullRef[idx+1:]
	} else {
		fk.RefTable = fullRef
	}
	fk.RefColumns = parseColumnNames(matches[3])

	return fk
}

// parseTableOptions 解析表选项
func (s *DDLParserService) parseTableOptions(stmt string, table *TableDef) {
	body := extractCreateTableBody(stmt)
	if body == "" {
		return
	}
	// 找到 body 对应的右括号在原语句中的位置
	bodyStart := strings.Index(stmt, body)
	if bodyStart == -1 {
		return
	}
	afterStart := bodyStart + len(body) + 1 // 跳过 )
	if afterStart >= len(stmt) {
		return
	}
	after := strings.TrimSpace(stmt[afterStart:])

	// ENGINE
	if re := regexp.MustCompile(`(?i)ENGINE\s*=\s*(\w+)`); re.MatchString(after) {
		table.Engine = re.FindStringSubmatch(after)[1]
	}

	// CHARSET
	if re := regexp.MustCompile(`(?i)(?:DEFAULT\s+)?CHARSET\s*=\s*(\w+)`); re.MatchString(after) {
		table.Charset = re.FindStringSubmatch(after)[1]
	} else if re := regexp.MustCompile(`(?i)CHARACTER\s+SET\s*=\s*(\w+)`); re.MatchString(after) {
		table.Charset = re.FindStringSubmatch(after)[1]
	}

	// COMMENT
	if re := regexp.MustCompile(`(?i)COMMENT\s*=\s*['"]([^'"]*)['"]`); re.MatchString(after) {
		table.Comment = re.FindStringSubmatch(after)[1]
	}
}

// splitDefinitions 分割列/索引/约束定义
func splitDefinitions(body string) []string {
	var defs []string
	var current strings.Builder
	depth := 0
	inSingle := false
	inDouble := false
	inBacktick := false

	for _, ch := range body {
		switch {
		case ch == '\'' && !inDouble && !inBacktick:
			inSingle = !inSingle
		case ch == '"' && !inSingle && !inBacktick:
			inDouble = !inDouble
		case ch == '`' && !inSingle && !inDouble:
			inBacktick = !inBacktick
		case ch == '(' && !inSingle && !inDouble && !inBacktick:
			depth++
		case ch == ')' && !inSingle && !inDouble && !inBacktick:
			depth--
		case ch == ',' && !inSingle && !inDouble && !inBacktick && depth == 0:
			defs = append(defs, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(ch)
	}

	remaining := strings.TrimSpace(current.String())
	if remaining != "" {
		defs = append(defs, remaining)
	}

	return defs
}

// parseColumnDef 解析列定义
func (s *DDLParserService) parseColumnDef(def string) ColumnDef {
	col := ColumnDef{
		Nullable: true,
	}

	def = strings.TrimSpace(def)

	// 匹配: ["]column_name["] TYPE [(length)] [options]
	// (\w+(?:\s*\([^)]*\))?) 能匹配 VARCHAR(128)、DECIMAL(10,2) 等带括号参数的类型
	re := regexp.MustCompile(`^["` + "`" + `']?(\w+)["` + "`" + `']?\s+(\w+(?:\s*\([^)]*\))?)(?:\s|$)(.*)`)
	matches := re.FindStringSubmatch(def)
	if len(matches) < 3 {
		return col
	}

	col.Name = matches[1]
	col.Type = strings.TrimSpace(matches[2])
	rest := strings.TrimSpace(matches[3])

	// 提取类型参数 (如 VARCHAR(255), DECIMAL(10,2))
	if typeRe := regexp.MustCompile(`^(\w+)\s*\(([^)]*)\)`); typeRe.MatchString(col.Type) {
		typeMatches := typeRe.FindStringSubmatch(col.Type)
		if len(typeMatches) >= 3 {
			col.Type = strings.ToUpper(typeMatches[1]) + "(" + typeMatches[2] + ")"
		}
	} else {
		col.Type = strings.ToUpper(col.Type)
	}

	upper := strings.ToUpper(rest)

	// NOT NULL
	if strings.Contains(upper, "NOT NULL") {
		col.Nullable = false
	}

	// AUTO_INCREMENT / AUTOINCREMENT
	if strings.Contains(upper, "AUTO_INCREMENT") || strings.Contains(upper, "AUTOINCREMENT") {
		col.AutoIncrement = true
	}

	// DEFAULT value - 支持 NEXT VALUE FOR, CURRENT_TIMESTAMP 等复杂默认值
	defaultRe := regexp.MustCompile(`(?i)DEFAULT\s+(.+?)(?:\s+(?:NOT\s+NULL|NULL|COMMENT|AUTO_INCREMENT|AUTOINCREMENT|PRIMARY\s+KEY|UNIQUE|CHECK|REFERENCES|$)|$)`)
	if defaultMatches := defaultRe.FindStringSubmatch(rest); len(defaultMatches) >= 2 {
		dv := strings.TrimSpace(defaultMatches[1])
		// 去掉尾部可能的多余字符
		dv = strings.TrimRight(dv, " ,")
		dv = strings.Trim(dv, "'\"`")
		col.DefaultValue = dv
	}

	// COMMENT
	commentRe := regexp.MustCompile(`(?i)COMMENT\s+['"]([^'"]*?)['"]`)
	if commentMatches := commentRe.FindStringSubmatch(rest); len(commentMatches) >= 2 {
		col.Comment = commentMatches[1]
	}

	return col
}

// parseForeignKey 解析外键定义 (FOREIGN KEY 形式)
func (s *DDLParserService) parseForeignKey(def string) *ForeignKeyDef {
	fk := &ForeignKeyDef{}

	fkRe := regexp.MustCompile(`(?i)FOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s+["` + "`" + `']?([\w.]+)["` + "`" + `']?\s*\(([^)]+)\)`)
	matches := fkRe.FindStringSubmatch(def)
	if len(matches) < 4 {
		return nil
	}

	fk.Columns = parseColumnNames(matches[1])
	fullRef := matches[2]
	// 处理 schema.table 格式
	if idx := strings.LastIndex(fullRef, "."); idx >= 0 {
		fk.RefTable = fullRef[idx+1:]
	} else {
		fk.RefTable = fullRef
	}
	fk.RefTable = strings.Trim(fk.RefTable, "\"'`")
	fk.RefColumns = parseColumnNames(matches[3])
	fk.Name = fmt.Sprintf("fk_%s_%s", fk.RefTable, strings.Join(fk.Columns, "_"))

	return fk
}

// parseIndex 解析索引定义
func (s *DDLParserService) parseIndex(def string, idxType string) IndexDef {
	idx := IndexDef{
		Unique: idxType == "UNIQUE" || idxType == "PRIMARY",
		Type:   idxType,
	}

	// KEY/INDEX index_name (col1[, col2])
	re := regexp.MustCompile(`(?i)(?:UNIQUE\s+)?(?:KEY|INDEX)\s+["` + "`" + `']?(\w+)["` + "`" + `']?\s*\(([^)]+)\)`)
	matches := re.FindStringSubmatch(def)
	if len(matches) >= 3 {
		idx.Name = matches[1]
		idx.Columns = parseColumnNames(matches[2])
	} else {
		re2 := regexp.MustCompile(`(?i)(?:UNIQUE\s+)?(?:KEY|INDEX)\s*\(([^)]+)\)`)
		matches2 := re2.FindStringSubmatch(def)
		if len(matches2) >= 2 {
			idx.Name = "idx_unnamed"
			idx.Columns = parseColumnNames(matches2[1])
		}
	}

	return idx
}

// extractColumnList 从定义中提取 PRIMARY KEY(columns) 的列名列表
func extractColumnList(def string, keyword string) []string {
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(keyword) + `\s*\(([^)]+)\)`)
	matches := re.FindStringSubmatch(def)
	if len(matches) >= 2 {
		return parseColumnNames(matches[1])
	}
	return nil
}

// parseColumnNames 解析逗号分隔的列名
func parseColumnNames(s string) []string {
	parts := strings.Split(s, ",")
	var cols []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// 处理带排序的 (col ASC/DESC)
		if spaceIdx := strings.Index(p, " "); spaceIdx != -1 {
			p = p[:spaceIdx]
		}
		p = stripQuotes(p)
		if p != "" {
			cols = append(cols, p)
		}
	}
	return cols
}

// stripQuotes 去除两端的引号
func stripQuotes(s string) string {
	return strings.Trim(s, "\"'` ")
}

// generateMermaidClassDiagram 生成 Mermaid classDiagram 语法
func (s *DDLParserService) generateMermaidClassDiagram(tables []TableDef) string {
	var sb strings.Builder
	sb.WriteString("classDiagram\n")

	// 外键关系
	for _, table := range tables {
		for _, fk := range table.ForeignKeys {
			refClass := toClassName(fk.RefTable)
			sourceClass := toClassName(table.Name)
			// 检查引用表是否存在
			if classNameExists(tables, refClass) {
				sb.WriteString(fmt.Sprintf("    %s --> %s : %s\n", sourceClass, refClass, strings.Join(fk.Columns, ", ")))
			}
		}
	}

	for _, table := range tables {
		className := toClassName(table.Name)
		sb.WriteString(fmt.Sprintf("    class %s {\n", className))

		// 表名标签
		tableLabel := table.Name
		if table.Comment != "" {
			tableLabel += " [" + table.Comment + "]"
		}
		sb.WriteString(fmt.Sprintf("        %s\n", tableLabel))

		for _, col := range table.Columns {
			var parts []string
			if col.IsPrimaryKey {
				parts = append(parts, "PK")
			}
			if !col.Nullable {
				parts = append(parts, "NOT NULL")
			}
			if col.AutoIncrement {
				parts = append(parts, "AUTO_INC")
			}

			colType := col.Type
			if col.DefaultValue != "" {
				colType += " = " + col.DefaultValue
			}

			annotation := ""
			if col.Comment != "" {
				annotation = " " + col.Comment
			}
			if len(parts) > 0 {
				annotation += " [" + strings.Join(parts, ", ") + "]"
			}

			typeStr := ""
			if colType != "" {
				typeStr = " " + colType
			}

			sb.WriteString(fmt.Sprintf("        +%s%s%s\n", col.Name, typeStr, annotation))
		}
		sb.WriteString("    }\n")
	}

	return sb.String()
}

// classNameExists 检查类名是否在表列表中
func classNameExists(tables []TableDef, className string) bool {
	for _, t := range tables {
		if toClassName(t.Name) == className {
			return true
		}
	}
	return false
}

// generateHTMLTables 生成 HTML 表格
func (s *DDLParserService) generateHTMLTables(tables []TableDef) string {
	var sb strings.Builder

	for _, table := range tables {
		// 表标题
		tableLabel := table.Name
		if table.Schema != "" {
			tableLabel = table.Schema + "." + tableLabel
		}
		sb.WriteString(fmt.Sprintf("<h3>%s</h3>\n", tableLabel))

		sb.WriteString("<table border=\"1\" cellspacing=\"0\" cellpadding=\"6\" style=\"border-collapse:collapse;width:100%;\">\n")
		sb.WriteString("<thead><tr style=\"background:#4f46e5;color:#fff;\">")
		sb.WriteString("<th>#</th><th>字段名</th><th>类型</th><th>允许空</th><th>默认值</th><th>主键</th><th>自增</th><th>备注</th>")
		sb.WriteString("</tr></thead>\n<tbody>\n")

		for i, col := range table.Columns {
			nullableStr := "是"
			if !col.Nullable {
				nullableStr = "否"
			}
			pkStr := ""
			if col.IsPrimaryKey {
				pkStr = "✅"
			}
			autoStr := ""
			if col.AutoIncrement {
				autoStr = "✅"
			}
			defaultStr := col.DefaultValue
			if defaultStr == "" {
				defaultStr = "-"
			}
			commentStr := col.Comment
			if commentStr == "" {
				commentStr = "-"
			}

			rowStyle := ""
			if i%2 == 0 {
				rowStyle = "background:#f9fafb;"
			}

			sb.WriteString(fmt.Sprintf(
				"<tr style=\"%s\"><td>%d</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				rowStyle, i+1, col.Name, col.Type, nullableStr, defaultStr, pkStr, autoStr, commentStr,
			))
		}

		sb.WriteString("</tbody>\n</table>\n")

		// 索引
		if len(table.Indexes) > 0 {
			sb.WriteString("<h4>索引</h4>\n")
			sb.WriteString("<table border=\"1\" cellspacing=\"0\" cellpadding=\"6\" style=\"border-collapse:collapse;width:100%;\">\n")
			sb.WriteString("<thead><tr style=\"background:#6d28d9;color:#fff;\">")
			sb.WriteString("<th>索引名</th><th>类型</th><th>列</th><th>唯一</th>")
			sb.WriteString("</tr></thead>\n<tbody>\n")

			for i, idx := range table.Indexes {
				uniqueStr := "否"
				if idx.Unique {
					uniqueStr = "是"
				}
				rowStyle := ""
				if i%2 == 0 {
					rowStyle = "background:#f9fafb;"
				}
				sb.WriteString(fmt.Sprintf(
					"<tr style=\"%s\"><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
					rowStyle, idx.Name, idx.Type, strings.Join(idx.Columns, ", "), uniqueStr,
				))
			}
			sb.WriteString("</tbody>\n</table>\n")
		}

		// 外键
		if len(table.ForeignKeys) > 0 {
			sb.WriteString("<h4>外键</h4>\n")
			sb.WriteString("<table border=\"1\" cellspacing=\"0\" cellpadding=\"6\" style=\"border-collapse:collapse;width:100%;\">\n")
			sb.WriteString("<thead><tr style=\"background:#dc2626;color:#fff;\">")
			sb.WriteString("<th>名称</th><th>本表列</th><th>引用表</th><th>引用列</th>")
			sb.WriteString("</tr></thead>\n<tbody>\n")

			for i, fk := range table.ForeignKeys {
				rowStyle := ""
				if i%2 == 0 {
					rowStyle = "background:#f9fafb;"
				}
				sb.WriteString(fmt.Sprintf(
					"<tr style=\"%s\"><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
					rowStyle, fk.Name, strings.Join(fk.Columns, ", "), fk.RefTable, strings.Join(fk.RefColumns, ", "),
				))
			}
			sb.WriteString("</tbody>\n</table>\n")
		}

		// 表选项
		if table.Engine != "" || table.Charset != "" || table.Comment != "" {
			sb.WriteString("<p style=\"color:#666;font-size:0.85rem;\">")
			if table.Engine != "" {
				sb.WriteString(fmt.Sprintf("引擎: <code>%s</code> ", table.Engine))
			}
			if table.Charset != "" {
				sb.WriteString(fmt.Sprintf("字符集: <code>%s</code>", table.Charset))
			}
			if table.Comment != "" {
				sb.WriteString(fmt.Sprintf(" 备注: %s", table.Comment))
			}
			sb.WriteString("</p>\n")
		}
	}

	return sb.String()
}

// generateMarkdownTables 生成 Markdown 表格
func (s *DDLParserService) generateMarkdownTables(tables []TableDef) string {
	var sb strings.Builder

	for _, table := range tables {
		tableLabel := table.Name
		if table.Schema != "" {
			tableLabel = table.Schema + "." + tableLabel
		}
		sb.WriteString(fmt.Sprintf("### %s\n\n", tableLabel))

		sb.WriteString("| # | 字段名 | 类型 | 允许空 | 默认值 | 主键 | 自增 | 备注 |\n")
		sb.WriteString("|---|--------|------|--------|--------|------|------|------|\n")

		for i, col := range table.Columns {
			nullableStr := "是"
			if !col.Nullable {
				nullableStr = "否"
			}
			pkStr := ""
			if col.IsPrimaryKey {
				pkStr = "✅"
			}
			autoStr := ""
			if col.AutoIncrement {
				autoStr = "✅"
			}
			defaultStr := col.DefaultValue
			if defaultStr == "" {
				defaultStr = "-"
			}
			commentStr := col.Comment
			if commentStr == "" {
				commentStr = "-"
			}

			sb.WriteString(fmt.Sprintf("| %d | `%s` | %s | %s | %s | %s | %s | %s |\n",
				i+1, col.Name, col.Type, nullableStr, defaultStr, pkStr, autoStr, commentStr))
		}

		sb.WriteString("\n")

		// 索引
		if len(table.Indexes) > 0 {
			sb.WriteString("**索引**\n\n")
			sb.WriteString("| 索引名 | 类型 | 列 | 唯一 |\n")
			sb.WriteString("|--------|------|----|------|\n")
			for _, idx := range table.Indexes {
				uniqueStr := "否"
				if idx.Unique {
					uniqueStr = "是"
				}
				sb.WriteString(fmt.Sprintf("| `%s` | %s | %s | %s |\n",
					idx.Name, idx.Type, strings.Join(idx.Columns, ", "), uniqueStr))
			}
			sb.WriteString("\n")
		}

		// 外键
		if len(table.ForeignKeys) > 0 {
			sb.WriteString("**外键**\n\n")
			sb.WriteString("| 名称 | 本表列 | 引用表 | 引用列 |\n")
			sb.WriteString("|------|--------|--------|--------|\n")
			for _, fk := range table.ForeignKeys {
				sb.WriteString(fmt.Sprintf("| `%s` | %s | `%s` | %s |\n",
					fk.Name, strings.Join(fk.Columns, ", "), fk.RefTable, strings.Join(fk.RefColumns, ", ")))
			}
			sb.WriteString("\n")
		}

		// 表选项
		if table.Engine != "" || table.Charset != "" || table.Comment != "" {
			var opts []string
			if table.Engine != "" {
				opts = append(opts, "引擎: `"+table.Engine+"`")
			}
			if table.Charset != "" {
				opts = append(opts, "字符集: `"+table.Charset+"`")
			}
			if table.Comment != "" {
				opts = append(opts, "备注: "+table.Comment)
			}
			sb.WriteString(strings.Join(opts, " | ") + "\n\n")
		}

		sb.WriteString("---\n\n")
	}

	return sb.String()
}

// toClassName 将表名转换为类名（首字母大写、驼峰）
func toClassName(tableName string) string {
	parts := strings.Split(tableName, "_")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
		}
	}
	return strings.Join(parts, "")
}
