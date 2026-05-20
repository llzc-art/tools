package handler

import (
	"encoding/json"

	"github.com/valyala/fasthttp"
	"lelezc.com/tools/internal/database"
	"lelezc.com/tools/pkg/logger"
	"lelezc.com/tools/pkg/response"
)

// --- 笔记目录 ---

// NoteFolderList 获取所有笔记目录
func NoteFolderList(ctx *fasthttp.RequestCtx) {
	folders, err := database.ListNoteFolders()
	if err != nil {
		logger.Errorc("NoteFolderList", "查询失败: "+err.Error())
		response.Error(ctx, 5000, "查询失败")
		return
	}
	if folders == nil {
		folders = []database.NoteFolder{}
	}
	response.Success(ctx, folders)
}

// NoteFolderCreate 创建笔记目录
func NoteFolderCreate(ctx *fasthttp.RequestCtx) {
	var req struct {
		Name     string `json:"name"`
		ParentID int64  `json:"parent_id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Name == "" {
		response.Error(ctx, 1001, "目录名称不能为空")
		return
	}

	f := &database.NoteFolder{
		Name:     req.Name,
		ParentID: req.ParentID,
	}
	if err := database.CreateNoteFolder(f); err != nil {
		logger.Errorc("NoteFolderCreate", "创建失败: "+err.Error())
		response.Error(ctx, 5000, "创建失败")
		return
	}
	response.Success(ctx, f)
}

// NoteFolderUpdate 更新笔记目录
func NoteFolderUpdate(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		ParentID int64  `json:"parent_id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.ID == 0 {
		response.Error(ctx, 1001, "ID 不能为空")
		return
	}
	if req.Name == "" {
		response.Error(ctx, 1001, "目录名称不能为空")
		return
	}

	f := &database.NoteFolder{
		ID:       req.ID,
		Name:     req.Name,
		ParentID: req.ParentID,
	}
	if err := database.UpdateNoteFolder(f); err != nil {
		logger.Errorc("NoteFolderUpdate", "更新失败: "+err.Error())
		response.Error(ctx, 5000, "更新失败")
		return
	}
	response.Success(ctx, nil)
}

// NoteFolderDelete 删除笔记目录
func NoteFolderDelete(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if err := database.DeleteNoteFolder(req.ID); err != nil {
		logger.Errorc("NoteFolderDelete", "删除失败: "+err.Error())
		response.Error(ctx, 5000, "删除失败")
		return
	}
	response.Success(ctx, nil)
}

// --- 笔记文档 ---

// NoteDocumentList 获取目录下的文档列表
func NoteDocumentList(ctx *fasthttp.RequestCtx) {
	var req struct {
		FolderID int64 `json:"folder_id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}

	docs, err := database.ListNoteDocuments(req.FolderID)
	if err != nil {
		logger.Errorc("NoteDocumentList", "查询失败: "+err.Error())
		response.Error(ctx, 5000, "查询失败")
		return
	}
	if docs == nil {
		docs = []database.NoteDocument{}
	}
	response.Success(ctx, docs)
}

// NoteDocumentGet 获取单个文档
func NoteDocumentGet(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}

	doc, err := database.GetNoteDocument(req.ID)
	if err != nil {
		logger.Errorc("NoteDocumentGet", "查询失败: "+err.Error())
		response.Error(ctx, 5000, "查询失败")
		return
	}
	if doc == nil {
		response.Error(ctx, 2001, "文档不存在")
		return
	}
	response.Success(ctx, doc)
}

// NoteDocumentCreate 创建笔记文档
func NoteDocumentCreate(ctx *fasthttp.RequestCtx) {
	var req struct {
		FolderID int64  `json:"folder_id"`
		Title    string `json:"title"`
		Content  string `json:"content"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.Title == "" {
		response.Error(ctx, 1001, "文档标题不能为空")
		return
	}

	d := &database.NoteDocument{
		FolderID: req.FolderID,
		Title:    req.Title,
		Content:  req.Content,
	}
	if err := database.CreateNoteDocument(d); err != nil {
		logger.Errorc("NoteDocumentCreate", "创建失败: "+err.Error())
		response.Error(ctx, 5000, "创建失败")
		return
	}
	response.Success(ctx, d)
}

// NoteDocumentUpdate 更新笔记文档
func NoteDocumentUpdate(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID       int64  `json:"id"`
		FolderID int64  `json:"folder_id"`
		Title    string `json:"title"`
		Content  string `json:"content"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if req.ID == 0 {
		response.Error(ctx, 1001, "ID 不能为空")
		return
	}
	if req.Title == "" {
		response.Error(ctx, 1001, "文档标题不能为空")
		return
	}

	d := &database.NoteDocument{
		ID:       req.ID,
		FolderID: req.FolderID,
		Title:    req.Title,
		Content:  req.Content,
	}
	if err := database.UpdateNoteDocument(d); err != nil {
		logger.Errorc("NoteDocumentUpdate", "更新失败: "+err.Error())
		response.Error(ctx, 5000, "更新失败")
		return
	}
	response.Success(ctx, nil)
}

// NoteDocumentDelete 删除笔记文档
func NoteDocumentDelete(ctx *fasthttp.RequestCtx) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		response.Error(ctx, 1001, "参数错误")
		return
	}
	if err := database.DeleteNoteDocument(req.ID); err != nil {
		logger.Errorc("NoteDocumentDelete", "删除失败: "+err.Error())
		response.Error(ctx, 5000, "删除失败")
		return
	}
	response.Success(ctx, nil)
}
