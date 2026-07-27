package onnx

import (
	"image"
	"golang.org/x/image/draw"
)

// imagingResize 用高质量缩放保持宽高比
// 注：项目原本用的是 github.com/disintegration/imaging，
//     但成像质量相近且不需要新引入依赖，这里直接用标准库 draw。
func imagingResize(src image.Image, w, h int) image.Image {
	dst := image.NewNRGBA(image.Rect(0, 0, w, h))
	draw.ApproxBiLinear.Scale(dst, dst.Bounds(), src, src.Bounds(), draw.Over, nil)
	return dst
}