// icongen 生成 macOS 应用图标（.icns）。
// 纯 Go 逐像素绘制并做超采样抗锯齿，不依赖任何图形库或设计工具。
//
// 用法: go run ./tools/icongen -o build/AppIcon.icns
package main

import (
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	out := flag.String("o", "build/AppIcon.icns", "输出的 .icns 路径")
	flag.Parse()

	iconsetDir := "build/AppIcon.iconset"
	if err := os.MkdirAll(iconsetDir, 0755); err != nil {
		fmt.Fprintln(os.Stderr, "创建目录失败:", err)
		os.Exit(1)
	}

	sizes := []struct {
		name string
		px   int
	}{
		{"icon_16x16.png", 16},
		{"icon_16x16@2x.png", 32},
		{"icon_32x32.png", 32},
		{"icon_32x32@2x.png", 64},
		{"icon_128x128.png", 128},
		{"icon_128x128@2x.png", 256},
		{"icon_256x256.png", 256},
		{"icon_256x256@2x.png", 512},
		{"icon_512x512.png", 512},
		{"icon_512x512@2x.png", 1024},
	}

	for _, s := range sizes {
		img := renderIcon(s.px)
		path := filepath.Join(iconsetDir, s.name)
		f, err := os.Create(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "创建文件失败:", err)
			os.Exit(1)
		}
		if err = png.Encode(f, img); err != nil {
			f.Close()
			fmt.Fprintln(os.Stderr, "编码 PNG 失败:", err)
			os.Exit(1)
		}
		f.Close()
		fmt.Printf("  生成 %s (%dx%d)\n", s.name, s.px, s.px)
	}

	if err := os.MkdirAll(filepath.Dir(*out), 0755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cmd := exec.Command("iconutil", "-c", "icns", iconsetDir, "-o", *out)
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "iconutil 打包失败: %v\n%s\n", err, string(output))
		os.Exit(1)
	}
	fmt.Println("已生成:", *out)
}

// renderIcon 以超采样方式渲染指定尺寸的图标
func renderIcon(size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4 // 每像素 4x4 采样
	scale := float64(size)
	inv := 1.0 / float64(ss*ss)

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var sr, sg, sb, sa float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/ss) / scale
					py := (float64(y) + (float64(sy)+0.5)/ss) / scale
					r, g, b, a := sample(px, py)
					sr += r * a
					sg += g * a
					sb += b * a
					sa += a
				}
			}
			var r, g, b float64
			if sa > 0 {
				r = sr / sa
				g = sg / sa
				b = sb / sa
			}
			img.SetNRGBA(x, y, color.NRGBA{
				R: to8(r), G: to8(g), B: to8(b), A: to8(sa * inv),
			})
		}
	}
	return img
}

// sample 返回归一化坐标处的颜色与覆盖率
func sample(px, py float64) (float64, float64, float64, float64) {
	// 圆角矩形背景（macOS 图标四周留白约 9%）
	if roundedRectSDF(px, py, 0.5, 0.5, 0.41, 0.41, 0.185) > 0 {
		return 0, 0, 0, 0
	}

	// 径向渐变：中心亮蓝 -> 边缘深蓝
	dx := px - 0.5
	dy := py - 0.44
	dist := math.Hypot(dx, dy) / 0.62
	if dist > 1 {
		dist = 1
	}
	t := smoothstep(dist)
	br := lerp(0.21, 0.032, t)
	bg := lerp(0.54, 0.082, t)
	bb := lerp(0.94, 0.20, t)

	// 字母 p：圆碗 + 竖干（笔画比参考图略细，小尺寸下更清晰）
	bowlCx, bowlCy, bowlR := 0.570, 0.510, 0.184
	ringDist := math.Abs(math.Hypot(px-bowlCx, py-bowlCy) - bowlR)
	onRing := ringDist < 0.036

	stemHalfW, stemHalfH := 0.036, 0.245
	onStem := rectSDF(px, py, 0.386, 0.550, stemHalfW, stemHalfH) < 0

	if onRing || onStem {
		// 白色字母，顶部略亮，底部带一点冷色，避免纯白显得死板
		shade := smoothstep(clamp((py-0.20)/0.62, 0, 1))
		return lerp(1.0, 0.86, shade*0.55), lerp(1.0, 0.92, shade*0.55), 1.0, 1.0
	}

	// 图标内部一层极淡的高光，模拟参考图的玻璃质感
	high := 1.0 - clamp(math.Hypot(px-0.5, py-0.22)/0.42, 0, 1)
	br += high * 0.035
	bg += high * 0.045
	bb += high * 0.05

	return br, bg, bb, 1.0
}

func roundedRectSDF(px, py, cx, cy, hw, hh, r float64) float64 {
	qx := math.Abs(px-cx) - hw + r
	qy := math.Abs(py-cy) - hh + r
	ax := math.Max(qx, 0)
	ay := math.Max(qy, 0)
	return math.Min(math.Max(qx, qy), 0) + math.Hypot(ax, ay) - r
}

func rectSDF(px, py, cx, cy, hw, hh float64) float64 {
	qx := math.Abs(px-cx) - hw
	qy := math.Abs(py-cy) - hh
	ax := math.Max(qx, 0)
	ay := math.Max(qy, 0)
	return math.Min(math.Max(qx, qy), 0) + math.Hypot(ax, ay)
}

func smoothstep(t float64) float64 {
	t = clamp(t, 0, 1)
	return t * t * (3 - 2*t)
}

func clamp(v, lo, hi float64) float64 {
	return math.Min(math.Max(v, lo), hi)
}

func lerp(a, b, t float64) float64 {
	return a + (b-a)*t
}

func to8(v float64) uint8 {
	v = clamp(v, 0, 1)
	return uint8(v*255 + 0.5)
}
