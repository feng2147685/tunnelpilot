package api

import (
	"embed"
	"io"
	"os"
)

//go:embed web
var webFS embed.FS

func readAllInto(dst *os.File, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}
