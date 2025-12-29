//go:build !(linux && cgo && cuda) && !(windows && cgo && cuda)

package gpu

import "unsafe"

// cgoMemcpy stub for non-CUDA platforms
func cgoMemcpy(dst, src unsafe.Pointer, size int) {}

// CopyToDevice stub
func CopyToDevice(dst unsafe.Pointer, src []byte) error {
	return ErrNoCUDA
}

// CopyFromDevice stub
func CopyFromDevice(dst []byte, src unsafe.Pointer) error {
	return ErrNoCUDA
}

// CopyDeviceToDevice stub
func CopyDeviceToDevice(dst, src unsafe.Pointer, size int) error {
	return ErrNoCUDA
}

// ZeroDevice stub
func ZeroDevice(ptr unsafe.Pointer, size int) error {
	return ErrNoCUDA
}

// PinnedBuffer stub
type PinnedBuffer struct{}

func NewPinnedBuffer(size int) *PinnedBuffer {
	return nil
}

func (pb *PinnedBuffer) Free() {}

func (pb *PinnedBuffer) Pointer() unsafe.Pointer {
	return nil
}

func (pb *PinnedBuffer) Size() int {
	return 0
}

func (pb *PinnedBuffer) Bytes() []byte {
	return nil
}
