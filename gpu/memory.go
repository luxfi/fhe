//go:build (linux || windows) && cgo && cuda

package gpu

/*
#cgo LDFLAGS: -lcudart

#include <cuda_runtime.h>
#include <string.h>

// Host to device memory copy
int cuda_memcpy_htod(void* dst, void* src, size_t size) {
    return cudaMemcpy(dst, src, size, cudaMemcpyHostToDevice);
}

// Device to host memory copy
int cuda_memcpy_dtoh(void* dst, void* src, size_t size) {
    return cudaMemcpy(dst, src, size, cudaMemcpyDeviceToHost);
}

// Device to device memory copy
int cuda_memcpy_dtod(void* dst, void* src, size_t size) {
    return cudaMemcpy(dst, src, size, cudaMemcpyDeviceToDevice);
}

// Async host to device
int cuda_memcpy_htod_async(void* dst, void* src, size_t size, void* stream) {
    return cudaMemcpyAsync(dst, src, size, cudaMemcpyHostToDevice, (cudaStream_t)stream);
}

// Async device to host
int cuda_memcpy_dtoh_async(void* dst, void* src, size_t size, void* stream) {
    return cudaMemcpyAsync(dst, src, size, cudaMemcpyDeviceToHost, (cudaStream_t)stream);
}

// Set memory to zero
int cuda_memset(void* dst, int value, size_t size) {
    return cudaMemset(dst, value, size);
}

// Allocate pinned host memory for faster transfers
void* cuda_host_alloc(size_t size) {
    void* ptr = NULL;
    cudaHostAlloc(&ptr, size, cudaHostAllocDefault);
    return ptr;
}

// Free pinned host memory
void cuda_host_free(void* ptr) {
    if (ptr != NULL) {
        cudaFreeHost(ptr);
    }
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// cgoMemcpy copies data from host to GPU
func cgoMemcpy(dst, src unsafe.Pointer, size int) {
	if dst == nil || src == nil || size <= 0 {
		return
	}
	ret := C.cuda_memcpy_htod(dst, src, C.size_t(size))
	if ret != 0 {
		fmt.Printf("Warning: cudaMemcpy failed with error %d\n", ret)
	}
}

// CopyToDevice copies host memory to GPU
func CopyToDevice(dst unsafe.Pointer, src []byte) error {
	if len(src) == 0 || dst == nil {
		return nil
	}
	srcPtr := unsafe.Pointer(&src[0])
	ret := C.cuda_memcpy_htod(dst, srcPtr, C.size_t(len(src)))
	if ret != 0 {
		return fmt.Errorf("cudaMemcpy HtoD failed: %d", ret)
	}
	return nil
}

// CopyFromDevice copies GPU memory to host
func CopyFromDevice(dst []byte, src unsafe.Pointer) error {
	if len(dst) == 0 || src == nil {
		return nil
	}
	dstPtr := unsafe.Pointer(&dst[0])
	ret := C.cuda_memcpy_dtoh(dstPtr, src, C.size_t(len(dst)))
	if ret != 0 {
		return fmt.Errorf("cudaMemcpy DtoH failed: %d", ret)
	}
	return nil
}

// CopyDeviceToDevice copies between GPU memory locations
func CopyDeviceToDevice(dst, src unsafe.Pointer, size int) error {
	if dst == nil || src == nil || size <= 0 {
		return nil
	}
	ret := C.cuda_memcpy_dtod(dst, src, C.size_t(size))
	if ret != 0 {
		return fmt.Errorf("cudaMemcpy DtoD failed: %d", ret)
	}
	return nil
}

// ZeroDevice sets GPU memory to zero
func ZeroDevice(ptr unsafe.Pointer, size int) error {
	if ptr == nil || size <= 0 {
		return nil
	}
	ret := C.cuda_memset(ptr, 0, C.size_t(size))
	if ret != 0 {
		return fmt.Errorf("cudaMemset failed: %d", ret)
	}
	return nil
}

// PinnedBuffer is a host memory buffer with faster GPU transfer
type PinnedBuffer struct {
	ptr  unsafe.Pointer
	size int
}

// NewPinnedBuffer allocates pinned host memory
func NewPinnedBuffer(size int) *PinnedBuffer {
	if size <= 0 {
		return nil
	}
	ptr := C.cuda_host_alloc(C.size_t(size))
	if ptr == nil {
		return nil
	}
	return &PinnedBuffer{ptr: ptr, size: size}
}

// Free releases the pinned buffer
func (pb *PinnedBuffer) Free() {
	if pb.ptr != nil {
		C.cuda_host_free(pb.ptr)
		pb.ptr = nil
	}
}

// Pointer returns the buffer pointer
func (pb *PinnedBuffer) Pointer() unsafe.Pointer {
	return pb.ptr
}

// Size returns the buffer size
func (pb *PinnedBuffer) Size() int {
	return pb.size
}

// Bytes returns the buffer as a byte slice (for reading/writing)
func (pb *PinnedBuffer) Bytes() []byte {
	if pb.ptr == nil {
		return nil
	}
	return unsafe.Slice((*byte)(pb.ptr), pb.size)
}
