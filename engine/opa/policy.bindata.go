// Code generated by go-bindata. DO NOT EDIT.
// sources:
// policy/authz.rego (2.226kB)
// policy/common.rego (2.02kB)
// policy/introspection.rego (1.864kB)

package opa

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("read %q: %w", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes  []byte
	info   os.FileInfo
	digest [sha256.Size]byte
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (fi bindataFileInfo) Name() string {
	return fi.name
}
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}
func (fi bindataFileInfo) IsDir() bool {
	return false
}
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _policyAuthzRego = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xac\x55\x51\x6e\xab\x3a\x10\xfd\x8e\x57\x31\x8f\xaf\x50\xa1\x2c\xa0\x12\x2b\x41\x08\x39\x30\x79\x71\xaf\xc1\xc8\x36\xad\xda\x2a\x7b\xbf\xb2\xc7\x76\xa0\x21\x25\x91\xee\x17\xcc\xf1\x99\x39\xc7\xc3\xd8\x8c\xbc\xfd\xc3\xff\x47\xe0\x93\x3d\x7f\x31\x26\xfa\x51\x69\x0b\x1d\xb7\xfc\xd0\xaa\xbe\x57\xc3\x02\x1a\x95\x14\xad\x40\xb3\x00\xb5\x92\x68\x18\xeb\xf0\xc4\x27\x69\x7d\x25\xa5\xc5\x17\x76\x50\xc2\x89\x4b\x83\x8c\x9d\xb9\x69\x7a\xec\x8f\xa8\xab\x51\xc9\x46\x74\x35\x7c\xb3\x9d\x7b\x35\xd3\x11\x5e\x4b\x88\x85\xe3\xf2\x81\xd8\xa6\x6a\x6a\xb6\x13\xc3\x38\xd9\xc8\xf4\xc1\xc1\x4c\xc7\x37\x6c\x2d\xad\x93\xd1\x88\x35\x3d\xb7\xed\x19\xcd\x3e\xa5\x15\x10\x94\x72\x76\x21\x2f\x1a\x8d\x9a\x74\x8b\x55\xd0\x2b\xc0\x58\x6e\xb1\xc7\xc1\x3a\x75\xef\xee\x8a\x44\xf6\xaa\xd1\x44\x33\xd5\xa2\xc6\x21\x66\x2d\x3c\x46\x70\x69\x32\xc1\x73\x1f\x11\xf3\xa6\x07\xd5\x7c\x08\xd9\xb5\x5c\x77\x7b\x9e\x3b\x7b\xad\x1a\x2c\x17\x83\xd9\xf3\x02\xb2\x97\x2c\x87\x32\x76\xfb\xc2\x18\x6f\xad\x50\xc3\x4c\xc4\x15\x56\x1a\x3b\x9f\x3a\x2f\x16\x60\xd7\x64\x57\x81\xc2\x8d\x12\x25\xcc\x17\xf7\x66\x94\xc2\x86\x42\x05\x64\xaf\x59\x5e\x00\x61\x2e\xc9\xc5\xf9\xb2\xdc\xbe\x32\xa8\xdf\x85\xdb\x6e\xf6\x92\xd5\x05\x5c\xe3\xa6\x80\xa6\x76\x0a\x56\x4f\x78\x37\xcb\x7e\x8e\x2b\xb9\x84\x3e\x90\x9e\xbd\x64\x05\xbc\xa3\x3e\xfe\x94\xf6\xd8\xbd\xf4\x45\x56\xf3\x10\xbf\x2e\xa0\xb9\x2e\xbb\xc1\x23\xca\x63\x63\x47\xdc\xe7\x86\x8e\x72\x68\xe4\x6e\xbe\xa0\x9b\x34\x02\xe7\xc2\x84\xa4\xa3\xb1\xed\xf0\x89\x23\xa0\x24\x42\x09\xee\xd1\x88\x8e\xed\xfc\x4d\x51\x85\x70\x6e\x36\x92\x08\xd9\xb0\x3e\x63\x26\xd7\xa3\x56\xee\xec\x57\x55\x78\xa1\x23\x7f\xc7\xbf\x56\x6f\xcf\x75\x35\x14\xa5\xb6\xc6\xc0\x97\xa0\xf7\x64\xd4\xc5\x79\xa2\xcc\x18\x3e\xf5\xc2\xd8\x6a\x02\x5c\x69\xc9\x5f\x59\x42\xb8\x32\x5a\x35\x18\xdb\x70\x29\xe3\x26\xcd\xd2\x03\x35\x27\xad\x3d\x23\xf2\xdf\xa6\x08\xfc\xac\x7f\xd3\x02\xdf\x71\xbf\x37\x2f\x57\x55\x78\x3a\x6d\x7c\x00\x62\x3c\xf7\x09\x28\x87\xed\x6e\xff\x24\x84\x6d\xdd\xe8\xc4\xfa\x7d\xb8\xfd\xb5\x27\xa5\xfa\x70\x26\xc3\x6e\x32\x0f\x64\xe1\x66\xf2\x94\x0e\x87\xcf\x39\xc3\xc5\x0b\xc2\xec\x0f\xf8\xcd\x76\xbe\x80\xbb\x74\x2d\x38\x66\x12\xc1\x2e\x4d\x6d\x78\xd6\x6b\xba\xbf\x6d\xe7\xd1\xa9\x0f\xae\xc5\x86\x64\xd8\xc8\xbf\x52\xbc\xb6\x61\x55\xf5\x5e\x13\x52\xab\xd6\xec\xb2\x0b\xfb\x1b\x00\x00\xff\xff\xa3\x58\xea\x7b\xb2\x08\x00\x00")

func policyAuthzRegoBytes() ([]byte, error) {
	return bindataRead(
		_policyAuthzRego,
		"policy/authz.rego",
	)
}

func policyAuthzRego() (*asset, error) {
	bytes, err := policyAuthzRegoBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "policy/authz.rego", size: 2226, mode: os.FileMode(0666), modTime: time.Unix(1667147659, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x9a, 0xcf, 0x91, 0xcf, 0x4e, 0x13, 0x49, 0x1a, 0x5, 0x27, 0xa7, 0x99, 0xbb, 0x35, 0x78, 0x55, 0x2d, 0x62, 0x11, 0xf4, 0x2e, 0xc6, 0xd1, 0x17, 0xa6, 0x10, 0x5, 0x86, 0xfd, 0x53, 0xed, 0x6f}}
	return a, nil
}

var _policyCommonRego = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xa4\x54\xc1\x6e\x1b\x37\x10\x3d\x9b\x5f\x31\xdd\x0d\x20\xc9\x58\x4b\x45\x2f\x45\x17\xd5\xc1\x48\x7a\x29\x82\x34\x48\x8c\x5e\x82\x40\x98\xe5\x8e\xb4\xac\x57\x24\xc1\x19\x5a\x56\x0c\xfb\xdb\x0b\x72\xb5\xb2\xad\xb4\x88\xd3\xea\x24\x72\xe7\xbd\xc7\x79\xf3\xc8\x12\xde\xa3\xbe\xc6\x0d\x81\x76\xdb\xad\xb3\xa0\x9d\x15\x34\x96\x61\x1d\xad\x16\xe3\x2c\x03\xda\x16\x42\xec\x89\x41\x3a\x14\xc0\x40\xc0\x1d\x06\x6a\x55\x09\x0d\xc9\x8e\xc8\x82\x74\x04\x18\xa5\xfb\x92\xab\x8d\x95\xe0\xd8\x53\x26\x80\x40\x1b\x07\xbd\xdb\x18\xad\xfc\x33\x31\xa5\xb4\xb3\x2c\x2b\xec\xfb\x95\x0f\xee\x2f\xd2\xc2\xb0\x84\xe2\xe1\xe1\xf2\xed\xdb\x8b\xf7\x1f\xfe\xf8\xfd\xb7\xd7\x57\x1f\x1f\x1e\x0a\xa5\x4a\x55\xc2\x9f\x18\x0c\x36\x3d\x01\xdd\x7a\xb4\x6c\x9c\x55\xa5\x52\xd6\xad\x6e\x0e\x1f\x78\x8a\x33\xb8\x53\x67\x63\x0f\x53\xac\xa0\x78\x75\x57\xcc\x60\xb9\x84\x35\xf6\x4c\xea\x5e\xa9\xd3\x6a\x63\x5b\xba\x75\xeb\xc7\xe2\x5f\xe1\xe9\xd6\x7d\x31\x4b\xa8\x12\xde\xd0\xda\xd8\x6c\x02\x1d\xcd\x81\x49\x3e\x4b\x3b\x81\x5d\x67\x74\x07\x81\x24\x06\xcb\x60\x84\xe1\x06\xfb\x48\x70\x63\x30\x23\x5c\x14\x1f\x05\x46\x71\x55\x8e\x50\x6a\x27\x73\x55\xc2\x3b\x27\x54\x83\x8e\x21\x90\x95\x7e\x5f\x81\xb3\xfd\x7e\xe8\xb4\x1d\x34\x9d\xa5\x23\x1c\x76\x04\xd7\xd6\xed\x6a\x78\x75\x87\x3f\xd5\x91\x29\x58\xdc\xd2\xfd\x5c\x0d\x88\xa9\x0b\x66\x33\x83\x25\x8c\x1a\xa9\x51\xf6\xbd\x91\xa9\xb1\x3e\xca\x9c\x63\x93\xed\xfe\xb4\xfa\x5c\x41\x51\x17\x15\x7c\x2a\x12\x4b\x51\xc1\xaa\x82\x91\xef\xf3\x4c\x9d\x1d\x19\xea\x25\x04\xf2\x3d\x6a\xca\xec\xd9\xad\xa7\xda\xc5\x23\x2e\x3b\xb6\x33\x7d\xab\x31\xb4\x07\x9b\xc9\xb6\xbc\x33\xd2\x65\x53\xeb\xf3\xd1\xd5\xd7\x1d\xe9\xeb\x21\x58\x46\xa0\x75\xc4\x60\x9d\x00\xd9\x16\x52\x75\x2e\x85\xcb\x77\x6f\x8e\x25\x66\x28\x40\x60\xd7\x1b\xc1\xb0\x87\xe2\xbc\x78\x74\xf0\xaa\x23\xe8\x51\x84\x42\xaa\x6c\x93\x69\xec\x06\xf0\x8e\xd2\x7a\x32\x90\x47\x3f\xf0\x4f\x06\x3f\x02\xb1\x8b\x41\x13\x2c\xe1\x7c\xa2\xca\x43\xde\x8d\x05\x17\x03\x78\x0c\x62\xb0\x87\x40\x1c\x7b\xe1\x51\xec\xc8\x8a\x37\xce\xb4\x50\x58\x27\x45\x75\x08\x42\x97\x22\x14\xf8\x04\x0a\xce\x8b\xd9\x9a\x2f\x98\x2f\x56\x05\x4c\x29\x08\x9d\x88\xe7\x7a\xb1\xd8\x18\xe9\x62\x33\xd7\x6e\xbb\x70\x9e\xec\x85\x77\xbd\xd1\xfb\x0b\xdc\x90\x95\x85\xf3\xb8\x30\xcc\x91\x78\xf1\xf3\x8f\xbf\xcc\x95\x75\xb2\xfa\x96\xc3\x8f\xb1\x3f\x43\xf8\x61\x99\x8c\x1a\x4c\xbf\xea\x0c\x03\x47\xef\x5d\x90\x1c\x2e\x26\x68\x22\xa7\x78\xf3\xd0\x7a\xad\x4a\x48\xb4\x97\x30\x8a\xc0\x16\xf7\x43\x28\x9d\xd6\x31\x24\x6f\x24\x7b\xcd\x02\x3c\xdc\xf4\x64\xcc\xb4\xf9\x0a\x94\xc6\xd5\xe4\x3b\xdf\x18\x4b\x87\xb9\x22\xf8\x40\x6b\x73\x0b\x53\x9a\x6f\xe6\xa0\xd1\xa6\x32\xc6\x3d\x14\xb7\xf5\xbe\x5e\x3b\x77\x5e\xcc\x32\xa1\x7e\x46\x88\xde\xf7\x26\xdd\x42\x97\xe5\x0f\x17\x66\x3c\x41\x7e\x7d\xd0\xee\xa1\x25\xf2\x14\xc6\x6d\x56\x25\xa4\xdf\xa0\x55\x60\xca\xd4\x16\x45\x77\xc4\x69\xd5\x14\x19\x97\xfe\xd5\xba\xa8\x80\x44\xcf\x67\xf3\x63\x80\x57\xb9\x34\xb9\xda\x64\x9f\x59\x30\xc8\xd1\x69\x09\x66\x3b\x6d\xaa\x64\xee\x6c\xc8\xb4\x2a\xe1\xc3\x18\xa7\x0c\x35\x76\xa3\x4a\x35\x46\x6c\x75\x50\x9e\x1a\x5b\x01\x8b\x0b\xd4\x66\xda\x67\x0f\xd9\x61\x3f\xed\x3e\x99\xf3\x71\xd7\xd8\x34\xdb\x61\x99\x34\xff\x1b\xf7\xd7\xbc\x27\x2d\x3f\x61\x79\x89\xca\x77\x1e\xff\xf0\x54\xfd\x3f\x81\x17\xf5\xf0\x5c\xe9\x9f\xa5\x56\xc3\x08\x61\x09\x12\x22\x0d\x63\xfc\x38\xbc\x92\x4f\xa7\x78\x78\x38\xff\xdd\xe8\x97\x8c\xeb\x1b\x24\xdf\x3b\x97\x53\xba\x93\x56\xfe\x0e\x00\x00\xff\xff\x76\xb1\x2c\x2c\xe4\x07\x00\x00")

func policyCommonRegoBytes() ([]byte, error) {
	return bindataRead(
		_policyCommonRego,
		"policy/common.rego",
	)
}

func policyCommonRego() (*asset, error) {
	bytes, err := policyCommonRegoBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "policy/common.rego", size: 2020, mode: os.FileMode(0666), modTime: time.Unix(1667147659, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x95, 0x7d, 0xa0, 0x87, 0xb1, 0xc, 0x98, 0x88, 0x2f, 0xea, 0x7b, 0x43, 0xd6, 0xf9, 0x73, 0x24, 0x20, 0x82, 0xbf, 0x80, 0x6c, 0xd2, 0x88, 0x43, 0xd9, 0xf8, 0x65, 0x15, 0xb2, 0x65, 0xf, 0x2}}
	return a, nil
}

var _policyIntrospectionRego = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xbc\x55\xcd\x6e\xdb\x30\x0c\x3e\x5b\x4f\x41\x24\x87\x6e\x40\xe6\x07\x28\xe0\x47\xd8\x4e\xbb\x19\x81\xc1\x48\x4c\xad\xd5\x16\x0d\x89\x4e\x91\x0e\x7d\xf7\x41\x92\xdd\x38\x3f\x1d\xba\x6e\xd8\xc9\x16\xf5\xf1\x13\xbf\x8f\xb4\x3c\xa0\x7e\xc4\x07\x02\x1c\xa5\x7d\x2e\xad\x13\xcf\x61\x20\x2d\x96\x9d\x52\xb6\x1f\xd8\x0b\x18\x14\x2c\x13\x00\x30\x64\xe4\xd9\x96\xe6\xbe\x67\x77\x16\x1a\xb8\xb3\xda\x52\x38\x0b\x7a\xee\x28\x28\xa5\xd9\x05\x69\xc2\x31\x08\xf5\x8d\x1c\x07\x82\x0a\x56\x79\xb9\x52\x6a\x40\xeb\x9b\x1e\x45\xb7\x14\x1a\x4f\x81\x47\xaf\xa9\xae\x07\xee\x1a\x6b\x36\x10\x04\x85\x7a\x72\x92\x56\x11\xbc\xdd\xc2\x4f\x55\xcc\x07\x4e\xc0\x6d\xf9\x0a\x0c\xf5\x32\x67\x5b\xce\x9c\xa1\x6e\xb6\x50\x2d\x08\xe7\x0d\x55\x58\x37\x8c\x52\x46\xf2\x09\x14\x5f\x55\x91\x75\xbe\x12\xcc\x55\x7e\x8a\xbb\xaf\xd1\xcd\x0d\xc6\xcf\xea\xe5\x42\x18\x26\x87\xff\xa5\xac\xcc\x78\x25\x2a\x87\xdf\x94\x94\xdb\x9e\x41\xe7\x7a\x72\x6c\x73\x45\xf5\x3f\xb4\xc4\x41\x81\x0a\xe2\xa3\xb1\x46\x15\x69\x70\xea\x69\x79\x21\x35\x45\xff\x5a\xe5\x82\x25\x09\x5c\xc3\xf7\xd6\x06\xd0\x38\x06\x0a\x20\x2d\x41\x8b\xa1\xe9\xa9\xdf\x91\x87\x40\x02\xc2\xb0\x23\x78\x20\x47\x1e\x85\x0c\xa0\x33\xd0\x53\xcf\xf6\x99\x0c\xb0\xd3\x04\xd6\x05\x21\x34\xc0\x7b\xb5\x86\x3d\x7b\x20\xd4\x2d\x24\x13\x8e\x25\x7c\x65\x4f\x7c\x20\x0f\x56\x60\xf0\x74\x88\x2e\xa4\x73\x76\xa8\x1f\xc5\xa3\x7e\xb4\xee\x01\xf6\x9e\xfb\xf9\x90\xb8\x36\xe3\xd0\x59\x8d\x42\x6a\x0d\xe8\xc2\x13\xf9\x98\x84\x02\x2d\x1e\x68\xaa\x89\x0e\xd8\x8d\xa9\xa6\xdd\x31\x31\xce\x53\x98\x6a\xcc\x1a\x21\x9b\xe0\x43\xa9\x16\xba\xaa\xe9\x16\x38\x85\x94\x4a\xc0\x26\x7a\x55\xd7\xb4\xdf\x93\x96\xdc\xd2\x0d\xdc\x6a\x77\x6e\x74\xc6\xc1\x7d\x05\xef\x6f\x79\xce\x51\xc5\xe9\xec\x39\x47\x15\x1f\xb8\x12\x2e\x92\xde\x33\xa2\xb9\xed\xdf\x58\xe8\x3e\x3a\xe9\x49\x46\xef\x92\x81\x61\xdc\xc5\x96\xf3\x3e\xad\xa2\x47\xec\x53\x9f\xd3\xa0\xcd\xf1\xc1\xf3\xc1\x1a\x32\x90\x86\x70\xa3\xd6\xc0\xa3\x07\x3f\x76\x14\xa0\x1f\x83\xc0\x2a\x53\xae\x12\xfa\x2e\xe6\xde\xe5\x7b\x51\x61\xd7\xf1\x13\x99\x6c\x73\xaa\x26\xda\xb8\xb4\x7e\x95\x20\xab\xd9\xfb\x66\x03\x4d\xae\xd8\x90\xb3\xbf\xcf\x34\xe4\x8e\x37\x12\x4f\x32\x12\x30\x36\x7f\x51\x05\x7c\x81\x05\xb3\x3a\x55\xe8\xf9\x07\x69\xa9\xa7\x67\xfe\xae\xf3\xfb\x9f\xf5\x7b\x4a\x8a\x9f\xa9\x2a\x26\x75\x50\x7d\x64\x62\x2e\x67\xf6\x34\x37\x8e\xe5\x9a\x2f\xff\x70\x2a\xb8\xfa\x0b\x5d\x9a\x72\x43\xe9\x5b\x2e\xa8\x17\xf5\x2b\x00\x00\xff\xff\x99\x2c\x87\x8f\x48\x07\x00\x00")

func policyIntrospectionRegoBytes() ([]byte, error) {
	return bindataRead(
		_policyIntrospectionRego,
		"policy/introspection.rego",
	)
}

func policyIntrospectionRego() (*asset, error) {
	bytes, err := policyIntrospectionRegoBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "policy/introspection.rego", size: 1864, mode: os.FileMode(0666), modTime: time.Unix(1667147659, 0)}
	a := &asset{bytes: bytes, info: info, digest: [32]uint8{0x6a, 0xd8, 0x5e, 0x31, 0x75, 0xc4, 0x59, 0xad, 0xf6, 0xef, 0x6, 0xa6, 0x62, 0xe0, 0x63, 0x18, 0xff, 0xdd, 0xd3, 0xf5, 0xaf, 0x6, 0xe6, 0x68, 0xfc, 0x6f, 0x5c, 0x62, 0x38, 0x68, 0xcb, 0x6e}}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// AssetString returns the asset contents as a string (instead of a []byte).
func AssetString(name string) (string, error) {
	data, err := Asset(name)
	return string(data), err
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// MustAssetString is like AssetString but panics when Asset would return an
// error. It simplifies safe initialization of global variables.
func MustAssetString(name string) string {
	return string(MustAsset(name))
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetDigest returns the digest of the file with the given name. It returns an
// error if the asset could not be found or the digest could not be loaded.
func AssetDigest(name string) ([sha256.Size]byte, error) {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[canonicalName]; ok {
		a, err := f()
		if err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("AssetDigest %s can't read by error: %v", name, err)
		}
		return a.digest, nil
	}
	return [sha256.Size]byte{}, fmt.Errorf("AssetDigest %s not found", name)
}

// Digests returns a map of all known files and their checksums.
func Digests() (map[string][sha256.Size]byte, error) {
	mp := make(map[string][sha256.Size]byte, len(_bindata))
	for name := range _bindata {
		a, err := _bindata[name]()
		if err != nil {
			return nil, err
		}
		mp[name] = a.digest
	}
	return mp, nil
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"policy/authz.rego":         policyAuthzRego,
	"policy/common.rego":        policyCommonRego,
	"policy/introspection.rego": policyIntrospectionRego,
}

// AssetDebug is true if the assets were built with the debug flag enabled.
const AssetDebug = false

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//
//	data/
//	  foo.txt
//	  img/
//	    a.png
//	    b.png
//
// then AssetDir("data") would return []string{"foo.txt", "img"},
// AssetDir("data/img") would return []string{"a.png", "b.png"},
// AssetDir("foo.txt") and AssetDir("notexist") would return an error, and
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		canonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(canonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"policy": {nil, map[string]*bintree{
		"authz.rego":         {policyAuthzRego, map[string]*bintree{}},
		"common.rego":        {policyCommonRego, map[string]*bintree{}},
		"introspection.rego": {policyIntrospectionRego, map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory.
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = os.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	return os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
}

// RestoreAssets restores an asset under the given directory recursively.
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	canonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(canonicalName, "/")...)...)
}
