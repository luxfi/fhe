module github.com/luxfi/fhe

go 1.25.5

require (
	github.com/luxfi/gpu v0.29.4
	github.com/luxfi/lattice/v7 v7.0.0
	github.com/redis/go-redis/v9 v9.7.0
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/ALTree/bigfloat v0.2.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/exp v0.0.0-20250506013437-ce4c2cf36ca6 // indirect
	golang.org/x/sys v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// GPU bindings require local C++ compilation
// TODO: Rename github.com/luxfi/mlx to github.com/luxfi/gpu to fix module path
replace github.com/luxfi/gpu => /Users/z/work/luxcpp/gpu
