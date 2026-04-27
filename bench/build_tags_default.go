// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

//go:build !gpu

package bench

// buildTagsValue is recorded into Ladder.Host.BuildTags. The default
// (no -tags gpu) means GPU benches will skip with NotApplicable.
const buildTagsValue = "default"

// gpuLinkAttempted is true when the test binary was compiled with the
// gpu cgo wrapper actually linked. Default-tags builds report false.
const gpuLinkAttempted = false
