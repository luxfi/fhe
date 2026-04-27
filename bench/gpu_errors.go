// Copyright (c) 2026, Lux Industries Inc
// SPDX-License-Identifier: BSD-3-Clause

package bench

import "errors"

// errGPUDisabled is returned by GPU paths when the binary was not built
// with -tags gpu. Cells use it to skip with NotApplicable.
var errGPUDisabled = errors.New("gpu disabled: rebuild with -tags gpu")
