package anonymization

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
)

var (
	Debug string = "off"

	stderr *bufio.Writer = nil

	// full path or only file name (function name)?
	fullPath = false

	// control debugging only from this file
	dbgAllowed bool

	// control debugging by calling DbgOn() on a per function basis
	dbgFlag = false

	callers [1]uintptr
)

func init() {
	if strings.ToLower(Debug) == "on" {
		dbgAllowed = true
	} else {
		dbgAllowed = false
	}
}

func DbgOn() bool {
	prev := dbgFlag
	if dbgAllowed {
		dbgFlag = true
	}
	return prev
}

func DbgRestore(dbg bool) {
	dbgFlag = dbg
}

func DbgOff() bool {
	prev := dbgFlag
	dbgFlag = false
	return prev
}

func Dbg(format string, args ...interface{}) {
	if dbgFlag {
		if stderr == nil {
			stderr = bufio.NewWriter(os.Stderr)
		}
		msg := fmt.Sprintf(format, args...)
		defer func() {
			fmt.Fprintln(stderr, msg)
			stderr.Flush()
		}()
		n := runtime.Callers(2, callers[:])
		if n == 0 {
			return
		}
		frames := runtime.CallersFrames(callers[:])
		if frames == nil {
			return
		}
		frame, _ := frames.Next()
		name := frame.Func.Name()
		file, line := frame.Func.FileLine(callers[0])
		if !fullPath {
			name = path.Base(name)
			file = path.Base(file)
		}
		fln := fmt.Sprintf("%s:%d, %s: ", file, line, name)
		msg = fln + msg
	}
}
