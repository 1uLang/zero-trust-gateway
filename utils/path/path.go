package path

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

var DS = string(os.PathSeparator)

var configDir string
var isTesting = checkIsTesting()
var Root string

// 初始化
func init() {
	Root = findRoot()
}

// 判断是否在测试模式下
func IsTesting() bool {
	return isTesting
}

func checkIsTesting() bool {
	execFile := filepath.Base(os.Args[0])
	return execFile == "main" ||
		execFile == "main.exe" ||
		strings.HasPrefix(execFile, "___") ||
		strings.HasSuffix(execFile, ".test") ||
		strings.HasSuffix(execFile, ".test.exe")
}

func LogDir() string {
	return Root + DS + "logs"
}

func LogFile(file string) string {
	if runtime.GOOS == "windows" {
		file = strings.Replace(file, "/", DS, -1)
	}
	return LogDir() + DS + file
}

func BinDir() string {
	return Root + DS + "bin"
}

func ConfigDir() string {
	if len(configDir) > 0 {
		return configDir
	}

	configDir = findLatestDir(Root, "configs")
	return configDir
}

func SetConfigDir(dir string) {
	configDir = dir
}

func ConfigFile(file string) string {
	if runtime.GOOS == "windows" {
		file = strings.Replace(file, "/", DS, -1)
	}
	return ConfigDir() + DS + file
}

func findRoot() string {
	// WORKROOT
	root := strings.TrimSpace(os.Getenv("WORKROOT"))
	if len(root) > 0 {
		abs, err := filepath.Abs(root)
		if err != nil {
			return root
		}
		return abs
	}

	// GOPATH变量
	if IsTesting() {
		root = strings.TrimSpace(os.Getenv("GOPATH"))
		if len(root) > 0 {
			abs, err := filepath.Abs(root)
			if err != nil {
				return root + DS + "src" + DS + "main"
			}
			return abs + DS + "src" + DS + "main"
		}
	}

	// 当前执行的目录
	dir, err := os.Getwd()
	if err == nil {
		return dir
	}
	return "./"
}

func UpdateRoot(root string) {
	Root = root
	configDir = ""
}

func findLatestDir(parent string, name string) string {
	matches, err := filepath.Glob(parent + DS + name + ".*")
	if err != nil {
		return parent + DS + name
	}

	if len(matches) == 0 {
		return parent + DS + name
	}

	var lastVersion = ""
	var resultDir = ""

	for _, match := range matches {
		dirname := match
		stat, err := os.Stat(dirname)
		if err != nil || !stat.IsDir() {
			continue
		}

		version := filepath.Base(match)[len(name)+1:]

		if len(lastVersion) == 0 {
			lastVersion = version
			resultDir = dirname
			continue
		}

		if versionCompare(lastVersion, version) < 0 {
			lastVersion = version
			resultDir = dirname
			continue
		}
	}

	if len(resultDir) == 0 {
		return parent + DS + name
	}

	return resultDir
}

// 对比版本号，返回-1，0，1三个值
func versionCompare(version1 string, version2 string) int8 {
	if len(version1) == 0 {
		if len(version2) == 0 {
			return 0
		}

		return -1
	}

	if len(version2) == 0 {
		return 1
	}

	pieces1 := strings.Split(version1, ".")
	pieces2 := strings.Split(version2, ".")
	count1 := len(pieces1)
	count2 := len(pieces2)

	for i := 0; i < count1; i++ {
		if i > count2-1 {
			return 1
		}

		piece1 := pieces1[i]
		piece2 := pieces2[i]
		len1 := len(piece1)
		len2 := len(piece2)

		if len1 == 0 {
			if len2 == 0 {
				continue
			}
		}

		maxLength := 0
		if len1 > len2 {
			maxLength = len1
		} else {
			maxLength = len2
		}

		piece1 = fmt.Sprintf("%0"+strconv.Itoa(maxLength)+"s", piece1)
		piece2 = fmt.Sprintf("%0"+strconv.Itoa(maxLength)+"s", piece2)

		if piece1 > piece2 {
			return 1
		}

		if piece1 < piece2 {
			return -1
		}
	}

	if count1 > count2 {
		return 1
	}

	if count1 == count2 {
		return 0
	}

	return -1
}
