package utils

import (
	"bufio"
	"fmt"
	"os/exec"
)

func RunCMD(cmd string) (string, error) {
	cmd0 := exec.Command(cmd)
	stdout0, err := cmd0.StdoutPipe() // 获取命令输出内容
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	if err := cmd0.Start(); err != nil { //开始执行命令
		fmt.Println(err)
		return "", err
	}

	outputbuf0 := bufio.NewReader(stdout0)
	touput0, _, err := outputbuf0.ReadLine()
	if err != nil {
		return "", err
	}
	return string(touput0), nil
}
