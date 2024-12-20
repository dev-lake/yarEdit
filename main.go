package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/VirusTotal/gyp"
	"github.com/VirusTotal/gyp/ast"
)

func main() {
	inputFile := flag.String("input", "", "输入的.yar规则文件路径")
	// outputFile := flag.String("output", "", "输出的.yar规则文件路径")
	metaKey := flag.String("key", "", "要添加的meta键名")
	metaValue := flag.String("value", "", "要添加的meta值")
	flag.Parse()

	if *inputFile == "" || *metaKey == "" || *metaValue == "" {
		fmt.Println("请提供必要的参数:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// 检查输入文件扩展名
	if !strings.HasSuffix(*inputFile, ".yar") {
		fmt.Println("输入文件必须是.yar格式")
		os.Exit(1)
	}

	// 读取输入文件
	content, err := os.ReadFile(*inputFile)
	if err != nil {
		fmt.Printf("读取文件失败: %v\n", err)
		os.Exit(1)
	}

	// 解析YARA规则
	ruleset, err := gyp.ParseString(string(content))
	if err != nil {
		fmt.Printf("解析YARA规则失败: %v\n", err)
		os.Exit(1)
	}

	// 为每个规则添加或更新meta信息
	for _, rule := range ruleset.Rules {
		// 检查是否已存在相同的key
		found := false
		for _, meta := range rule.Meta {
			if meta.Key == *metaKey {
				meta.Value = *metaValue // 更新已存在的值
				found = true
				break
			}
		}
		// 如果不存在则添加新的meta
		if !found {
			rule.Meta = append(rule.Meta, &ast.Meta{Key: *metaKey, Value: *metaValue})
		}
	}

	outFilePath := (*inputFile)[:len(*inputFile)-4] + "-yaredit.yar"

	outputFile, err := os.Create(outFilePath)
	if err != nil {
		fmt.Printf("创建输出文件失败: %v\n", err)
		os.Exit(1)
	}
	defer outputFile.Close()

	err = ruleset.WriteSource(outputFile)
	if err != nil {
		fmt.Printf("输出文件写入失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("!!! 成功处理 %d 条规则并保存到：%s\n", len(ruleset.Rules), outFilePath)
}
