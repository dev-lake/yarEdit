# yarEdit

一个 Yara 规则批量处理工具。

目前仅实现对单一文件内的 yara 规则批量添加 meta 信息，
如果之前存在相同名称的 meta 信息则会被覆盖。

### 使用方法
```bash
./yarEdit -input rule.yar -key Type -value WebShell
```

### 问题
目前已知存在的问题：
- comments lost
- "import" duplication
经测试，这两项问题不影响规则的正常使用和编译，暂不做修复。