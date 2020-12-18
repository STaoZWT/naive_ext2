# naive_ext2
## 限制
- 文件系统大小：4MB
- 单个文件最大大小：6KB
- 目录支持最大目录项数量：46
- 最多支持文件、目录数量总和：1023
- 文件名最大长度：127
- 最大路径深度：31

## 支持的操作
### ls
- 格式：`ls [dir1] [dir2..]`
- 功能：无参数时，展示当前目录项目；有参数时，依次展示输入路径的目录项目
### mkdir
- 格式：`mkdir dir1 [dir2..]`
- 功能：在相应路径建立目录
### touch
- 格式：`touch file1 [file2..]`
- 功能：在相应路径建立空文件
### cp
- 格式：`cp file1 file2`
- 功能：将`file1`复制到`file2`
### tee
- 格式：`tee file1 [file2..]`
- 功能：将标准输入`stdin`中的内容写入对应文件中
### cat
- 格式：`cat file`
- 功能：将对应文件的内容打印到标准输出`stdout`
### cd
- 格式：`cd dir`
- 功能：进入相应目录
### rm
- 格式：`rm file1 [file2..]`
- 功能：删除相应路径的相应文件
### rmdir
- 格式：`rmdir dir1 [dir2..]`
- 功能：删除对应目录（仅支持删除空目录）
### mv
- 格式：`mv file1 file2`
- 功能：将`file1`移动至`file2`
### ln
- 格式：`ln file1 file2`
- 功能：将建立`file2`到`file1`的硬链接
### shutdown
- 格式：`shutdown`
- 功能：关闭文件系统

## 使用方式
- 请确保系统中已经安装cmake, make和gcc
- 进入到项目目录中，依次使用`cmake .`初始化cmake，使用`make`编译程序，然后使用`./main`执行程序即可。

## Have fun !
