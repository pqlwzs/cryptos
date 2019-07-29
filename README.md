# cryptos

基于文件的名称、大小两个信息快速生成数字校验码

具体步骤：
1. 对输入目录递归检索所有文件，取得文件的相对路径和大小，计算md5值
2. 对所有md5值进行排序后连接，再次计算md5值
3. 用RSA计算md5的签名，转换base64输出
