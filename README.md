软件界面
<img width="998" alt="image" src="https://github.com/user-attachments/assets/204da8f1-0b66-4879-be78-729e71da6321" />


1. 使用pip install 需要的库
2. 执行python network-batch-test-tool-v1.2.py 文件
3. 如需打包成exe,可使用以下打包命令

```python
python -m PyInstaller --onefile --noconsole --name "network-batch-test-tool-v1.2" --hidden-import=queue --hidden-import=bs4 --clean -w .\network-batch-test-tool-v1.2.py
```
