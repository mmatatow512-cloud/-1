import traceback

try:
    import app
    print("成功导入app模块")
    # 尝试运行应用
    if __name__ == "__main__":
        app.app.run(debug=True)
except Exception as e:
    print("发生错误:")
    print(type(e).__name__, ":", e)
    print("\n详细错误信息:")
    traceback.print_exc()