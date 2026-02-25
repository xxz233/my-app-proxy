# 使用Python 3.9作为基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DB_PATH=/data/app_config.db
ENV ENABLE_AUTH=true
# ENV API_KEY=changeme

# 设置时区为中国上海
ENV TZ=Asia/Shanghai

# 2. 安装系统依赖
RUN echo "安装系统依赖..." && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    gcc \
    libsqlite3-dev \
    tzdata \
    ca-certificates && \
    # 设置时区
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone && \
    # 清理缓存以减小镜像体积
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 复制Python依赖文件
COPY requirements.txt .

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 创建数据目录
RUN mkdir -p /data /app/backgrounds

# 创建非root用户运行应用
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app /data
USER appuser

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/background?info=1')"

# 启动命令
CMD ["python", "my_app_proxy.py"]
