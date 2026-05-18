#!/bin/bash

# ============================================
# 攻城师天梯 - 编译脚本
# 用法:
#   ./build.sh              # 编译当前平台
#   ./build.sh -a           # 编译所有平台
#   ./build.sh -p linux     # 编译指定平台 (linux/darwin/windows)
#   ./build.sh -v 1.0.0     # 指定版本号
#   ./build.sh -s           # 跳过前端构建
#   ./build.sh -a -v 1.0.0  # 编译所有平台并指定版本号
# ============================================

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# 默认参数
VERSION=""
BUILD_ALL=false
PLATFORM=""
SKIP_FRONTEND=false
OUTPUT_DIR="build"
APP_NAME="tools-server"
PACKAGE_NAME="tools"

# 解析参数
while getopts "v:ap:sh" opt; do
    case $opt in
        v) VERSION="$OPTARG" ;;
        a) BUILD_ALL=true ;;
        p) PLATFORM="$OPTARG" ;;
        s) SKIP_FRONTEND=true ;;
        h)
            echo "用法: $0 [-v 版本号] [-a] [-p 平台] [-s] [-h]"
            echo "  -v  指定版本号 (默认: dev)"
            echo "  -a  编译所有平台"
            echo "  -p  编译指定平台 (linux/darwin/windows)"
            echo "  -s  跳过前端构建"
            echo "  -h  显示帮助"
            exit 0
            ;;
        *) error "未知参数，使用 -h 查看帮助" ;;
    esac
done

# 版本号
if [ -z "$VERSION" ]; then
    VERSION="dev"
fi
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}"

# 项目根目录
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

info "========================================="
info "  攻城师天梯 编译脚本"
info "  版本: ${VERSION}"
info "  时间: ${BUILD_TIME}"
info "========================================="

# 1. 检查 Go 环境
info "检查 Go 环境..."
if ! command -v go &> /dev/null; then
    error "未安装 Go，请先安装 Go 1.24+"
fi
GO_VERSION=$(go version | awk '{print $3}')
ok "Go 版本: ${GO_VERSION}"

# 2. 构建前端
if [ "$SKIP_FRONTEND" = true ]; then
    warn "跳过前端构建"
    if [ ! -d "web/dist" ]; then
        error "web/dist 目录不存在，请先执行前端构建或去掉 -s 参数"
    fi
    ok "使用已有的前端构建产物"
else
    info "构建前端..."
    if [ ! -d "web" ]; then
        error "未找到 web 目录"
    fi

    if [ -f "web/package.json" ]; then
        if ! command -v npm &> /dev/null; then
            error "未安装 npm，请先安装 Node.js"
        fi

        info "安装前端依赖..."
        cd web
        npm install --prefer-offline --no-audit --no-fund
        ok "前端依赖安装完成"

        info "编译前端项目..."
        npm run build
        cd "$PROJECT_DIR"
        ok "前端构建完成 → web/dist/"
    else
        error "未找到 web/package.json，请确认前端项目结构"
    fi
fi

# 验证前端产物
if [ ! -f "web/dist/index.html" ]; then
    error "前端构建产物不存在: web/dist/index.html"
fi
ok "前端产物验证通过"

# 3. 整理 Go 依赖
info "整理 Go 模块依赖..."
go mod tidy
ok "依赖整理完成"

# 4. 创建输出目录
mkdir -p "${OUTPUT_DIR}"

# 记录已编译的平台目录
BUILT_DIRS=()

# 编译函数
build() {
    local os=$1
    local arch=$2
    local output_name="${APP_NAME}"

    if [ "$os" = "windows" ]; then
        output_name="${APP_NAME}.exe"
    fi

    local output_path="${OUTPUT_DIR}/${os}-${arch}/${output_name}"
    mkdir -p "${OUTPUT_DIR}/${os}-${arch}"

    info "编译 ${os}/${arch}..."
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build \
        -ldflags "${LDFLAGS}" \
        -o "$output_path" \
        main.go

    local size=$(ls -lh "$output_path" | awk '{print $5}')
    ok "${os}/${arch} 编译完成 → ${output_path} (${size})"

    BUILT_DIRS+=("${os}-${arch}")
}

# 5. 执行编译
if [ "$BUILD_ALL" = true ]; then
    info "编译所有平台..."
    build linux amd64
    build linux arm64
    build darwin amd64
    build darwin arm64
    build windows amd64
elif [ -n "$PLATFORM" ]; then
    case $PLATFORM in
        linux)
            build linux amd64
            build linux arm64
            ;;
        darwin|macos)
            build darwin amd64
            build darwin arm64
            ;;
        windows|win)
            build windows amd64
            ;;
        *)
            error "不支持的平台: ${PLATFORM} (支持: linux/darwin/windows)"
            ;;
    esac
else
    current_os=$(go env GOOS)
    current_arch=$(go env GOARCH)
    build "$current_os" "$current_arch"
fi

# ============================================
# 生成安装包附加文件
# ============================================

# 生成 README
generate_readme() {
    local os=$1
    local bin_name="${APP_NAME}"
    local start_cmd="./${bin_name}"
    if [ "$os" = "windows" ]; then
        bin_name="${APP_NAME}.exe"
        start_cmd="${bin_name}"
    fi

    cat <<EOF
# 攻城师天梯 v${VERSION}

## 快速启动

### Linux / macOS

\`\`\`bash
# 赋予执行权限
chmod +x ${APP_NAME}

# 启动服务（默认端口 8080）
${start_cmd}

# 指定配置文件启动
${start_cmd} -c config.yaml

# 查看帮助
${start_cmd} -h
\`\`\`

### Windows

双击 \`start.bat\` 或在 CMD/PowerShell 中运行：

\`\`\`cmd
${bin_name}
\`\`\`

## 访问服务

启动后访问 http://localhost:8080

## 配置说明

编辑 \`config.yaml\` 可修改：

- 服务端口（默认 8080）
- 数据库路径（默认 ./data/tools.db）
- 日志级别和格式

## 目录结构

\`\`\`
.
├── ${bin_name}       # 主程序
├── config.yaml       # 配置文件
├── start.sh         # 启动脚本 (Linux/macOS)
├── start.bat        # 启动脚本 (Windows)
└── README.md        # 说明文档
\`\`\`

## 版本信息

- 版本: ${VERSION}
- 构建时间: ${BUILD_TIME}
EOF
}

# 生成 Linux/macOS 启动脚本
generate_start_sh() {
    cat <<'STARTSH'
#!/bin/bash

# 攻城师天梯启动脚本

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 默认配置文件
CONFIG_FILE="config.yaml"

# 解析参数
while getopts "c:h" opt; do
    case $opt in
        c) CONFIG_FILE="$OPTARG" ;;
        h)
            echo "用法: ./start.sh [-c 配置文件] [-h]"
            echo "  -c  指定配置文件 (默认: config.yaml)"
            echo "  -h  显示帮助"
            exit 0
            ;;
    esac
done

# 检查配置文件
if [ ! -f "$CONFIG_FILE" ]; then
    echo "[WARN] 配置文件 $CONFIG_FILE 不存在，使用默认配置"
    CONFIG_FILE=""
fi

# 检查端口是否被占用
PORT=$(grep -E "^\s*port:" "$CONFIG_FILE" 2>/dev/null | awk '{print $2}' | tr -d '"')
if [ -z "$PORT" ]; then
    PORT=8080
fi

if command -v lsof &> /dev/null; then
    if lsof -i :$PORT -t &> /dev/null; then
        echo "[WARN] 端口 $PORT 已被占用，服务可能启动失败"
    fi
fi

# 创建数据目录
mkdir -p data

# 启动服务
echo "========================================="
echo "  攻城师天梯"
echo "  端口: $PORT"
echo "  配置: ${CONFIG_FILE:-默认}"
echo "========================================="
echo ""

if [ -n "$CONFIG_FILE" ]; then
    ./tools-server -c "$CONFIG_FILE"
else
    ./tools-server
fi
STARTSH
}

# 生成 Windows 启动脚本
generate_start_bat() {
    cat <<'STARTBAT'
@echo off
chcp 65001 >nul 2>&1
title 攻城师天梯

echo =========================================
echo   攻城师天梯
echo =========================================
echo.

if not exist "data" mkdir data

if exist "config.yaml" (
    tools-server.exe -c config.yaml
) else (
    tools-server.exe
)

pause
STARTBAT
}

# ============================================
# 打包函数
# ============================================

package() {
    local dir=$1
    local os=$(echo "$dir" | cut -d'-' -f1)
    local arch=$(echo "$dir" | cut -d'-' -f2)
    local pkg_dir="${PACKAGE_NAME}_${VERSION}_${os}_${arch}"
    local full_dir="${OUTPUT_DIR}/${pkg_dir}"

    info "打包 ${os}-${arch}..."

    # 创建独立打包目录
    mkdir -p "$full_dir"

    # 复制二进制
    cp "${OUTPUT_DIR}/${dir}/${APP_NAME}"* "$full_dir/" 2>/dev/null || true

    # 复制配置文件
    cp config/config.yaml "$full_dir/"

    # 生成 README
    generate_readme "$os" > "$full_dir/README.md"

    # 生成启动脚本
    if [ "$os" = "windows" ]; then
        generate_start_bat > "$full_dir/start.bat"
    else
        generate_start_sh > "$full_dir/start.sh"
        chmod +x "$full_dir/start.sh"
        # 确保二进制有执行权限
        if [ -f "$full_dir/${APP_NAME}" ]; then
            chmod +x "$full_dir/${APP_NAME}"
        fi
    fi

    # 打包
    local archive_name="${pkg_dir}"
    cd "${OUTPUT_DIR}"

    if [ "$os" = "windows" ]; then
        # Windows 使用 zip
        if command -v zip &> /dev/null; then
            zip -r -q "${archive_name}.zip" "${pkg_dir}"
            ok "打包完成 → ${OUTPUT_DIR}/${archive_name}.zip"
        else
            warn "未安装 zip，跳过 ${os}-${arch} 打包 (可使用: brew install zip)"
        fi
    else
        # Linux/macOS 使用 tar.gz
        tar -czf "${archive_name}.tar.gz" "${pkg_dir}"
        ok "打包完成 → ${OUTPUT_DIR}/${archive_name}.tar.gz"
    fi

    cd "$PROJECT_DIR"
}

# ============================================
# 6. 复制配置文件并打包
# ============================================

info "复制配置文件..."
for dir in "${BUILT_DIRS[@]}"; do
    if [ -d "${OUTPUT_DIR}/${dir}" ]; then
        cp config/config.yaml "${OUTPUT_DIR}/${dir}/" 2>/dev/null || true
    fi
done
ok "配置文件复制完成"

# 7. 生成安装包
info "生成安装包..."
for dir in "${BUILT_DIRS[@]}"; do
    package "$dir"
done

# 8. 清理中间目录（保留安装包）
info "清理中间文件..."
for dir in "${BUILT_DIRS[@]}"; do
    rm -rf "${OUTPUT_DIR}/${dir}"
done

# 9. 汇总输出
info "========================================="
info "  编译 & 打包完成！"
info "  版本: ${VERSION}"
info "  输出目录: ${OUTPUT_DIR}/"
info "========================================="

echo ""
ls -lh "${OUTPUT_DIR}/"*.tar.gz "${OUTPUT_DIR}/"*.zip 2>/dev/null || true

echo ""
info "安装包说明:"
info "  .tar.gz  → Linux / macOS (解压后运行 start.sh)"
info "  .zip     → Windows (解压后双击 start.bat)"
echo ""
info "使用方式:"
info "  tar xzf ${PACKAGE_NAME}_${VERSION}_*_*.tar.gz"
info "  cd ${PACKAGE_NAME}_${VERSION}_*_*/"
info "  ./start.sh"
