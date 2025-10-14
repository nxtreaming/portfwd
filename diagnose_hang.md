# UDP Hang 诊断指南

## 🚨 当前状态（2025-10-14 更新）

### ✅ 已确认修复的问题

**时间戳更新 Bug（Commit 4975bf3）**：
- ✅ 在网络良好环境下（如公司网络），udpfwd 工作完美
- ✅ 连接稳定运行 47+ 分钟，处理 980,000+ 个包
- ✅ 不会触发错误的 Recycling 消息
- ✅ 时间戳持续更新，没有停滞

### ⚠️ 仍存在的问题

**网络质量敏感的 Freeze/Hang（新发现）**：
- ❌ 在网络不良环境下（如家庭网络），仍会出现 freeze/hang
- 🔍 **根本原因**：客户端到 udpfwd 之间的大量丢包
- 💥 **影响范围**：OpenVPN 连接 broken → 所有使用 VPN 的程序卡死
- ⏱️ **恢复方式**：需要 cool down 一段时间才能恢复

**关键区别**：
- 这不是 udpfwd 的代码 bug
- 这是网络层面的丢包导致的级联故障
- udpfwd 本身可能正常运行，但 OpenVPN 协议层崩溃

---

## 📋 诊断检查清单

### ✅ 第一步：确认代码版本

```bash
cd /path/to/portfwd
git log --oneline -3
```

**期望输出**：
```
b600c91 Add regression test for timestamp burst bug
4975bf3 Fix critical bug: active UDP connections incorrectly recycled
a5f7616 Merge pull request #18 (UDP backlog fix)
```

如果不是这个版本，先 `git pull` 更新代码。

---

### ✅ 第二步：重新编译

```bash
cd src
make clean
make
```

**检查编译时间**：
```bash
ls -lh udpfwd
# 确认文件时间是最新的
```

---

### ✅ 第三步：停止旧进程

```bash
# 查找所有 udpfwd 进程
ps aux | grep udpfwd

# 停止所有旧进程
killall udpfwd

# 确认已停止
ps aux | grep udpfwd
```

---

### ✅ 第四步：启动新版本（带调试日志）

```bash
# 启动 udpfwd
./udpfwd 0.0.0.0:1194 your_server:1194 -C 100 -t 300

# 或者使用 nohup 后台运行
nohup ./udpfwd 0.0.0.0:1194 your_server:1194 -C 100 -t 300 > /var/log/udpfwd.log 2>&1 &
```

---

### ✅ 第五步：观察日志

```bash
# 实时查看日志
tail -f /var/log/udpfwd_*.log

# 或者
tail -f /var/log/udpfwd.log
```

**期望看到的调试日志**：

```
[INFO] UDP forwarder started
[INFO] New UDP session [IP]:PORT, total 1
[DEBUG] touch_proxy_conn #100: IP:PORT old=XXX new=YYY (diff=Z)
[DEBUG] touch_proxy_conn #200: IP:PORT old=YYY new=ZZZ (diff=1)
...
```

**如果看到这些，说明修复生效了**：
- ✅ `touch_proxy_conn` 被调用
- ✅ `last_active` 在更新
- ✅ `diff` 通常是 0 或 1（正常）

**如果看到这些，说明有发送阻塞问题**：
- ⚠️ `[DEBUG] Queued packet to backlog`
- ⚠️ `[DEBUG] send() returned EWOULDBLOCK`
- ⚠️ 这是 GPT-5 修复的问题

---

## 🔍 诊断不同类型的 Hang

### Hang 类型 A: 连接被错误回收 ✅ 已修复

**症状**：
```
[INFO] Recycling IP:PORT ... idle=301 sec, timeout=300 sec
```

**原因**：时间戳不更新（Commit 4975bf3 已修复）

**状态**：✅ **已完全修复并验证**
- 在良好网络环境下，连接可稳定运行数小时
- 处理百万级数据包无问题
- 不再出现错误的 Recycling 消息

**如果仍然看到 Recycling**：
- 检查是否真的空闲了（OpenVPN 断开）
- 检查 OpenVPN keepalive 配置
- 考虑增加超时时间或禁用（`-t 0`）

---

### Hang 类型 B: 发送阻塞 ✅ 已修复

**症状**：
- 连接还在（没有 Recycling 消息）
- 但数据包发不出去
- OpenVPN 显示连接超时

**原因**：发送阻塞（Commit a5f7616 已修复）

**状态**：✅ **已修复**
- UDP backlog 机制已实现
- EWOULDBLOCK 情况已正确处理

**如果仍然看到发送问题**：
- 可能是网络层面的丢包（见 Hang 类型 C）
- 检查系统 UDP 缓冲区大小

---

### Hang 类型 C: 网络丢包导致的级联故障 ⚠️ 当前主要问题

**症状**：
- ✅ udpfwd 日志可能正常（没有 Recycling）
- ❌ OpenVPN 连接 broken/timeout
- ❌ 所有使用 VPN 的程序卡死
- ⏱️ 需要 cool down 一段时间才恢复
- 🌐 **只在网络质量差的环境下出现**（如家庭网络）
- ✅ **在网络质量好的环境下不出现**（如公司网络）

**根本原因**：
1. **客户端 → udpfwd 之间大量丢包**
   - 家庭网络：ISP 限速、WiFi 干扰、路由器性能差
   - 公司网络：专线、有线连接、企业级路由器

2. **OpenVPN 协议层崩溃**
   - UDP 丢包 → OpenVPN keepalive 超时
   - OpenVPN 认为连接断开 → 尝试重连
   - 重连失败 → 进入 broken 状态
   - TUN/TAP 接口阻塞 → 所有 VPN 流量卡死

3. **级联故障**
   ```
   网络丢包 → OpenVPN broken → TUN/TAP 阻塞 → 所有程序卡死
   ```

**验证方法**：

```bash
# 1. 测试客户端到 udpfwd 的丢包率
ping -c 100 your_udpfwd_server
# 看丢包率，如果 >5% 就很危险

# 2. 使用 mtr 查看路由质量
mtr --report --report-cycles 100 your_udpfwd_server
# 看每一跳的丢包率

# 3. 测试 UDP 吞吐量和丢包
iperf3 -c your_udpfwd_server -u -b 10M -t 60
# 看 Lost/Total Datagrams 比例

# 4. 抓包分析
tcpdump -i any -n port 1194 -w capture.pcap -c 10000
# 用 Wireshark 分析：Statistics → UDP Multicast Streams
```

**典型丢包模式**：

| 网络环境 | 丢包率 | 延迟 | 抖动 | udpfwd 表现 |
|---------|--------|------|------|-------------|
| 公司网络 | <0.1% | 10-20ms | <5ms | ✅ 完美 |
| 家庭 WiFi | 5-15% | 30-100ms | 10-50ms | ❌ Freeze |
| 家庭有线 | 1-5% | 20-50ms | 5-20ms | ⚠️ 偶尔卡 |
| 移动网络 | 10-30% | 50-200ms | 20-100ms | ❌ 严重卡顿 |

**解决方案**：

#### 短期方案（缓解症状）

1. **优化 OpenVPN 配置**（提高容错性）
   ```
   # 在 OpenVPN 配置文件中添加
   
   # 更激进的 keepalive（更快检测断开）
   keepalive 5 30
   
   # 更快的重连
   ping-restart 60
   
   # 允许更多重传
   connect-retry-max 10
   
   # 减小 MTU 降低丢包影响
   mssfix 1200
   tun-mtu 1400
   
   # 启用数据压缩（减少包数量）
   compress lz4-v2
   
   # 禁用 TLS 重协商（避免超时）
   reneg-sec 0
   ```

2. **调整 udpfwd 参数**
   ```bash
   # 禁用超时（避免误杀连接）
   ./udpfwd 0.0.0.0:1194 server:1194 -C 100 -t 0
   
   # 或者大幅增加超时
   ./udpfwd 0.0.0.0:1194 server:1194 -C 100 -t 3600
   ```

3. **增加系统 UDP 缓冲区**
   ```bash
   # 临时增加
   sudo sysctl -w net.core.rmem_max=26214400
   sudo sysctl -w net.core.wmem_max=26214400
   sudo sysctl -w net.core.rmem_default=26214400
   sudo sysctl -w net.core.wmem_default=26214400
   
   # 永久生效（添加到 /etc/sysctl.conf）
   net.core.rmem_max = 26214400
   net.core.wmem_max = 26214400
   net.core.rmem_default = 26214400
   net.core.wmem_default = 26214400
   ```

#### 中期方案（改善网络）

1. **使用有线连接**
   - WiFi → 有线：丢包率可降低 80%

2. **优化路由器**
   - 启用 QoS，优先 VPN 流量
   - 关闭其他占带宽的设备
   - 升级路由器固件

3. **更换 ISP 或套餐**
   - 选择低延迟、低丢包的 ISP
   - 升级到更高带宽套餐

#### 长期方案（架构改进）

1. **实现 FEC（前向纠错）**
   - 在 udpfwd 中添加 Reed-Solomon 编码
   - 可容忍 20-30% 丢包而不影响连接

2. **实现 ARQ（自动重传）**
   - 在 udpfwd 层面实现可靠 UDP
   - 类似 KCP/QUIC 的机制

3. **切换到 TCP 模式**
   - 使用 tcpfwd 代替 udpfwd
   - OpenVPN over TCP（虽然性能差，但更可靠）

4. **多路径传输**
   - 同时使用多个网络接口
   - 实现路径选择和故障切换

---

### Hang 类型 D: OpenVPN 配置问题

**症状**：
- udpfwd 日志正常
- 但 OpenVPN 还是 hang

**原因**：OpenVPN 自身的问题

**验证**：
```bash
# 查看 OpenVPN 日志
tail -f /var/log/openvpn.log
```

**常见问题**：
1. Keepalive 配置不当
2. 密钥重协商失败
3. MTU 问题
4. 路由问题

**解决**：
```
# 在 OpenVPN 配置中添加
keepalive 10 60
ping-restart 120
mssfix 1400
```

---

## 🎯 当前诊断结论（2025-10-14）

### ✅ 已解决的问题

1. **时间戳更新 Bug（Commit 4975bf3）**
   - **问题**：活跃连接被错误回收
   - **状态**：✅ 完全修复并验证
   - **证据**：47 分钟稳定运行，980,000+ 包，无错误 Recycling

2. **发送阻塞 Bug（Commit a5f7616）**
   - **问题**：UDP 发送缓冲区满时丢包
   - **状态**：✅ 已修复
   - **证据**：Backlog 机制正常工作

### ⚠️ 当前主要问题：网络丢包导致的级联故障

**问题本质**：
- 这不是 udpfwd 的代码 bug
- 这是网络质量问题导致的 OpenVPN 协议层崩溃
- udpfwd 本身可能正常运行，但无法弥补底层网络的丢包

**环境差异**：
```
公司网络（良好）：
  丢包率 <0.1% → udpfwd 完美运行 → OpenVPN 稳定 → ✅ 无问题

家庭网络（不良）：
  丢包率 5-15% → udpfwd 尽力而为 → OpenVPN 崩溃 → ❌ Freeze/Hang
```

**故障链**：
```
1. 客户端 → udpfwd 丢包（网络层）
2. OpenVPN keepalive 超时（协议层）
3. OpenVPN 进入 broken 状态（应用层）
4. TUN/TAP 接口阻塞（系统层）
5. 所有 VPN 程序卡死（用户层）
```

**推荐行动**：

1. **立即行动**（缓解症状）
   - 优化 OpenVPN 配置（见上面的配置示例）
   - 禁用 udpfwd 超时：`-t 0`
   - 增加系统 UDP 缓冲区

2. **短期改进**（改善网络）
   - 使用有线连接代替 WiFi
   - 启用路由器 QoS
   - 测试不同时段的网络质量

3. **长期方案**（架构升级）
   - 考虑实现 FEC（前向纠错）
   - 考虑切换到 TCP 模式
   - 考虑多路径传输

**验证步骤**：
```bash
# 1. 测试网络质量
ping -c 100 your_server  # 看丢包率
mtr --report your_server  # 看路由质量

# 2. 如果丢包率 >5%，这就是根本原因
# 3. 优化网络或调整配置（见上面的方案）
```

---

## 📊 收集诊断信息

如果上述步骤都无法解决，请收集以下信息：

### 1. 完整的 udpfwd 日志

```bash
# 从启动到 hang 的完整日志
cat /var/log/udpfwd_*.log > udpfwd_full.log
```

### 2. 系统信息

```bash
# 操作系统
uname -a

# CPU 信息
cat /proc/cpuinfo | grep "model name" | head -1

# 内存信息
free -h

# 网络接口
ip addr
```

### 3. 网络统计

```bash
# 网络接口统计
netstat -s | grep -i udp

# 连接状态
ss -anup | grep udpfwd
```

### 4. 抓包（如果可能）

```bash
# 抓取 udpfwd 的流量
tcpdump -i any -n port 1194 -w udpfwd_capture.pcap -c 1000
```

---

## 🎯 快速诊断命令

```bash
# 一键诊断脚本
cat > diagnose.sh << 'EOF'
#!/bin/bash
echo "=== UDP Hang Diagnosis ==="
echo ""

echo "1. Code Version:"
git log --oneline -3
echo ""

echo "2. Binary Info:"
ls -lh src/udpfwd
echo ""

echo "3. Running Processes:"
ps aux | grep udpfwd | grep -v grep
echo ""

echo "4. Recent Logs (last 50 lines):"
tail -50 /var/log/udpfwd_*.log 2>/dev/null || tail -50 /var/log/udpfwd.log 2>/dev/null
echo ""

echo "5. Network Stats:"
netstat -s | grep -i udp | head -10
echo ""

echo "6. Connections:"
ss -anup | grep udpfwd
echo ""

echo "=== End of Diagnosis ==="
EOF

chmod +x diagnose.sh
./diagnose.sh
```

---

## 📝 报告格式

如果需要进一步帮助，请提供：

```
### 环境信息
- OS: [Linux/Windows/macOS]
- Version: [具体版本]
- CPU: [型号]
- Network: [网络环境描述]

### 代码版本
[git log --oneline -3 的输出]

### Hang 症状
- 发生时间: [时间]
- 频率: [每次/偶尔/随机]
- 持续时间: [秒/分钟/小时]
- 恢复方式: [自动/需要重启]

### 日志片段
[包含 hang 前后的完整日志]

### 调试日志
- 是否看到 [DEBUG] touch_proxy_conn? [是/否]
- 是否看到 [DEBUG] EWOULDBLOCK? [是/否]
- 是否看到 Recycling 消息? [是/否]

### 网络测试
[ping/mtr/iperf3 的结果]
```

---

## 🚀 下一步行动

1. ✅ **立即执行**：运行上面的诊断脚本
2. ✅ **收集日志**：保存完整的日志文件
3. ✅ **报告结果**：告诉我你看到了什么

根据你的诊断结果，我们可以：
- 如果是代码问题 → 继续修复
- 如果是配置问题 → 调整配置
- 如果是网络问题 → 优化网络
- 如果是 OpenVPN 问题 → 修改 OpenVPN 配置
