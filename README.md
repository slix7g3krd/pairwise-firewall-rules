# pairwise-firewall-rules

运维把防火墙规则一次性导入后，边界策略就开始失效：源和目的都写成 `any`，默认放行全网；端口范围写成 `0-65535`，等于全开；协议字段拼错后规则被静默跳过；deny 规则排在 allow 后面，永远不生效；CIDR 写错掩码，内网段被放大；出站规则只写目的不写源；重复规则互相覆盖，最后一条赢；空规则被当成 allow；注释和换行没有清理，解析出半条；默认策略不是 deny。security/firewall_rules.py 是核心，tests/test_firewall_rules.py 15个红。要修的是：禁 any-any；端口范围收敛；协议白名单；deny 前置；CIDR 校验；出站源限制；重复规则去重；空规则拒绝；注释清理；默认 deny。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
