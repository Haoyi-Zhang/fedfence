# FedFence FSE 2027 最终完成报告

## 1. 最终状态

本工作包已经完成当前环境中可诚实完成的论文、实现、实验、复现、审计和
PDF 质检。最终产物是一份 **12 页匿名 ACM FSE 评审稿候选件**，配套一个
可执行的变更审查工具和冻结证据包。

机器审计结论：

- `local_audit_passed = true`
- `submission_package_complete = true`
- `external_validation_complete = false`

最后一项不是失败，而是明确的研究边界：当前证据不能替代代表性抽样、独立
意图标注、维护者确认、真实组织部署、比较工具共同语料实验或人类参与者研究。

## 2. 论文主线已经从“形式化证明展示”改为“软件配置变更审查”

最终题目为：

> **FedFence: Specification-Guided Review of CI/CD Trust Changes**

核心问题不再表述为“一个字符串是否看起来安全”，而是：

> 当 workflow、身份提供方、云信任策略、发布要求和仓库治理分别演化时，
> 一次配置改动是否扩大了可获权身份，或删除了必须继续工作的身份？

最终论文按三个研究问题组织：

1. 三值审查门能否区分越权、必需身份丢失、证据不足/语义不支持；
2. 能否解释公开代码中的 before/after OIDC trust 变更；
3. 当前公开 IaC 暴露出哪些实现和规范化边界，以及如何接入普通 PR 流程。

## 3. 实现完成情况

最终实现新增或完成：

- `pass / fail / unknown` 三值结果；
- 稳定退出码 `0 / 1 / 2`；
- before/after change review；
- 上界安全约束与有限 required-token 正向回归义务；
- tuple 级 Allow-minus-Deny 语义；
- 严格 preflight、过期/范围/摘要/依赖检查；
- replayable certificate 和 concrete witness；
- text、JSON、SARIF 2.1.0、GitHub annotation 四类输出；
- 根目录 composite GitHub Action；
- review packet JSON Schema；
- 完整参考 PR workflow；
- 修复一个后端 dispatch 缺陷：selected-claim Deny 不再被错误送入只理解
  `sub/aud` 的 regular backend。

## 4. 最终证据

### 本地一致性

| 项目 | 最终结果 |
|---|---:|
| 单元/集成测试 | 79 passed，0 failure/error/skip |
| 有限语义审计 | 65,536 models passed |
| 前序历史案例重放 | 37/37 agreement |
| 前序 self-check | 3,945 passed |
| 可执行 walkthrough | 8/8 expected |

### 公开 before/after 变更

- 搜索查询：3
- 候选 commit：17
- 纳入：9
- 排除：8，全部有原因
- source snapshot verified：9/9
- before/after phase 与开发者陈述方向一致：18/18
- `fail -> pass`：8
- `fail -> unknown`：1
- owner-confirmed findings：0
- independently adjudicated labels：0

其中 compatibility repair 证明了二侧约束的必要性：旧策略并未越过安全上界，
但它漏掉了运行时实际发出的 immutable subject；required-token 义务可将其识别为
可用性回归。

### Immutable-subject 维护语料

- 12 个公开仓库 / 12 个 full-SHA commit；
- 11 个 commit 报告 credential exchange 被拒绝或中断；
- 6 个明确提到 CloudTrail；
- 4 个明确提到解码真实 workflow token；
- 2 个修复具有归档的公开 GitHub Actions 成功 run ID；
- 9 类修复策略。

这些是 source-stated maintenance evidence，不是独立根因裁决或流行率估计。

### Source-normalization frontier

24 个 query-defined 公开仓库中：

- 5 个文件为直接 literal；
- 2 个可由固定 HCL 默认值 constant-fold；
- 17 个需要 caller/module/dynamic-HCL/host-language evaluation；
- 6 个固定源文件中没有显式 audience 条件；
- 1 个使用当前证明 profile 不支持的 set operator。

该实验说明：真实场景的主要瓶颈不仅是正则匹配，而是获得已经解析的配置。
它不估计真实世界比例，也不声称 extractor accuracy。

## 5. 性能与工具比较边界

冻结的 9-change 本地批处理运行 7 次：

- median：946.08 ms
- p95：986.22 ms

计时仅覆盖 analyzer、required-token checks 和 certificate replay，不包含网络、
源码收集、Terraform/CDK 求值、云端行为或人工审核。

Access Analyzer、Checkov、tfsec/Trivy、OPA 在本执行环境中没有完成共同语料运行，
最终记录为 **0 comparative benchmark runs**。论文没有把“工具不可用”解释为
“工具漏报”，也没有声称产品优越性。

## 6. PDF 与投稿包审计

- 模板：`acmsmall,screen,review,anonymous`
- 页数：12
- 引用：32/32，全部定义且全部使用
- overfull box：0
- Type 3 fonts：0
- Author metadata：空
- mojibake probes：0
- PDF 可由 PyMuPDF 打开，非扫描件，无加密/XFA
- 已移除占位 submission ID；正式投稿时可填入系统分配的真实编号
- 40 个 final-layer JSON 全部可解析，Python 全部可编译，Action/workflow YAML 可解析
- 12 页全部以 200 DPI 渲染并人工检查：未见文字裁剪、表格越界、重叠、黑块或
  破损字形

## 7. 复现

```bash
make reproduce
make paper
make audit
```

最终单一驱动完整运行通过，manifest 记录 `execution_mode = single-driver-run`。
12 个步骤均返回 `passed`，总墙钟时间约 34.95 秒；其中测试约 20.17 秒，八个
walkthrough 约 6.27 秒，其余步骤均在约 1.7 秒内完成。冻结性能文件在普通复现中做
完整性校验，若需要重新计时可单独运行 `scripts/benchmark_public_changes.py`。

关键文件：

- `fse/results/final_reproduction_manifest.json`
- `fse/results/final_audit.json`
- `fse/results/provenance.json`
- `paper/FedFence_FSE_final_submission_candidate.pdf`

## 8. 明确未完成、也未冒充完成的外部研究

当前包没有声称：

- 代表性流行率或 supported-fragment coverage；
- precision/recall 或独立 field accuracy；
- 由 FedFence 主动发现并获维护者确认的漏洞；
- FedFence 在真实组织中的 live deployment；
- 对现有产品的共同语料优势；
- 人类参与者的效率/可用性提升；
- 从数学模型到 Python 的 machine-checked refinement；
- required-token examples 构成完整的可用性语言。

因此，当前版本是一个完整、可复现、边界诚实的投稿候选包，而不是用生成实验或
公开 commit 描述替代外部验证。
