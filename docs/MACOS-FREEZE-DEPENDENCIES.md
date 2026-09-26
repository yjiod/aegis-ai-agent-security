# Mac 冻结构建工具链准入记录

现有 PyInstaller 构建工具链改为精确版本及 wheel SHA-256 锁定；没有引入新的客户端业务库。仅在构建机使用，不需要终端安装 pip 或这些构建工具。

检查日期：2026-09-26。每个 wheel 的下载 URL 和 SHA-256 已与 PyPI 对应版本元数据交叉核验；仅允许官方 `files.pythonhosted.org` 工件。OSV 批量查询所列六个版本未返回已知漏洞；这不是未来无漏洞保证，变更锁文件必须重新检查。

| 构建组件 | 固定版本 | 许可证 | 所选工件发布时间 |
| --- | --- | --- | --- |
| [altgraph](https://pypi.org/project/altgraph/0.17.5/) | 0.17.5 | MIT | 2025-11-21 |
| [macholib](https://pypi.org/project/macholib/1.16.4/) | 1.16.4 | MIT | 2025-11-22 |
| [packaging](https://pypi.org/project/packaging/26.3/) | 26.3 | Apache-2.0 OR BSD-2-Clause | 2026-08-04 |
| [pyinstaller](https://pypi.org/project/pyinstaller/6.22.3/) | 6.22.3 | GPLv2-or-later with a special exception which allows to use PyInstaller to build and distribute non-free programs (including commercial ones) | 2026-09-12 |
| [pyinstaller-hooks-contrib](https://pypi.org/project/pyinstaller-hooks-contrib/2026.7/) | 2026.7 | GPL-2.0-or-later (standard hooks); Apache-2.0 (runtime hooks) | 2026-08-24 |
| [setuptools](https://pypi.org/project/setuptools/84.0.0/) | 84.0.0 | MIT | 2026-08-08 |

选择理由：沿用已有冻结工具，保持现有单文件更新工件契约；替代的原生重写需要单独迁移和验证，不影响本期消除用户外部解释器前置条件。各项目为既有维护项目，所选工件为近期维护版本。构建工具只处理公开仓库源码和合成测试资料，不使用管理员权限、不访问生产数据；发布签名仍应由受控签名流程完成。

安装入口为 `pip install --only-binary=:all: --require-hashes -r scripts/macos-freeze-requirements.txt`，拒绝源码构建和未知摘要。CI 固定 Python 3.12.14，由已固定提交的 setup-python 提供；ARM64 与 x64 均在原生 runner 上运行。锁定输入不等于已证明逐字节可复现，也不等于签名、公证或生产发布通过。

许可证依据包括 [PyInstaller 许可说明](https://github.com/pyinstaller/pyinstaller/blob/develop/COPYING.txt) 和 [hooks 许可分类](https://github.com/pyinstaller/pyinstaller-hooks-contrib/blob/master/LICENSE)。最终分发必须保留适用的解释器、引导程序、动态库及运行时 hook 许可告知；此构建验证不替代最终安装包的完整 SBOM 和许可验收。

[OSV 查询接口](https://google.github.io/osv.dev/api/#operation/OSV.QueryAffectedBatch)；[GitHub 原生 runner 架构清单](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)。
