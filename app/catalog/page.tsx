'use client';

/**
 * 组件目录（Component Catalog）— 开发参考页面
 *
 * 目标：在不引入 Storybook 的前提下，提供一个零外部依赖的组件走查页。
 * 所有示例都是真实渲染的活组件，直接复用 @/components/ui/* 与
 * app/globals.css、app/detail.css、app/demo.css 中的项目自定义样式类。
 *
 * ─────────────────────────────────────────────────────────────
 * ⚠ 生产构建排除（TODO：尚未实现，仅在此登记）
 *
 * /catalog 属于开发辅助路由，不应该出现在生产构建产物中。
 * 目前还没有接入任何排除逻辑，上线前需要用下列任一方式处理：
 *   1. 构建脚本：在 `vinext build` 前把 app/catalog 移出编译范围
 *      （例如临时重命名目录，或在 CI 中删除该目录后再构建）；
 *   2. 运行时守卫：改为服务端组件并加
 *      `if (process.env.NODE_ENV === 'production') notFound();`
 *      （当前页面是 'use client'，需要额外拆一层服务端包装）；
 *   3. 部署层拦截：在 wrangler / 反向代理规则里直接屏蔽 /catalog 路径。
 * 在排除逻辑落地前，任何生产导航、站点地图或文档都不应链接到本页。
 * ─────────────────────────────────────────────────────────────
 */

import { useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  CircleDot,
  Download,
  Info,
  Laptop,
  LockKeyhole,
  RefreshCw,
  Search,
  Settings,
  ShieldCheck,
  Sparkles,
  Users,
} from 'lucide-react';
import {
  Alert,
  AlertAction,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert';
import {
  Avatar,
  AvatarBadge,
  AvatarFallback,
  AvatarGroup,
  AvatarGroupCount,
} from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Progress,
  ProgressLabel,
  ProgressValue,
} from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { Spinner } from '@/components/ui/spinner';
import { Switch } from '@/components/ui/switch';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Toggle } from '@/components/ui/toggle';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { Toast } from '@/components/toast';

/* ---------- 目录导航数据 ---------- */

const categories = [
  { id: 'buttons', label: '按钮', en: 'Buttons' },
  { id: 'badges', label: '徽标', en: 'Badges' },
  { id: 'cards', label: '卡片', en: 'Cards' },
  { id: 'data-display', label: '数据展示', en: 'Data Display' },
  { id: 'feedback', label: '反馈', en: 'Feedback' },
  { id: 'navigation', label: '导航', en: 'Navigation' },
  { id: 'forms', label: '表单', en: 'Forms' },
  { id: 'patterns', label: '自定义样式', en: 'Custom Patterns' },
];

const deviceRows = [
  ['dev-mac-0142', '沈磊 · Cursor', '4.8.1', '通过', 'pass'],
  ['ci-runner-007', '流水线 · Claude Code', '4.7.9', '告警', 'warn'],
  ['win-laptop-2210', '郭婷 · Copilot', '4.6.2', '拦截', 'fail'],
] as const;

/* ---------- 目录骨架组件 ---------- */

function CatalogCategory({
  id,
  title,
  en,
  summary,
  children,
}: {
  id: string;
  title: string;
  en: string;
  summary: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} className="scroll-mt-24">
      <header className="mb-3 border-b border-[#1b332c] pb-2">
        <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1">
          <h2 className="text-lg font-semibold tracking-tight text-[#eaf7f2]">
            {title}
          </h2>
          <span className="font-mono text-[11px] text-[#4fe5a6]">{en}</span>
        </div>
        <p className="mt-1 text-xs leading-relaxed text-[#78968c]">{summary}</p>
      </header>
      <div className="space-y-3">{children}</div>
    </section>
  );
}

function CatalogEntry({
  name,
  source,
  description,
  note,
  children,
}: {
  name: string;
  source: string;
  description: string;
  note?: string;
  children: React.ReactNode;
}) {
  return (
    <article className="rounded-xl border border-[#1b332c] bg-[#0b1a16]/80 p-4">
      <div className="mb-2 flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <h3 className="text-sm font-semibold text-[#dff4ed]">{name}</h3>
        <code className="rounded bg-[#0f211c] px-1.5 py-0.5 font-mono text-[11px] text-[#65d9a9]">
          {source}
        </code>
      </div>
      <p className="mb-3 text-xs leading-relaxed text-[#78968c]">
        {description}
      </p>
      <div className="space-y-2.5">{children}</div>
      {note ? (
        <p className="mt-3 rounded-md border border-[#3a3220] bg-[#1d1a10] px-2.5 py-2 text-[11px] leading-relaxed text-[#c8b183]">
          注意：{note}
        </p>
      ) : null}
    </article>
  );
}

function Variant({
  label,
  code,
  vertical = false,
  children,
}: {
  label: string;
  code?: string;
  vertical?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-[#172d26] bg-[#07110f] p-3">
      <div className="mb-2.5 flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <p className="text-[11px] font-bold tracking-[0.1em] text-[#5e7c73] uppercase">
          {label}
        </p>
        {code ? (
          <code className="font-mono text-[10.5px] text-[#4f7a6c]">{code}</code>
        ) : null}
      </div>
      <div
        className={
          vertical
            ? 'flex flex-col items-start gap-3'
            : 'flex flex-wrap items-center gap-2.5'
        }
      >
        {children}
      </div>
    </div>
  );
}

function ControlRow({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex w-full max-w-md items-center justify-between gap-4 rounded-lg border border-[#172d26] bg-[#0a1714] px-3 py-2">
      <div className="min-w-0">
        <p className="text-xs font-medium text-[#cfe8df]">{label}</p>
        {hint ? (
          <p className="mt-0.5 text-[11px] text-[#6d8d82]">{hint}</p>
        ) : null}
      </div>
      {children}
    </div>
  );
}

/* ---------- 页面 ---------- */

export default function CatalogPage() {
  const [toast, setToast] = useState('');
  const [liveScan, setLiveScan] = useState(true);

  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(''), 2800);
    return () => clearTimeout(timer);
  }, [toast]);

  return (
    <div className="min-w-0">
      

      <div className="page-head">
        <div>
          <p className="eyebrow">开发工具 / 组件目录</p>
          <h1>组件目录</h1>
          <p>
            按分类列出全部常用组件与项目自定义样式，每个条目附带来源路径、说明与可交互示例。
          </p>
        </div>
      </div>

      <Toast message={toast} />

      <div className="grid gap-5 lg:grid-cols-[196px_minmax(0,1fr)]">
        {/* 分类侧边导航：锚点滚动，html 已启用 scroll-behavior: smooth */}
        <nav
          aria-label="组件分类"
          className="lg:sticky lg:top-[84px] lg:self-start"
        >
          <p className="nav-label">分类导航</p>
          {categories.map((category) => (
            <a
              key={category.id}
              href={`#${category.id}`}
              className="nav-item !min-h-9 !text-[13px]"
            >
              <span className="!ml-0 !text-[13px] !normal-case">
                {category.label}
              </span>
              <span className="font-mono text-[10px] text-[#4f7a6c]">
                {category.en}
              </span>
            </a>
          ))}
          <a href="#top" className="nav-item !min-h-9 !text-[13px]">
            <span className="!ml-0 !text-[13px]">回到顶部</span>
          </a>
          <div className="side-foot mt-4">
            <LockKeyhole size={16} />
            <div>
              <strong>零外部依赖</strong>
              <small>未安装 Storybook</small>
            </div>
            <Check size={16} />
          </div>
        </nav>

        <div id="top" className="min-w-0 space-y-8">
          {/* ---------- 按钮 ---------- */}
          <CatalogCategory
            id="buttons"
            title="按钮"
            en="Buttons"
            summary="主要操作入口：variant 决定语义，size 决定信息密度；图标子元素会自动缩放到匹配尺寸。"
          >
            <CatalogEntry
              name="Button"
              source="@/components/ui/button"
              description="基于 Base UI Button 与 class-variance-authority 封装。variant 支持 default / outline / secondary / ghost / destructive / link，size 支持 xs / sm / default / lg 以及 icon / icon-xs / icon-sm / icon-lg。同时导出 buttonVariants，便于把按钮样式套到 Link 或 Tooltip 触发器上。"
            >
              <Variant
                label="语义变体"
                code='variant="default | outline | ghost | destructive"'
              >
                <Button>同步基线</Button>
                <Button variant="outline">
                  <Download />
                  导出报告
                </Button>
                <Button variant="secondary">弱强调</Button>
                <Button variant="ghost">幽灵按钮</Button>
                <Button variant="destructive">隔离设备</Button>
                <Button variant="link">查看规则说明</Button>
              </Variant>
              <Variant
                label="尺寸与图标按钮"
                code='size="xs | sm | default | lg | icon"'
              >
                <Button size="xs">超小</Button>
                <Button size="sm">小</Button>
                <Button>默认</Button>
                <Button size="lg">大</Button>
                <Button size="icon" variant="outline" aria-label="搜索">
                  <Search />
                </Button>
                <Button size="icon-sm" variant="ghost" aria-label="设置">
                  <Settings />
                </Button>
              </Variant>
              <Variant
                label="加载与禁用"
                code="<Button disabled><Spinner />正在同步</Button>"
              >
                <Button disabled>
                  <Spinner />
                  正在同步
                </Button>
                <Button variant="outline" disabled>
                  已停用
                </Button>
                <Button variant="destructive">
                  <RefreshCw />
                  重新扫描
                </Button>
              </Variant>
            </CatalogEntry>
          </CatalogCategory>

          {/* ---------- 徽标 ---------- */}
          <CatalogCategory
            id="badges"
            title="徽标"
            en="Badges"
            summary="状态与计数标签，固定 5 单位高度（h-5）的胶囊形状，内部 svg 会被强制为 size-3。"
          >
            <CatalogEntry
              name="Badge"
              source="@/components/ui/badge"
              description="通过 useRender 实现，默认渲染 span，可用 render 属性替换为 a 等标签。variant 支持 default / secondary / destructive / outline / ghost / link。控制台各页最常用的是 outline 变体 + 指示点的组合。"
            >
              <Variant
                label="语义变体"
                code='variant="default | secondary | outline | destructive"'
              >
                <Badge>已通过</Badge>
                <Badge variant="secondary">观察中</Badge>
                <Badge variant="outline">基线 v4.8</Badge>
                <Badge variant="destructive">高危 12</Badge>
                <Badge variant="ghost">ghost</Badge>
              </Variant>
              <Variant
                label="带指示点（项目常用写法）"
                code='<Badge variant="outline"><span className="live-dot" />…</Badge>'
              >
                <Badge variant="outline">
                  <span className="live-dot" />
                  实时上报
                </Badge>
                <Badge variant="outline">
                  <span className="demo-dot" />
                  演示数据
                </Badge>
                <Badge variant="outline">
                  <span className="live-dot" />
                  只读摘要已连接
                </Badge>
              </Variant>
              <Variant label="带图标">
                <Badge>
                  <Check />
                  合规
                </Badge>
                <Badge variant="destructive">
                  <AlertTriangle />
                  需处理
                </Badge>
                <Badge variant="outline">
                  <ShieldCheck />
                  受保护
                </Badge>
              </Variant>
            </CatalogEntry>
          </CatalogCategory>

          {/* ---------- 卡片 ---------- */}
          <CatalogCategory
            id="cards"
            title="卡片"
            en="Cards"
            summary="内容容器，自带 ring-1 描边与 --card-spacing 间距变量；带 CardFooter 时会自动取消底部内边距。"
          >
            <CatalogEntry
              name="Card"
              source="@/components/ui/card"
              description="由 Card / CardHeader / CardTitle / CardDescription / CardAction / CardContent / CardFooter 组合。size 支持 default 与 sm（sm 会把间距变量从 4 降到 3）。CardAction 自动定位到头部右上角，CardFooter 自带顶部分隔线与 muted 背景。"
            >
              <Variant label="标准结构：头部 + 内容 + 页脚" vertical>
                <Card className="w-full max-w-sm">
                  <CardHeader>
                    <CardTitle>策略同步状态</CardTitle>
                    <CardDescription>
                      最近一次同步于 12 分钟前完成
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Progress value={92} />
                    <p className="mt-2 text-xs text-[#78968c]">
                      312 台终端中 287 台已应用最新基线。
                    </p>
                  </CardContent>
                  <CardFooter className="justify-between">
                    <span className="text-xs text-[#78968c]">
                      同步周期：每 15 分钟
                    </span>
                    <Button size="sm" variant="outline">
                      立即同步
                    </Button>
                  </CardFooter>
                </Card>
              </Variant>
              <Variant label="头部操作区 CardAction" vertical>
                <Card className="w-full max-w-sm">
                  <CardHeader>
                    <CardTitle>风险事件</CardTitle>
                    <CardDescription>按严重度与时间排序</CardDescription>
                    <CardAction>
                      <Badge variant="destructive">12 待处理</Badge>
                    </CardAction>
                  </CardHeader>
                  <CardContent className="text-xs text-[#78968c]">
                    高危 3 项来自 payment-service，中危 9 项集中在依赖清单过期。
                  </CardContent>
                </Card>
              </Variant>
              <Variant label="紧凑尺寸 size=sm" vertical>
                <Card size="sm" className="w-full max-w-xs">
                  <CardHeader>
                    <CardTitle>接入概览</CardTitle>
                    <CardDescription>近 7 日新增 18 台</CardDescription>
                  </CardHeader>
                  <CardContent className="text-xs text-[#78968c]">
                    紧凑卡片适合放在侧栏或仪表盘次要位置。
                  </CardContent>
                </Card>
              </Variant>
            </CatalogEntry>
          </CatalogCategory>

          {/* ---------- 数据展示 ---------- */}
          <CatalogCategory
            id="data-display"
            title="数据展示"
            en="Data Display"
            summary="指标、表格、头像、骨架屏与分隔线：控制台里承载真实数据的主要组件。"
          >
            <CatalogEntry
              name="Progress"
              source="@/components/ui/progress"
              description="value 取值 0 到 100，内部自带 Track 与 Indicator；把 ProgressLabel / ProgressValue 作为子节点传入即可显示标题与百分比（ProgressValue 不传 children 时自动输出格式化数值）。"
              note="放在 .metric 或 .coverage-row 内时，globals.css 会把进度条覆盖为 4px 高、带绿色发光的样式；.metric.danger 下则切换为红色渐变。"
            >
              <Variant label="不同进度值：25% / 65% / 92%" vertical>
                <div className="w-full max-w-md space-y-3">
                  <Progress value={25}>
                    <ProgressLabel>Skill 扫描覆盖率</ProgressLabel>
                    <ProgressValue />
                  </Progress>
                  <Progress value={65}>
                    <ProgressLabel>MCP 权限收敛</ProgressLabel>
                    <ProgressValue />
                  </Progress>
                  <Progress value={92}>
                    <ProgressLabel>基线合规率</ProgressLabel>
                    <ProgressValue />
                  </Progress>
                </div>
              </Variant>
              <Variant label="在指标卡中的实际效果" vertical>
                <article className="metric w-full max-w-xs">
                  <div className="metric-top">
                    <span>基线覆盖率</span>
                    <ShieldCheck size={18} />
                  </div>
                  <strong>
                    92.4<small>%</small>
                  </strong>
                  <Progress value={92} />
                  <p>
                    当前版本设备 <em>287</em> 台
                  </p>
                </article>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="Table"
              source="@/components/ui/table"
              description="原生 table 语义封装，外层自动包一个 overflow-x-auto 容器。需要无障碍表头、列对齐或排序语义时优先用它。"
              note="项目内多数列表页使用的是 .data-head / .data-row 网格写法（见「自定义样式」一节），两者不要在同一张表里混用。"
            >
              <Variant label="三行数据表" vertical>
                <div className="w-full">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>设备 ID</TableHead>
                        <TableHead>用户 · 工具</TableHead>
                        <TableHead>Agent 版本</TableHead>
                        <TableHead className="text-right">状态</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {deviceRows.map(([id, owner, version, status]) => (
                        <TableRow key={id}>
                          <TableCell className="font-medium">{id}</TableCell>
                          <TableCell className="text-[#78968c]">
                            {owner}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-[#78968c]">
                            {version}
                          </TableCell>
                          <TableCell className="text-right">
                            <Badge
                              variant={
                                status === '拦截' ? 'destructive' : 'outline'
                              }
                            >
                              {status}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="Avatar"
              source="@/components/ui/avatar"
              description="size 支持 sm / default / lg；AvatarFallback 在图片缺失或未加载时显示（此处全部使用首字母回退）。AvatarGroup 会把头像叠放，AvatarGroupCount 用于溢出计数，AvatarBadge 是右下角状态点。"
            >
              <Variant label="回退头像与尺寸">
                <Avatar size="sm">
                  <AvatarFallback>沈</AvatarFallback>
                </Avatar>
                <Avatar>
                  <AvatarFallback>SL</AvatarFallback>
                </Avatar>
                <Avatar size="lg">
                  <AvatarFallback>GT</AvatarFallback>
                </Avatar>
              </Variant>
              <Variant label="头像组与状态点">
                <AvatarGroup>
                  <Avatar>
                    <AvatarFallback>SL</AvatarFallback>
                  </Avatar>
                  <Avatar>
                    <AvatarFallback>WQ</AvatarFallback>
                  </Avatar>
                  <Avatar>
                    <AvatarFallback>ZL</AvatarFallback>
                  </Avatar>
                  <AvatarGroupCount>+9</AvatarGroupCount>
                </AvatarGroup>
                <Avatar size="lg">
                  <AvatarFallback>AK</AvatarFallback>
                  <AvatarBadge />
                </Avatar>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="Skeleton"
              source="@/components/ui/skeleton"
              description="加载占位块，animate-pulse + bg-muted。用宽高类拼出与真实内容一致的骨架，避免加载完成后布局跳动。"
            >
              <Variant label="文本行占位" vertical>
                <div className="w-full max-w-sm space-y-2">
                  <Skeleton className="h-3.5 w-2/5" />
                  <Skeleton className="h-3 w-full" />
                  <Skeleton className="h-3 w-4/5" />
                </div>
              </Variant>
              <Variant label="卡片骨架屏" vertical>
                <div className="w-full max-w-sm rounded-xl border border-[#1b332c] bg-[#0b1a16] p-4">
                  <div className="flex items-center gap-3">
                    <Skeleton className="size-9 rounded-full" />
                    <div className="flex-1 space-y-2">
                      <Skeleton className="h-3 w-1/3" />
                      <Skeleton className="h-2.5 w-1/2" />
                    </div>
                  </div>
                  <Skeleton className="mt-4 h-20 w-full rounded-lg" />
                </div>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="Separator"
              source="@/components/ui/separator"
              description="语义分隔线，orientation 支持 horizontal 与 vertical；垂直模式需要父容器有确定高度（self-stretch）。"
            >
              <Variant label="水平分隔" vertical>
                <div className="w-full max-w-sm">
                  <p className="text-xs text-[#78968c]">
                    扫描引擎：Semgrep + 自研规则
                  </p>
                  <Separator className="my-3" />
                  <p className="text-xs text-[#78968c]">
                    策略版本：v4.8 · 只读
                  </p>
                </div>
              </Variant>
              <Variant label="垂直分隔">
                <div className="flex h-6 items-center gap-3 text-xs text-[#78968c]">
                  <span>只读摘要</span>
                  <Separator orientation="vertical" />
                  <span>演示数据</span>
                </div>
              </Variant>
            </CatalogEntry>
          </CatalogCategory>

          {/* ---------- 反馈 ---------- */}
          <CatalogCategory
            id="feedback"
            title="反馈"
            en="Feedback"
            summary="告知用户系统状态：Alert 常驻提示、Spinner 进行中、Tooltip 悬停解释、Toast 瞬时结果。"
          >
            <CatalogEntry
              name="Alert"
              source="@/components/ui/alert"
              description="alertVariants 只内置 default 与 destructive 两个 variant，因此信息态与警告态需要通过 className 扩展边框与文字色，下面给出与主题一致的写法。结构为 Alert 内放 svg 图标 + AlertTitle + AlertDescription，可选 AlertAction（绝对定位到右上角，容器会自动预留右侧内边距）。"
              note="如果 info / warning 会被多个页面复用，应该在 alertVariants 中新增 variant，而不是在每个页面重复写 className。"
            >
              <Variant label="信息 info" vertical>
                <Alert className="border-[#295443] bg-[#0f2620] text-[#c9f5e4]">
                  <Info />
                  <AlertTitle>只读摘要已连接</AlertTitle>
                  <AlertDescription className="text-[#8fc7b3]">
                    数据来自 /api/summary，每 60 秒刷新一次，不会写入任何终端。
                  </AlertDescription>
                </Alert>
              </Variant>
              <Variant label="警告 warning" vertical>
                <Alert className="border-[#6a5427] bg-[#2b2313] text-[#ffd77f]">
                  <AlertTriangle />
                  <AlertTitle>组件走查</AlertTitle>
                  <AlertDescription className="text-[#d9c28d]">
                    接收器未连接，页面中的设备数、合规率与风险条目均为界面样例。
                  </AlertDescription>
                </Alert>
              </Variant>
              <Variant label="危险 destructive" vertical>
                <Alert variant="destructive">
                  <AlertTriangle />
                  <AlertTitle>发现 3 项高危风险</AlertTitle>
                  <AlertDescription>
                    包含硬编码密钥与越权的 MCP 工具调用，需在 24 小时内处置。
                  </AlertDescription>
                  <AlertAction>
                    <Button size="xs" variant="destructive">
                      立即处理
                    </Button>
                  </AlertAction>
                </Alert>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="Spinner"
              source="@/components/ui/spinner"
              description="Loader2 图标 + animate-spin，自带 role=status 与 aria-label。尺寸与颜色直接用 Tailwind 类覆盖。"
            >
              <Variant label="尺寸与配色">
                <Spinner />
                <Spinner className="size-5 text-[#4fe5a6]" />
                <Spinner className="size-6 text-[#ff8f88]" />
                <Button variant="outline" disabled>
                  <Spinner />
                  加载中
                </Button>
              </Variant>
              <Variant label="区域内联加载" vertical>
                <div className="flex w-full max-w-sm items-center gap-2 rounded-lg border border-[#172d26] bg-[#0a1714] px-3 py-2 text-xs text-[#78968c]">
                  <Spinner className="size-3.5 text-[#4fe5a6]" />
                  正在拉取设备清单…
                </div>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="Tooltip"
              source="@/components/ui/tooltip"
              description="Base UI Tooltip 封装。TooltipProvider 提供共享延迟（delay 默认 0），TooltipContent 支持 side / sideOffset / align 定位。TooltipTrigger 默认渲染 button，若要触发器本身是 Button 组件，请用 render 属性而不是嵌套，避免出现 button 套 button。"
            >
              <TooltipProvider delay={120}>
                <Variant label="悬停显示（不同方向）">
                  <Tooltip>
                    <TooltipTrigger render={<Button variant="outline" />}>
                      扫描详情
                    </TooltipTrigger>
                    <TooltipContent>
                      最近一次扫描：2 分钟前 · 命中 3 条规则
                    </TooltipContent>
                  </Tooltip>
                  <Tooltip>
                    <TooltipTrigger
                      render={
                        <Button
                          size="icon"
                          variant="ghost"
                          aria-label="风险说明"
                        />
                      }
                    >
                      <AlertTriangle />
                    </TooltipTrigger>
                    <TooltipContent side="right">
                      高危：需 24 小时内处置
                    </TooltipContent>
                  </Tooltip>
                  <Tooltip>
                    <TooltipTrigger render={<Button variant="link" />}>
                      合规率口径
                    </TooltipTrigger>
                    <TooltipContent side="bottom">
                      合规率 = 已通过基线校验的设备 / 受管设备总数
                    </TooltipContent>
                  </Tooltip>
                </Variant>
              </TooltipProvider>
            </CatalogEntry>

            <CatalogEntry
              name="Toast 轻提示"
              source="app/globals.css 第 8 节 · .toast"
              description="项目自定义的全局提示条，position: fixed 固定在视口右上（right 24px / top 78px），带 toast-in 入场动画与玻璃拟态背景。用法是条件渲染加定时清除，各业务页面都用同一套写法。"
              note=".toast 是固定定位，不能内嵌在文档流里做静态展示；下面的按钮会触发页面右上角的真实 Toast。"
            >
              <Variant label="点击触发真实 Toast">
                <Button
                  variant="outline"
                  onClick={() =>
                    setToast('功能待接入：未连接策略发布 API，未修改任何终端。')
                  }
                >
                  <CircleDot />
                  触发 Toast
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => setToast('已复制设备指纹到剪贴板（样例）')}
                >
                  再来一条
                </Button>
              </Variant>
            </CatalogEntry>
          </CatalogCategory>

          {/* ---------- 导航 ---------- */}
          <CatalogCategory
            id="navigation"
            title="导航"
            en="Navigation"
            summary="页面内切换与侧边栏导航：Tabs 组件与项目自定义的 .nav-item。"
          >
            <CatalogEntry
              name="Tabs"
              source="@/components/ui/tabs"
              description="TabsList 有 default（胶囊底）与 line（下划线）两种 variant；TabsTrigger 与 TabsContent 通过 value 配对，Tabs 用 defaultValue 指定初始激活项，orientation 可切换为 vertical。"
            >
              <Variant label="三项标签页（default）" vertical>
                <Tabs defaultValue="scan" className="w-full max-w-lg">
                  <TabsList>
                    <TabsTrigger value="scan">扫描概览</TabsTrigger>
                    <TabsTrigger value="rules">命中规则</TabsTrigger>
                    <TabsTrigger value="history">历史记录</TabsTrigger>
                  </TabsList>
                  <TabsContent
                    value="scan"
                    className="w-full rounded-lg border border-[#172d26] bg-[#0a1714] p-3 text-xs text-[#78968c]"
                  >
                    今日扫描 35 个仓库，新增发现 2 项，门禁通过率 94%。
                  </TabsContent>
                  <TabsContent
                    value="rules"
                    className="w-full rounded-lg border border-[#172d26] bg-[#0a1714] p-3 text-xs text-[#78968c]"
                  >
                    命中 SEC-AUTH-01（硬编码密钥）与
                    SEC-INJ-03（输入未参数化）。
                  </TabsContent>
                  <TabsContent
                    value="history"
                    className="w-full rounded-lg border border-[#172d26] bg-[#0a1714] p-3 text-xs text-[#78968c]"
                  >
                    最近 7 日累计扫描 154 次，阻断 6 次。
                  </TabsContent>
                </Tabs>
              </Variant>
              <Variant label="下划线样式 variant=line" vertical>
                <Tabs defaultValue="day" className="w-full max-w-lg">
                  <TabsList variant="line">
                    <TabsTrigger value="day">按日</TabsTrigger>
                    <TabsTrigger value="week">按周</TabsTrigger>
                    <TabsTrigger value="month">按月</TabsTrigger>
                  </TabsList>
                  <TabsContent
                    value="day"
                    className="w-full pt-1 text-xs text-[#78968c]"
                  >
                    日维度视图，适合排查单次发布引入的问题。
                  </TabsContent>
                  <TabsContent
                    value="week"
                    className="w-full pt-1 text-xs text-[#78968c]"
                  >
                    周维度视图，用于团队周会复盘。
                  </TabsContent>
                  <TabsContent
                    value="month"
                    className="w-full pt-1 text-xs text-[#78968c]"
                  >
                    月维度视图，用于向管理层汇报趋势。
                  </TabsContent>
                </Tabs>
              </Variant>
              <Variant label="禁用项" vertical>
                <Tabs defaultValue="a" className="w-full max-w-lg">
                  <TabsList>
                    <TabsTrigger value="a">概览</TabsTrigger>
                    <TabsTrigger value="b">明细</TabsTrigger>
                    <TabsTrigger value="c" disabled>
                      导出（未连接）
                    </TabsTrigger>
                  </TabsList>
                  <TabsContent
                    value="a"
                    className="w-full pt-1 text-xs text-[#78968c]"
                  >
                    未连接的接口对应的标签页应使用 disabled，而不是隐藏。
                  </TabsContent>
                  <TabsContent
                    value="b"
                    className="w-full pt-1 text-xs text-[#78968c]"
                  >
                    明细数据需要接收器在线。
                  </TabsContent>
                </Tabs>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="导航项"
              source="app/globals.css 第 6 节 · .nav-item / .nav-item.active"
              description="控制台侧边栏导航项：44px 最小高度，悬停时右移 2px 并出现 3px 绿色内描边，.active 使用绿色渐变背景与主色文字。尾部计数用 span，告警计数用 b（红色发光胶囊），两者都会自动靠右对齐。"
              note="本页左侧的分类导航就是 .nav-item 的真实用法；示例中用 important 修饰类压缩了高度，生产侧边栏请直接使用原始类。"
            >
              <Variant label="默认 / 选中 / 带计数" vertical>
                <div className="w-full max-w-xs rounded-lg border border-[#172d26] bg-[#0a1714] p-2">
                  <a className="nav-item" href="#navigation">
                    <Activity size={18} />
                    总览
                  </a>
                  <a className="nav-item active" href="#navigation">
                    <AlertTriangle size={18} />
                    风险中心
                    <b>12</b>
                  </a>
                  <a className="nav-item" href="#navigation">
                    <Laptop size={18} />
                    设备与 Agent
                    <span>312</span>
                  </a>
                  <a className="nav-item" href="#navigation">
                    <Sparkles size={18} />
                    Skill 扫描器
                  </a>
                </div>
              </Variant>
            </CatalogEntry>
          </CatalogCategory>

          {/* ---------- 表单 ---------- */}
          <CatalogCategory
            id="forms"
            title="表单"
            en="Forms"
            summary="开关、勾选与输入：均为受控 / 非受控双模式，优先使用 defaultChecked、defaultValue 保持示例简洁。"
          >
            <CatalogEntry
              name="Switch / Toggle"
              source="@/components/ui/switch · @/components/ui/toggle"
              description="Switch 是布尔开关，size 支持 sm 与 default，受控时用 checked + onCheckedChange，非受控用 defaultChecked。Toggle 是可按压的切换按钮，用 pressed / defaultPressed / onPressedChange，variant 支持 default 与 outline。"
            >
              <Variant label="开 / 关状态" vertical>
                <ControlRow
                  label="启用实时扫描"
                  hint="开启后每 15 分钟增量扫描一次"
                >
                  <Switch defaultChecked />
                </ControlRow>
                <ControlRow
                  label="仅观察不阻断"
                  hint="命中规则时只记录，不拦截合并请求"
                >
                  <Switch />
                </ControlRow>
              </Variant>
              <Variant label="受控 / 小尺寸 / 禁用">
                <ControlRow label={`受控状态：${liveScan ? '开' : '关'}`}>
                  <Switch checked={liveScan} onCheckedChange={setLiveScan} />
                </ControlRow>
                <Switch size="sm" defaultChecked aria-label="小尺寸开关" />
                <Switch disabled defaultChecked aria-label="禁用开关" />
              </Variant>
              <Variant label="Toggle 按压态" code="defaultPressed">
                <Toggle aria-label="只看高危">
                  <AlertTriangle />
                </Toggle>
                <Toggle variant="outline" defaultPressed>
                  <RefreshCw />
                  实时刷新
                </Toggle>
                <Toggle variant="outline" disabled>
                  <Download />
                  导出
                </Toggle>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="Checkbox"
              source="@/components/ui/checkbox"
              description="自带 Indicator 与 Check 图标，无需额外子节点。选中态通过 data-checked 切换主色背景，可与 Label 组合使用。"
            >
              <Variant label="勾选状态" vertical>
                <Label className="gap-2 text-xs font-normal">
                  <Checkbox defaultChecked />
                  阻断高危合并请求
                </Label>
                <Label className="gap-2 text-xs font-normal">
                  <Checkbox />
                  仅记录，不阻断
                </Label>
                <Label className="gap-2 text-xs font-normal opacity-50">
                  <Checkbox disabled defaultChecked />
                  企业强制项（不可修改）
                </Label>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="Input / Label"
              source="@/components/ui/input · @/components/ui/label"
              description="Input 高度 h-8，聚焦时显示 ring 描边；错误态用 aria-invalid 触发 destructive 边框。Label 是无样式的 label 封装，可与任意表单控件通过 htmlFor 或嵌套关联。"
            >
              <Variant label="文本输入" vertical>
                <div className="w-full max-w-sm space-y-2">
                  <Label htmlFor="catalog-device">设备名称</Label>
                  <Input
                    id="catalog-device"
                    placeholder="例如 payment-service"
                    defaultValue="auth-gateway"
                  />
                </div>
              </Variant>
              <Variant label="禁用与错误态" vertical>
                <Input
                  className="max-w-sm"
                  disabled
                  defaultValue="由企业策略统一下发"
                />
                <Input
                  className="max-w-sm"
                  aria-invalid
                  placeholder="请填写白名单域名"
                  defaultValue="https://内部网关"
                />
              </Variant>
            </CatalogEntry>
          </CatalogCategory>

          {/* ---------- 自定义样式 ---------- */}
          <CatalogCategory
            id="patterns"
            title="自定义样式"
            en="Custom Patterns"
            summary="不来自 shadcn/ui、而是直接写在 globals.css / detail.css 里的项目样式类。这些类没有 React 封装，使用时必须严格遵循约定的 DOM 结构。导航项 .nav-item 见「导航」，Toast .toast 见「反馈」。"
          >
            <CatalogEntry
              name="指标卡 Metric"
              source="app/globals.css 第 9 节 · .metric / .metric.danger"
              description="总览页 KPI 卡片：玻璃拟态背景、顶部渐变亮线、悬停上浮 2px。DOM 结构约定为 .metric-top（标题 + 图标）→ strong（大数字，可内嵌 small 单位）→ Progress → p（补充说明，其中 em 表示正向增量、i 表示负向增量）。.danger 变体切换为红色主题。"
              note="生产页面用 .metrics（固定四列网格）包裹多张卡片；.metrics 的 grid-template-columns 写在无 layer 的自定义 CSS 中，Tailwind 的 grid-cols-* 工具类无法覆盖它，需要响应式时请自行写网格容器。"
            >
              <Variant label="常规 / 带进度 / 危险" vertical>
                <div className="grid w-full gap-3.5 sm:grid-cols-2 xl:grid-cols-3">
                  <article className="metric">
                    <div className="metric-top">
                      <span>受管终端</span>
                      <Laptop size={18} />
                    </div>
                    <strong>
                      312<small>台</small>
                    </strong>
                    <p>
                      较上周 <em>+4.2%</em>
                    </p>
                  </article>
                  <article className="metric">
                    <div className="metric-top">
                      <span>基线覆盖率</span>
                      <ShieldCheck size={18} />
                    </div>
                    <strong>
                      92.4<small>%</small>
                    </strong>
                    <Progress value={92} />
                    <p>
                      当前版本设备 <em>287</em> 台
                    </p>
                  </article>
                  <article className="metric danger">
                    <div className="metric-top">
                      <span>高风险设备</span>
                      <AlertTriangle size={18} />
                    </div>
                    <strong>
                      7<small>台</small>
                    </strong>
                    <Progress value={22} />
                    <p>
                      待处置 <i>3</i> 项高危事件
                    </p>
                  </article>
                </div>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="面板 Panel"
              source="app/globals.css 第 10 节 · .panel / .panel-head"
              description="与 .metric 共享边框、玻璃背景与阴影的基础容器，区别在于内边距更大且顶部亮线更弱。头部使用 .panel-head（左标题 + 右操作），标题用 h2、副标题用 p；panel-head 内的 Badge 与 button 会被自动重新着色。"
            >
              <Variant label="标准面板" vertical>
                <section className="panel w-full">
                  <div className="panel-head">
                    <div>
                      <h2>Agent 接入进度</h2>
                      <p>按团队统计的静默加载覆盖情况</p>
                    </div>
                    <Badge variant="outline">
                      <span className="live-dot" />
                      实时更新
                    </Badge>
                  </div>
                  <div className="grid gap-3 sm:grid-cols-3">
                    <div className="rounded-lg border border-[#172d26] bg-[#0a1714] p-3">
                      <p className="text-xs text-[#78968c]">平台工程</p>
                      <Progress value={96} />
                    </div>
                    <div className="rounded-lg border border-[#172d26] bg-[#0a1714] p-3">
                      <p className="text-xs text-[#78968c]">业务研发</p>
                      <Progress value={71} />
                    </div>
                    <div className="rounded-lg border border-[#172d26] bg-[#0a1714] p-3">
                      <p className="text-xs text-[#78968c]">数据智能</p>
                      <Progress value={44} />
                    </div>
                  </div>
                </section>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="严重度标签 Severity"
              source="app/globals.css 第 13 节 · .severity / .severity.red / .severity.orange"
              description="风险表中的等级标签：10px 字号、字重 700、发光边框。目前只提供 red（高危）与 orange（中危）两个修饰类，其他等级需要自行补充。父级 .risk-row 悬停时会增强发光。"
            >
              <Variant label="高危 / 中危">
                <span className="severity red">高危</span>
                <span className="severity orange">中危</span>
              </Variant>
              <Variant label="在风险行中的用法" vertical>
                <div className="w-full rounded-lg border border-[#172d26] bg-[#0a1714] p-2">
                  <div className="risk-row wide">
                    <span className="severity red">高危</span>
                    <div className="risk-main">
                      <strong>硬编码数据库凭据</strong>
                      <span>payment-service · SAST</span>
                    </div>
                    <span className="device">dev-mac-0142</span>
                    <span className="time">08:42</span>
                    <button
                      className="handle"
                      onClick={() =>
                        setToast('功能待接入：未连接工单接口，未认领该事件。')
                      }
                    >
                      认领处置
                    </button>
                  </div>
                  <div className="risk-row wide">
                    <span className="severity orange">中危</span>
                    <div className="risk-main">
                      <strong>MCP 工具权限过宽</strong>
                      <span>analytics-api · MCP 扫描</span>
                    </div>
                    <span className="device">ci-runner-007</span>
                    <span className="time">09:15</span>
                    <button
                      className="handle"
                      onClick={() =>
                        setToast('功能待接入：未连接工单接口，未认领该事件。')
                      }
                    >
                      认领处置
                    </button>
                  </div>
                </div>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="数据表格行"
              source="app/detail.css · .data-head / .data-row"
              description="项目列表页的主力表格：CSS Grid 固定四列 1.2fr / 0.8fr / 1fr / 0.5fr。表头是 10px 大写字母间距的小标题，数据行偶数行有微弱底色、悬停出现左侧绿色内描边。列内约定：strong 放主标识、span 放次要信息、i 放状态标签。"
              note="列数与 grid-template-columns 强绑定：增减列时必须同步修改 detail.css，或在容器上另写一套网格类；.data-row 状态标签的排版样式来自 .data-row i 选择器。"
            >
              <Variant label="表头 + 三行数据" vertical>
                <div className="w-full rounded-lg border border-[#172d26] bg-[#0a1714] px-1 py-1">
                  <div className="data-head">
                    <span>设备 ID</span>
                    <span>用户 · 工具</span>
                    <span>Agent 版本</span>
                    <span>状态</span>
                  </div>
                  {deviceRows.map(([id, owner, version, status, tone]) => (
                    <div className="data-row" key={id}>
                      <strong>{id}</strong>
                      <span>{owner}</span>
                      <span>{version}</span>
                      <i className={tone}>{status}</i>
                    </div>
                  ))}
                </div>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="状态指示 Status"
              source="app/detail.css · .pass / .fail / .warn"
              description="三态标签：通过（绿）、失败（红）、警告（琥珀）。业务页面通常用一个 statusTone(status) 工具函数把中文状态映射到类名。"
              note="padding、圆角、字号与 font-style: normal 都定义在 .data-row i 与 .policy-card i 两条规则里，脱离这两个父级单独使用 .pass 只会得到颜色，且 i 标签会保持斜体。独立使用时请改用 span 并补齐排版类（见第二个示例）。"
            >
              <Variant label="在 .data-row 内（推荐）" vertical>
                <div className="w-full max-w-md rounded-lg border border-[#172d26] bg-[#0a1714] px-1 py-1">
                  <div className="data-row">
                    <strong>SEC-AUTH-01</strong>
                    <span>硬编码密钥</span>
                    <span>阻断</span>
                    <i className="fail">未通过</i>
                  </div>
                  <div className="data-row">
                    <strong>SEC-DEP-04</strong>
                    <span>高危依赖</span>
                    <span>需审批</span>
                    <i className="warn">待复核</i>
                  </div>
                  <div className="data-row">
                    <strong>SEC-LOG-02</strong>
                    <span>日志脱敏</span>
                    <span>观察</span>
                    <i className="pass">通过</i>
                  </div>
                </div>
              </Variant>
              <Variant
                label="脱离 .data-row 时补齐排版类"
                code='className="pass inline-block rounded-md px-2 py-1 text-[10px] font-semibold"'
              >
                <span className="pass inline-block rounded-md px-2 py-1 text-[10px] font-semibold">
                  通过
                </span>
                <span className="warn inline-block rounded-md px-2 py-1 text-[10px] font-semibold">
                  告警
                </span>
                <span className="fail inline-block rounded-md px-2 py-1 text-[10px] font-semibold">
                  拦截
                </span>
              </Variant>
            </CatalogEntry>

            <CatalogEntry
              name="其他常用类速查"
              source="app/globals.css · app/demo.css"
              description="目录页与控制台共用的高频类，便于快速对照。"
            >
              <Variant label="辅助类" vertical>
                <p className="eyebrow">安全能力 / 组件目录</p>
                <span className="system-ok">
                  <span className="live-dot" />
                  只读摘要已连接
                </span>
                <span className="system-ok">
                  <span className="demo-dot" />
                  演示数据 · 接收器未连接
                </span>
                <div className="flex flex-wrap items-center gap-2">
                  <button className="handle">认领处置</button>
                  <button className="icon-btn" aria-label="搜索">
                    <Search size={18} />
                  </button>
                  <span className="flex items-center gap-2 text-xs text-[#78968c]">
                    <Users size={14} />
                    团队与权限
                    <Bot size={14} />
                    接入中心
                  </span>
                </div>
              </Variant>
            </CatalogEntry>
          </CatalogCategory>
        </div>
      </div>
    </div>
  );
}
