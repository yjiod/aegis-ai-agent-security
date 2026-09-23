'use client';

import * as React from 'react';
import { AlertTriangle, ShieldAlert, Undo2, UserRound } from 'lucide-react';

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogMedia,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Spinner } from '@/components/ui/spinner';
import { cn } from '@/lib/utils';

/**
 * 统一的不可逆动作确认弹窗（handoff P0 / 安全基线 1.5 不可逆操作保护）。
 *
 * 取代散落的 window.confirm：在执行前向操作人明确展示
 *   ① 影响范围（impact）—— 这一步会改变什么；
 *   ② 回滚方式（rollback）—— 出错了怎么恢复；
 *   ③ 操作人（operator）—— 谁在执行，便于审计追溯。
 * 弹窗本身只负责“确认”，真正的审计落库由各动作的服务端接口完成；
 * 这里保证的是“人在回路”与“影响可见”，封禁/删除等动作绝不自动执行。
 */
export type ActionConfirmVariant = 'danger' | 'warning' | 'default';

export interface ActionConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  /** 一句话说明动作本身；可传富文本。 */
  description?: React.ReactNode;
  /** 影响范围：逐条列出该动作会改变什么。 */
  impact?: string[];
  /** 回滚方式：告诉操作人如何撤销 / 恢复。 */
  rollback?: string;
  /**
   * 操作人标识（运行时值，例如当前登录工号 / 角色）。
   * 安全红线：禁止在代码里硬编码真实工号，只能由调用方在运行时传入。
   */
  operator?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: ActionConfirmVariant;
  busy?: boolean;
  busyLabel?: string;
  onConfirm: () => void;
}

const VARIANT_ICON: Record<ActionConfirmVariant, typeof ShieldAlert> = {
  danger: ShieldAlert,
  warning: AlertTriangle,
  default: AlertTriangle,
};

const VARIANT_MEDIA: Record<ActionConfirmVariant, string> = {
  danger: 'bg-destructive/12 text-destructive',
  warning: 'bg-muted text-[var(--sentinel-warning,#ffb84b)]',
  default: 'bg-muted text-muted-foreground',
};

export function ActionConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  impact,
  rollback,
  operator,
  confirmLabel = '确认执行',
  cancelLabel = '取消',
  variant = 'default',
  busy = false,
  busyLabel,
  onConfirm,
}: ActionConfirmDialogProps) {
  const Icon = VARIANT_ICON[variant];
  const hasImpact = Array.isArray(impact) && impact.length > 0;

  return (
    <AlertDialog
      open={open}
      onOpenChange={(next) => {
        // 执行中禁止关闭，避免操作人误以为动作被取消。
        if (!next && busy) return;
        onOpenChange(next);
      }}
    >
      <AlertDialogContent size="default" className="sm:max-w-md">
        <AlertDialogHeader>
          <AlertDialogMedia className={cn(VARIANT_MEDIA[variant])}>
            <Icon />
          </AlertDialogMedia>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          {description ? (
            <AlertDialogDescription>{description}</AlertDialogDescription>
          ) : null}
        </AlertDialogHeader>

        {(hasImpact || rollback || operator) && (
          <div className="grid gap-2 text-sm">
            {hasImpact && (
              <div className="rounded-lg border border-border/70 bg-muted/40 p-3">
                <p className="mb-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">
                  影响范围
                </p>
                <ul className="grid gap-1">
                  {impact?.map((line) => (
                    <li key={line} className="flex gap-2 text-foreground/90">
                      <span aria-hidden className="mt-[7px] size-1.5 shrink-0 rounded-full bg-current opacity-60" />
                      <span>{line}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {rollback && (
              <p className="flex gap-2 text-muted-foreground">
                <Undo2 size={15} className="mt-[2px] shrink-0" aria-hidden />
                <span>
                  <b className="font-medium text-foreground/80">回滚：</b>
                  {rollback}
                </span>
              </p>
            )}
            {operator && (
              <p className="flex gap-2 text-muted-foreground">
                <UserRound size={15} className="mt-[2px] shrink-0" aria-hidden />
                <span>
                  <b className="font-medium text-foreground/80">操作人：</b>
                  {operator}
                  <span className="text-xs">（将记入审计日志）</span>
                </span>
              </p>
            )}
          </div>
        )}

        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>{cancelLabel}</AlertDialogCancel>
          <AlertDialogAction
            variant={variant === 'danger' ? 'destructive' : 'default'}
            disabled={busy}
            onClick={(event) => {
              // 由父组件控制关闭时机（动作完成后），这里阻止默认关闭。
              event.preventDefault();
              onConfirm();
            }}
          >
            {busy ? <Spinner /> : <Icon />}
            {busy ? (busyLabel ?? '执行中…') : confirmLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export default ActionConfirmDialog;
