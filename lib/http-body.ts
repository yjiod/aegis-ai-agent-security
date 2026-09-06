/**
 * lib/http-body.ts — 把未定型的 JSON 请求体安全收窄为原始值。
 *
 * WHY: `await request.json()` 的静态类型是 unknown（这里统一标注为
 * `Record<string, unknown>`）。直接 `String(body.foo)` 在客户端传对象或数组时
 * 会静默产出 "[object Object]" 并写入存储 —— 对一个治理/审计类 API 而言这是
 * 数据完整性缺陷，不是风格问题。这里集中收窄：只接受 string / number /
 * boolean / bigint，其余一律判为非法并由调用方转 400。
 *
 * 收窄规则刻意区分「字段缺省」与「字段类型非法」：缺省走 fallback（保持既有
 * 宽松行为），类型非法直接拒绝（不静默降级成 fallback，否则 `{"severity":{}}`
 * 会被当成合法的 medium 写入）。
 *
 * 时间戳约定见 lib/store.ts 头部注释：store 与全部 TS 路由一律 epoch 毫秒
 * (`Date.now()`)，秒制只存在于 Python Collector 边界。
 */

/** 收窄失败时抛出，由路由处理器统一转 400 响应。 */
export class InvalidBodyField extends Error {
  readonly field: string;
  readonly reason: 'missing' | 'not_primitive';

  constructor(field: string, reason: 'missing' | 'not_primitive') {
    super(`invalid_field:${field}:${reason}`);
    this.name = 'InvalidBodyField';
    this.field = field;
    this.reason = reason;
  }
}

/** 仅原始类型可安全转文本；对象/数组/函数/符号返回 undefined。 */
function primitiveText(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return String(value);
  }
  return undefined;
}

/** 字段是否被显式提供（区分 undefined 与 null：null 视为已提供但缺值）。 */
function isAbsent(value: unknown): boolean {
  return value === undefined || value === null;
}

/**
 * 必填文本字段。缺省或类型非法都抛 InvalidBodyField。
 * 用于调用方已经用 `!== undefined` 判过存在性的分支。
 */
export function requireText(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (isAbsent(value)) throw new InvalidBodyField(field, 'missing');
  const text = primitiveText(value);
  if (text === undefined) throw new InvalidBodyField(field, 'not_primitive');
  return text;
}

/**
 * 可选文本字段：缺省返回 fallback，显式给了非法类型则抛。
 * 长度裁剪交给调用方（各字段上限不同，且需与后续校验语义保持一致）。
 */
export function optionalText(
  body: Record<string, unknown>,
  field: string,
  fallback: string,
): string {
  const value = body[field];
  if (isAbsent(value)) return fallback;
  const text = primitiveText(value);
  if (text === undefined) throw new InvalidBodyField(field, 'not_primitive');
  return text;
}

/**
 * 可省略文本字段：缺省或空串返回 undefined（对应 `body.x ? ... : undefined`
 * 的既有语义），否则裁剪到 maxLength。用于 description / finding_ref / note。
 */
export function maybeText(
  body: Record<string, unknown>,
  field: string,
  maxLength: number,
): string | undefined {
  const value = body[field];
  if (isAbsent(value) || value === '') return undefined;
  const text = primitiveText(value);
  if (text === undefined) throw new InvalidBodyField(field, 'not_primitive');
  return text.slice(0, maxLength);
}

/** 把 InvalidBodyField 映射成对外错误负载；非本类错误原样上抛。 */
export function invalidFieldPayload(error: unknown): { error: string; fields?: string } | null {
  if (error instanceof InvalidBodyField) {
    return {
      error: 'invalid_field_type',
      fields: `${error.field} (${error.reason})`,
    };
  }
  return null;
}
