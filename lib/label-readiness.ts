import { ensureLabelsLoaded } from '@/lib/labels';
import { logAudit } from '@/lib/store';

/** No label mutation or policy construction may use an unavailable snapshot. */
export async function labelsReadyFor(operation: string, actor: string): Promise<boolean> {
  try {
    await ensureLabelsLoaded();
    return true;
  } catch {
    logAudit({
      actor,
      action: 'labels:load_failed',
      resource_type: 'system',
      detail: `operation=${operation}; labels_unavailable`,
    });
    return false;
  }
}
