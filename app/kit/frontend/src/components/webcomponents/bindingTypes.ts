import type { RecordRow } from '../../lib/dataApi';
import type { DescribeResponse } from '../../lib/describe';
import type { ReportDataResponse } from '../../lib/reports';

export interface ResolvedInput {
  /** Absent on an app home or dashboard, where no record is open. */
  record?: RecordRow;
  describe?: DescribeResponse;
  props: Record<string, unknown>;
  rows: Record<string, RecordRow[]>;
  /** Describe of every object a plan fetched, by api_name; picklist order and labels live here. */
  describes: Record<string, DescribeResponse>;
  /** Saved-report results by plan path; a report that failed to load is absent. */
  reports?: Record<string, ReportDataResponse>;
  /** True when a stage hit its paging or id cap, so the rows are a partial view. */
  truncated?: boolean;
}

/** The input of a kind bound to the open record: both are always present. */
export type RecordInput = ResolvedInput & { record: RecordRow; describe: DescribeResponse };

export interface RelatedListRef {
  child_object: string;
  relationship: string;
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function str(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

export function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

export function objects(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.filter(isObject) : [];
}

export function isRelatedListRef(value: unknown): value is RelatedListRef {
  return (
    isObject(value) &&
    typeof value['child_object'] === 'string' &&
    typeof value['relationship'] === 'string'
  );
}
