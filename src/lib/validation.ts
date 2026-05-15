import type { ChildSliceSpec, ValidationResult } from './types';

export interface ValidatedChild extends Required<Pick<ChildSliceSpec, 'title' | 'startOffset' | 'endOffset'>> {
  id?: string;
  role?: string;
  level?: string;
  context: string;
}

export function validateChildSlices(parentContext: string, specs: ChildSliceSpec[]): ValidationResult & { children: ValidatedChild[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  const children: ValidatedChild[] = [];
  let previousEnd = 0;

  specs.forEach((spec, index) => {
    if (!Number.isInteger(spec.startOffset) || !Number.isInteger(spec.endOffset)) errors.push(`${spec.title}: offsets must be integers`);
    if (spec.startOffset < 0 || spec.endOffset > parentContext.length || spec.startOffset >= spec.endOffset) errors.push(`${spec.title}: invalid offsets`);
    if (index > 0 && spec.startOffset < previousEnd) errors.push(`${spec.title}: child slices overlap or are out of order`);
    if (spec.startOffset > previousEnd && parentContext.slice(previousEnd, spec.startOffset).trim().length > 0) {
      warnings.push(`meaningful uncovered text before ${spec.title}`);
    }
    children.push({ ...spec, context: parentContext.slice(spec.startOffset, spec.endOffset) });
    previousEnd = Math.max(previousEnd, spec.endOffset);
  });

  if (previousEnd < parentContext.length && parentContext.slice(previousEnd).trim().length > 0) warnings.push('meaningful uncovered text after last child');
  return { valid: errors.length === 0, errors, warnings, children };
}

export function mergeValidation(results: ValidationResult[]): ValidationResult {
  const errors = results.flatMap((r) => r.errors);
  const warnings = results.flatMap((r) => r.warnings);
  return { valid: errors.length === 0 && results.every((r) => r.valid), errors, warnings };
}
