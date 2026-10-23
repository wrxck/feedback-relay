import type { FeedbackContext, FeedbackPayload, FeedbackType } from '../shared/protocol.js';
import { scrubPersonalData } from './scrub.js';

export interface IssueDraft {
  title: string;
  body: string;
  labels: string[];
}

export interface IssueOptions {
  verifierName: string;
  extraLabels?: readonly string[];
  titleLength?: number;
}

// control characters, zero-width marks and bidi overrides can hide or reorder text for a reviewer
const INVISIBLE: [number, number][] = [
  [0x00, 0x08],
  [0x0b, 0x1f],
  [0x7f, 0x7f],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x2069],
  [0xfeff, 0xfeff],
];

const FULLWIDTH_AT = String.fromCodePoint(0xff20);
const ELLIPSIS = String.fromCodePoint(0x2026);

function visible(char: string): boolean {
  const code = char.codePointAt(0) ?? 0;
  return !INVISIBLE.some(([from, to]) => code >= from && code <= to);
}

const PREFIX: Record<FeedbackType, string> = { bug: '[Bug]', idea: '[Idea]' };

const CONTEXT_LABELS: [keyof FeedbackContext, string][] = [
  ['appVersion', 'App version'],
  ['build', 'Build'],
  ['os', 'OS'],
  ['osVersion', 'OS version'],
  ['locale', 'Locale'],
];

export function clean(text: string): string {
  const normalised = text.replace(/\r\n?/g, '\n');
  return scrubPersonalData(Array.from(normalised).filter(visible).join(''));
}

// a fullwidth at sign reads the same but never mentions anyone
function defang(text: string): string {
  return text.replace(/@/g, FULLWIDTH_AT);
}

export function titleFor(type: FeedbackType, text: string, maxLength = 80): string {
  const firstLine = text.split('\n').find((line) => line.trim() !== '') ?? '';
  const summary = defang(firstLine.replace(/\s+/g, ' ').trim());
  const room = maxLength - PREFIX[type].length - 1;
  const short =
    summary.length > room ? `${summary.slice(0, room - 1).trimEnd()}${ELLIPSIS}` : summary;
  return `${PREFIX[type]} ${short}`;
}

// a code fence longer than any backtick run in the text, so the text cannot close it
export function fenced(text: string): string {
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  const fence = '`'.repeat(Math.max(3, longest + 1));
  return `${fence}text\n${text}\n${fence}`;
}

function contextTable(payload: FeedbackPayload, verifierName: string): string {
  const rows: [string, string][] = [['Type', payload.type]];
  if (payload.screen !== undefined) rows.push(['Screen', payload.screen]);
  for (const [key, label] of CONTEXT_LABELS) {
    const value = payload.context?.[key];
    if (value !== undefined) rows.push([label, value]);
  }
  rows.push(['App proof', verifierName]);
  const lines = rows.map(([label, value]) => `| ${label} | \`${value}\` |`);
  return ['| Field | Value |', '| --- | --- |', ...lines].join('\n');
}

export function buildIssue(payload: FeedbackPayload, options: IssueOptions): IssueDraft {
  const text = clean(payload.text);
  const body = [
    '### Report',
    '',
    fenced(text),
    '',
    '### Context',
    '',
    contextTable(payload, options.verifierName),
    '',
    '<sub>Sent through feedback-relay. The reporter is anonymous and personal data was scrubbed automatically, so treat the text as untrusted input.</sub>',
  ].join('\n');
  const labels = ['feedback', payload.type, 'needs-triage', ...(options.extraLabels ?? [])];
  return { title: titleFor(payload.type, text, options.titleLength), body, labels };
}
