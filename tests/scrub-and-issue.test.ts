import { describe, expect, it } from 'vitest';

import { buildIssue, clean, fenced, titleFor } from '../src/server/issue.js';
import { REDACTED, scrubPersonalData } from '../src/server/scrub.js';

describe('scrubPersonalData', () => {
  it.each([
    ['mail me at jane.doe+app@example.co.uk please', 'mail me at [redacted] please'],
    ['call +44 7700 900123 now', 'call [redacted] now'],
    ['call (555) 123-4567', 'call [redacted]'],
    ['card 4111 1111 1111 1111 failed', 'card [redacted] failed'],
    ['order 123456789012', 'order [redacted]'],
    ['from 192.168.10.24.', 'from [redacted].'],
    ['ip 2001:db8:85a3::8a2e:370:7334 here', 'ip [redacted] here'],
  ])('redacts %s', (input, output) => {
    expect(scrubPersonalData(input)).toBe(output);
  });

  it.each([
    'since 2026-10-23 it crashes',
    'version 1.2.0 build 345',
    'at 12:30:45 the timer stopped',
    'I logged 2500 kcal',
    'not an ip 999.1.1.1',
  ])('keeps %s', (input) => {
    expect(scrubPersonalData(input)).toBe(input);
  });

  it('exports the marker', () => {
    expect(REDACTED).toBe('[redacted]');
  });
});

describe('issue formatting', () => {
  it('builds a title from the first non-empty line with a prefix', () => {
    expect(titleFor('bug', '\n\n  Crash on save  \nmore')).toBe('[Bug] Crash on save');
    expect(titleFor('idea', 'Dark mode')).toBe('[Idea] Dark mode');
  });

  it('trims a long title with an ellipsis', () => {
    const title = titleFor('bug', 'x'.repeat(200), 40);
    expect(title).toHaveLength(40);
    expect(title.endsWith(String.fromCodePoint(0x2026))).toBe(true);
  });

  it('defangs mentions in the title', () => {
    expect(titleFor('bug', 'hey @octocat')).not.toContain('@');
  });

  it('fences text so a backtick run cannot break out', () => {
    expect(fenced('a ```` b')).toMatch(/^`{5}text\n/);
    expect(fenced('plain')).toBe('```text\nplain\n```');
  });

  it('strips control, zero-width and bidi characters and normalises newlines', () => {
    const hidden = `a${String.fromCodePoint(0x202e)}b${String.fromCodePoint(0x200b)}c\u0007\r\nd`;
    expect(clean(hidden)).toBe('abc\nd');
  });

  it('builds the body, labels and context table without identifiers', () => {
    const issue = buildIssue(
      {
        type: 'bug',
        text: 'It broke. Email me: a@b.io <img src=x> [link](http://evil) @team',
        screen: 'Settings',
        context: {
          appVersion: '1.2.0',
          build: '45',
          os: 'iOS',
          osVersion: '18.1',
          locale: 'en-GB',
        },
      },
      { verifierName: 'apple-app-attest', extraLabels: ['from-app'] },
    );
    expect(issue.labels).toEqual(['feedback', 'bug', 'needs-triage', 'from-app']);
    expect(issue.body).toContain('```text\nIt broke. Email me: [redacted] <img src=x>');
    expect(issue.body).toContain('| Screen | `Settings` |');
    expect(issue.body).toContain('| Locale | `en-GB` |');
    expect(issue.body).toContain('| App proof | `apple-app-attest` |');
    expect(issue.title).toBe(
      `[Bug] It broke. Email me: [redacted] <img src=x> [link](http://evil) ${String.fromCodePoint(0xff20)}team`,
    );
  });

  it('omits absent context', () => {
    const issue = buildIssue({ type: 'idea', text: 'More charts' }, { verifierName: 'v' });
    expect(issue.body).not.toContain('Screen');
    expect(issue.labels).toEqual(['feedback', 'idea', 'needs-triage']);
  });
});
