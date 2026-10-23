import { isIPv4, isIPv6 } from 'node:net';

export const REDACTED = '[redacted]';

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g;
const IP_CANDIDATE = /(?<![\w:.])[0-9A-Fa-f:.]{7,45}(?![\w:])/g;
const DIGIT_RUN = /\+?\(?\d[\d\s().-]{5,}\d/g;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const MIN_DIGITS = 7;

function scrubIps(text: string): string {
  return text.replace(IP_CANDIDATE, (match) => {
    const candidate = match.replace(/\.$/, '');
    if (!isIPv4(candidate) && !isIPv6(candidate)) return match;
    return REDACTED + match.slice(candidate.length);
  });
}

// seven or more digits covers phone numbers, card numbers and account or order numbers
function scrubDigitRuns(text: string): string {
  return text.replace(DIGIT_RUN, (match) => {
    const trimmed = match.trim();
    if (ISO_DATE.test(trimmed)) return match;
    const digits = trimmed.replace(/\D/g, '').length;
    return digits >= MIN_DIGITS ? REDACTED : match;
  });
}

// best effort, not a guarantee: it removes the common shapes of personal data before github sees it
export function scrubPersonalData(text: string): string {
  return scrubDigitRuns(scrubIps(text.replace(EMAIL, REDACTED)));
}
