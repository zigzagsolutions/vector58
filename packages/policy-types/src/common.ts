import { z } from 'zod';

export const UuidSchema = z.uuid();
export const IsoDateTimeSchema = z.iso.datetime({ offset: true });
export const SlugSchema = z
  .string()
  .min(2)
  .max(48)
  .regex(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/, 'Lowercase letters, digits and hyphens only');

export const BrowserSchema = z.enum(['chrome', 'edge']);
export type Browser = z.infer<typeof BrowserSchema>;

export const ThreatCategorySchema = z.enum([
  'phishing',
  'malware',
  'command-and-control',
  'credential-theft',
  'fraud',
  'malicious-download',
  'custom',
]);
export type ThreatCategory = z.infer<typeof ThreatCategorySchema>;

export const IndicatorTypeSchema = z.enum(['domain', 'exact_url']);
export type IndicatorType = z.infer<typeof IndicatorTypeSchema>;

export const SeveritySchema = z.enum(['low', 'medium', 'high', 'critical']);
export type Severity = z.infer<typeof SeveritySchema>;
