export interface EmailParserOptions {
  debug?: boolean;
  outputPath?: string | null;
  includeAttachmentContent?: boolean;
  maxAttachmentSize?: number;
}

export interface Recipient {
  name: string;
  email: string;
}

export interface Attachment {
  filename: string;
  contentType?: string;
  size?: number;
  type: string;
  disposition?: string;
  isStandard?: boolean;
  isLink?: boolean;
  isEmbedded?: boolean;
  isLikelyIcon?: boolean;
  url?: string;
  iconUrl?: string;
  contentId?: string | null;
  iconAttachmentIndex?: number;
  isIconFor?: number[];
  exceededSizeLimit?: boolean;
  content?: string;
  partId?: string;
}

export interface SubjectInfo {
  raw: string;
  clean: string;
  hasReply: boolean;
  hasForward: boolean;
  prefixes: string[];
}

export interface EmailData {
  id: string;
  threadId?: string;
  from: Recipient;
  to: Recipient[];
  cc?: Recipient[];
  bcc?: Recipient[];
  replyTo?: Recipient[];
  subject: string;
  subjectInfo?: SubjectInfo;
  date: Date;
  body: string;
  bodyHtml?: string;
  hasAttachments: boolean;
  attachments: Attachment[];
  headers?: Record<string, any>;
  snippet?: string;
  html?: string;
  error?: string;
}

export interface BodyContent {
  text: string;
  html: string;
}

export interface GmailPart {
  mimeType?: string;
  filename?: string;
  body?: {
    data?: string;
    size?: number;
  };
  parts?: GmailPart[];
  partId?: string;
}

export interface GmailApiMessage {
  id?: string;
  threadId?: string;
  subject?: string;
  payload?: {
    headers?: {
      name: string;
      value: string;
    }[];
    body?: {
      data?: string;
    };
    parts?: GmailPart[];
    filename?: string;
  };
  raw?: string;
  snippet?: string;
  internalDate?: string;
}

export interface ParsedEmail {
  messageId?: string;
  from?: any;
  to?: any;
  cc?: any;
  bcc?: any;
  replyTo?: any;
  subject?: string;
  date?: Date;
  references?: string[];
  inReplyTo?: string;
  html?: string;
  text?: string;
  textAsHtml?: string;
  headers?: any;
  attachments?: any[];
} 