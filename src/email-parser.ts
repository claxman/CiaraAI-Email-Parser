/**
 * Universal Email Parser
 * Handles virtually ANY email format including:
 * - Standard RFC 822/MIME format
 * - Gmail API format (raw & payload styles)
 * - Microsoft Exchange/Outlook formats
 * - Plain text email exports
 * - MBOX archives
 * - Encoded email content
 * - Already parsed JSON
 */

import * as fs from 'fs';
import * as path from 'path';
// @ts-ignore - To ignore type issues with mailparser
import { simpleParser } from 'mailparser';
import * as cheerio from 'cheerio';
import * as iconv from 'iconv-lite'; // Optional for character encoding

import {
  EmailParserOptions,
  EmailData,
  BodyContent,
  GmailApiMessage,
  ParsedEmail,
  Attachment,
  Recipient,
  SubjectInfo
} from './types';

/**
 * Main function to handle any email format
 * @param input - File path, raw content, or parsed object
 * @param options - Processing options
 * @returns Parsed email data
 */
async function parseAnyEmail(
  input: string | Buffer | object,
  options: EmailParserOptions = {}
): Promise<EmailData> {
  const opts: EmailParserOptions = {
    debug: false,
    outputPath: null,
    includeAttachmentContent: false,
    maxAttachmentSize: 10 * 1024 * 1024, // 10MB
    ...options
  };
  
  const log = (...args: any[]): void => {
    if (opts.debug) console.log(...args);
  };
  
  log('Starting email parsing...');
  
  try {
    // STEP 1: Handle different input types
    let rawContent: any;
    let inputType = 'unknown';
    
    if (typeof input === 'string') {
      // Check if it's a file path
      if (fs.existsSync(input) && fs.statSync(input).isFile()) {
        log(`Reading file: ${input}`);
        rawContent = fs.readFileSync(input);
        const ext = path.extname(input).toLowerCase();
        
        // Set input type based on file extension
        if (ext === '.eml') inputType = 'eml';
        else if (ext === '.msg') inputType = 'msg';
        else if (ext === '.mbox') inputType = 'mbox';
        else if (ext === '.json') inputType = 'json';
        else inputType = 'raw';
        
        log(`Detected file type: ${inputType}`);

        // If it's a JSON file, try to parse it
        if (inputType === 'json') {
          try {
            const content = rawContent.toString();
            rawContent = JSON.parse(content);
            log('Successfully parsed JSON file');
          } catch (e) {
            log('Error parsing JSON file:', (e as Error).message);
            // Continue with raw content
          }
        }
      } else {
        // It's a string containing email content
        rawContent = input;
        inputType = input.startsWith('{') ? 'json' : 'raw';
        log(`Input appears to be raw ${inputType} content`);

        // Try to parse JSON string
        if (inputType === 'json') {
          try {
            rawContent = JSON.parse(input);
            log('Successfully parsed JSON string');
          } catch (e) {
            log('Error parsing JSON string:', (e as Error).message);
            // Continue with raw content
          }
        }
      }
    } else if (Buffer.isBuffer(input)) {
      // It's already a buffer
      rawContent = input;
      inputType = 'buffer';
      log('Input is a buffer');

      // Try to parse the buffer as JSON
      try {
        const content = rawContent.toString();
        if (content.trim().startsWith('{')) {
          const jsonData = JSON.parse(content);
          rawContent = jsonData;
          inputType = 'json';
          log('Successfully parsed buffer as JSON');
        }
      } catch (e) {
        log('Error parsing buffer as JSON:', (e as Error).message);
        // Continue with buffer content
      }
    } else if (input && typeof input === 'object') {
      // It's already an object, possibly a parsed email
      log('Input is already an object, checking format...');
      
      // Check if it looks like an already parsed email
      if (hasEmailFields(input)) {
        log('Input appears to be an already parsed email object');
        return normalizeEmailObject(input, opts);
      }
      
      // Otherwise, keep it as a JSON object
      rawContent = input;
      inputType = 'json';
    } else {
      throw new Error('Invalid input type. Expected string, buffer, or object.');
    }
    
    // STEP 2: Special format detection & handling
    let emailData: EmailData | undefined;
    
    // Handle JSON format (Gmail API, etc.)
    if (inputType === 'json' || (typeof rawContent === 'object' && rawContent !== null)) {
      log('Processing as JSON...');
      
      const jsonData = rawContent as any;

      // Debug log the JSON structure
      if (opts.debug) {
        log('JSON structure keys:', Object.keys(jsonData));
      }
      
      // Check for Gmail API 'raw' format
      if (jsonData.raw) {
        log('Found Gmail API raw format');
        try {
          // Decode the Base64 encoded raw email
          const decoded = Buffer.from(jsonData.raw, 'base64').toString();
          emailData = await parseStandardEmail(decoded, opts);
        } catch (e) {
          log('Error decoding Gmail API raw format:', (e as Error).message);
        }
      } 
      // Check for Gmail API message format with payload
      else if (jsonData.payload && jsonData.id) {
        log('Found Gmail API message format with payload');
        emailData = parseGmailApiMessage(jsonData, opts);
      }
      // Check for Gmail snippet without raw (need to construct minimal data)
      else if (jsonData.snippet && jsonData.id) {
        log('Found Gmail API message with snippet but no raw content');
        // Create minimal email data
        emailData = {
          id: jsonData.id,
          threadId: jsonData.threadId || `thread-${Date.now()}`,
          from: { name: '', email: '' },
          to: [],
          cc: [],
          bcc: [],
          subject: jsonData.subject || '(No Subject)',
          date: jsonData.internalDate ? new Date(parseInt(jsonData.internalDate)) : new Date(),
          body: jsonData.snippet || '',
          hasAttachments: false,
          attachments: [],
          headers: {},
          snippet: jsonData.snippet || ''
        };
      }
      // Check if it's already a parsed email object
      else if (hasEmailFields(jsonData)) {
        log('JSON contains already parsed email data');
        emailData = normalizeEmailObject(jsonData, opts);
      }
    }
    
    // If we haven't successfully parsed yet, try specialized formats
    if (!emailData) {
      // MSG format detection and parsing (if content looks like an MSG file)
      if (inputType === 'msg' || hasMsgSignature(rawContent)) {
        log('Attempting to parse as MSG format...');
        try {
          emailData = await parseMsgFormat(rawContent, opts);
        } catch (e) {
          log('MSG parsing failed, falling back to standard parser:', (e as Error).message);
        }
      }
      
      // MBOX format detection (if content has mbox markers)
      if (!emailData && (inputType === 'mbox' || hasMboxSignature(rawContent))) {
        log('Attempting to parse as MBOX format...');
        try {
          // For MBOX, we'll just extract the first email
          const firstEmail = extractFirstEmailFromMbox(rawContent);
          if (firstEmail) {
            emailData = await parseStandardEmail(firstEmail, opts);
          }
        } catch (e) {
          log('MBOX parsing failed, falling back to standard parser:', (e as Error).message);
        }
      }
      
      // If still not parsed, try as standard email
      if (!emailData) {
        log('Attempting standard email parsing...');
        emailData = await parseStandardEmail(rawContent, opts);
      }
    }
    
    // Save output if path provided
    if (emailData && opts.outputPath) {
      log(`Saving parsed email to ${opts.outputPath}`);
      fs.writeFileSync(opts.outputPath, JSON.stringify(emailData, null, 2));
    }
    
    return emailData;
  } catch (error) {
    console.error('Error parsing email:', error);
    
    // Create minimal fallback object for graceful failure
    return {
      error: (error as Error).message,
      id: `error-${Date.now()}`,
      subject: 'Error parsing email',
      from: { name: '', email: '' },
      to: [],
      date: new Date(),
      body: 'Failed to parse this email. The format may be unsupported.',
      hasAttachments: false,
      attachments: []
    };
  }
}

/**
 * Parse standard email formats using mailparser
 */
async function parseStandardEmail(content: string | Buffer, opts: EmailParserOptions): Promise<EmailData> {
  const log = (...args: any[]): void => {
    if (opts.debug) console.log(...args);
  };

  try {
    // Check if content looks like a Gmail API message with raw property
    if (typeof content === 'string' && content.trim().startsWith('{') && content.includes('"raw":')) {
      log('Content appears to be a Gmail API JSON with raw property, extracting...');
      try {
        const jsonObj = JSON.parse(content);
        if (jsonObj.raw) {
          log('Successfully extracted raw property, decoding Base64...');
          content = Buffer.from(jsonObj.raw, 'base64').toString();
          log('Successfully decoded Base64 content');
        }
      } catch (e) {
        log('Failed to parse JSON or decode Base64:', (e as Error).message);
      }
    }

    // Detect if content might be Base64 encoded
    if (typeof content === 'string' && looksLikeBase64(content)) {
      try {
        log('Content appears to be Base64 encoded, attempting to decode...');
        content = Buffer.from(content, 'base64').toString();
      } catch (e) {
        log('Base64 decoding failed, continuing with original content');
      }
    }
    
    // Detect and handle character encoding issues
    let processedContent: string | Buffer = content;
    if (Buffer.isBuffer(content)) {
      // Try to detect encoding
      const encoding = detectEncoding(content);
      if (encoding && encoding !== 'utf8' && encoding !== 'utf-8') {
        try {
          log(`Detected non-UTF8 encoding: ${encoding}, converting...`);
          if (iconv) {
            processedContent = iconv.decode(content, encoding);
          }
        } catch (e) {
          log('Encoding conversion failed, continuing with original content');
        }
      }
    }
    
    // Parse the email
    log('Parsing with mailparser...');
    const parseOptions = {
      skipHtmlToText: true, // We'll do our own HTML parsing
      skipTextToHtml: true
    };
    
    const parsed = await simpleParser(processedContent, parseOptions);
    log('Mailparser completed successfully');
    
    // Log the raw parsed object for debugging
    if (opts.debug) {
      log('Raw mailparser output:');
      log(JSON.stringify(parsed, null, 2));
    }

    // Extract attachments
    const attachments = extractAttachments(parsed, opts);
    const hasAttachments = attachments.length > 0;

    // Extract body content with both text and HTML versions
    const bodyContent = extractBody(parsed);
    
    // Extract key data from parsed email
    const emailData: EmailData = {
      id: parsed.messageId || `email-${Date.now()}`,
      from: extractSender(parsed.from),
      to: extractRecipients(parsed.to),
      cc: extractRecipients(parsed.cc),
      bcc: extractRecipients(parsed.bcc),
      replyTo: extractRecipients(parsed.replyTo),
      subject: parsed.subject || '(No Subject)',
      subjectInfo: extractSubjectInfo(parsed.subject),
      date: parsed.date || new Date(),
      body: bodyContent.text,
      bodyHtml: bodyContent.html,  // Add sanitized HTML version
      hasAttachments: hasAttachments,
      attachments: attachments,
      headers: extractImportantHeaders(parsed.headers),
      threadId: extractThreadId(parsed),
      html: parsed.html  // Keep original HTML for reference
    };
    
    // Extract snippet from body
    emailData.snippet = createSnippet(emailData.body, 100);
    
    // Debug attachments
    if (opts.debug) {
      log(`Found ${emailData.attachments.length} attachments:`);
      emailData.attachments.forEach((att, idx) => {
        log(`  ${idx+1}. ${att.filename}, type: ${att.contentType}, size: ${att.size}`);
      });
    }
    
    return emailData;
  } catch (error) {
    console.error('Error in parseStandardEmail:', error);
    throw error; // Rethrow to be caught in the main function
  }
}

/**
 * Parse Gmail API message format (with payload)
 */
function parseGmailApiMessage(jsonData: GmailApiMessage, opts: EmailParserOptions): EmailData {
  const log = (...args: any[]): void => {
    if (opts.debug) console.log(...args);
  };
  
  log('Parsing Gmail API message format...');
  
  // Extract headers
  const headers: Record<string, any> = {};
  if (jsonData.payload && jsonData.payload.headers) {
    jsonData.payload.headers.forEach(h => {
      headers[h.name.toLowerCase()] = h.value;
    });
  }
  
  // Extract body content
  let bodyText = '';
  let bodyHtml = '';
  
  if (jsonData.snippet) {
    bodyText = jsonData.snippet;
  }
  
  if (jsonData.payload) {
    if (jsonData.payload.body && jsonData.payload.body.data) {
      try {
        const decodedBody = Buffer.from(jsonData.payload.body.data, 'base64').toString();
        bodyText = decodedBody || bodyText;
        
        // If it looks like HTML, use it for HTML body
        if (decodedBody && decodedBody.trim().startsWith('<')) {
          bodyHtml = sanitizeHtml(decodedBody);
        }
      } catch (e) {
        log('Failed to decode payload body:', (e as Error).message);
      }
    }
    
    // Try to extract from parts if available
    if (jsonData.payload.parts) {
      const extractedContent = extractBodyFromParts(jsonData.payload.parts);
      if (extractedContent.text) {
        bodyText = extractedContent.text || bodyText;
      }
      if (extractedContent.html) {
        bodyHtml = sanitizeHtml(extractedContent.html);
      }
    }
  }
  
  // Create the email data object
  const emailData: EmailData = {
    id: jsonData.id || `gmail-${Date.now()}`,
    threadId: jsonData.threadId,
    from: {
      name: extractNameFromHeader(headers.from),
      email: extractEmailFromHeader(headers.from)
    },
    to: parseRecipientsFromHeader(headers.to),
    cc: parseRecipientsFromHeader(headers.cc),
    bcc: parseRecipientsFromHeader(headers.bcc),
    subject: headers.subject || '(No Subject)',
    date: headers.date ? new Date(headers.date) : new Date(),
    body: bodyText,
    bodyHtml: bodyHtml,
    hasAttachments: hasAttachmentsInPayload(jsonData.payload),
    attachments: extractGmailAttachments(jsonData.payload, opts),
    headers: headers,
    snippet: jsonData.snippet || createSnippet(bodyText, 100),
    html: bodyHtml // Store the original HTML
  };
  
  return emailData;
}

/**
 * Parse MSG format using external library or fallback
 */
async function parseMsgFormat(content: string | Buffer, opts: EmailParserOptions): Promise<EmailData> {
  const log = (...args: any[]): void => {
    if (opts.debug) console.log(...args);
  };
  
  log('Parsing MSG format...');
  
  // Try to use msg-parser if available
  try {
    const msgParser = require('msg-parser');
    
    // For file path input
    if (typeof content === 'string' && fs.existsSync(content)) {
      return new Promise<EmailData>((resolve, reject) => {
        msgParser.parseFile(content, (err: Error, parsed: any) => {
          if (err) {
            log('MSG parsing error:', err);
            reject(err);
            return;
          }
          
          // Convert to our standard format
          const emailData: EmailData = {
            id: `msg-${Date.now()}`,
            from: {
              name: parsed.from_name || '',
              email: parsed.from_email || ''
            },
            to: parsed.to.map((r: any) => ({ name: r.name || '', email: r.email || '' })),
            cc: (parsed.cc || []).map((r: any) => ({ name: r.name || '', email: r.email || '' })),
            subject: parsed.subject || '(No Subject)',
            date: parsed.date || new Date(),
            body: parsed.body || '',
            hasAttachments: parsed.attachments && parsed.attachments.length > 0,
            attachments: (parsed.attachments || []).map((att: any) => ({
              filename: att.fileName || 'attachment',
              contentType: att.contentType,
              size: att.content ? att.content.length : 0,
              type: determineFileType(att.fileName, att.contentType),
              isStandard: true,
              content: opts.includeAttachmentContent ? att.content : undefined
            })),
            headers: {},
            snippet: createSnippet(parsed.body || '', 100)
          };
          
          resolve(emailData);
        });
      });
    }
    
    // If we have buffer content
    if (Buffer.isBuffer(content)) {
      return new Promise<EmailData>((resolve, reject) => {
        msgParser.parseBuffer(content, (err: Error, parsed: any) => {
          if (err) {
            log('MSG buffer parsing error:', err);
            reject(err);
            return;
          }
          
          // Convert to our standard format (same as above)
          const emailData: EmailData = {
            id: `msg-${Date.now()}`,
            from: {
              name: parsed.from_name || '',
              email: parsed.from_email || ''
            },
            to: parsed.to.map((r: any) => ({ name: r.name || '', email: r.email || '' })),
            cc: (parsed.cc || []).map((r: any) => ({ name: r.name || '', email: r.email || '' })),
            subject: parsed.subject || '(No Subject)',
            date: parsed.date,
            body: parsed.body || '',
            hasAttachments: parsed.attachments && parsed.attachments.length > 0,
            attachments: (parsed.attachments || []).map((att: any) => ({
              filename: att.fileName || 'attachment',
              contentType: att.contentType,
              size: att.content ? att.content.length : 0,
              type: determineFileType(att.fileName, att.contentType),
              isStandard: true,
              content: opts.includeAttachmentContent ? att.content : undefined
            })),
            headers: {},
            snippet: createSnippet(parsed.body || '', 100)
          };
          
          resolve(emailData);
        });
      });
    }
  } catch (e) {
    // msg-parser not available or failed
    log('MSG parser not available:', (e as Error).message);
    
    // Fallback to standard parser as last resort
    return parseStandardEmail(content, opts);
  }
  
  // Fallback to standard parser if nothing else worked
  return parseStandardEmail(content, opts);
}

/**
 * Extract the first email from an MBOX file
 */
function extractFirstEmailFromMbox(content: string | Buffer): string | null {
  // Convert buffer to string if needed
  const str = Buffer.isBuffer(content) ? content.toString() : content;
  
  // Look for the "From " marker that starts each message
  const fromMarker = /^From [^\s]+ /m;
  const match = str.match(fromMarker);
  
  if (!match) {
    console.log('No MBOX format markers found');
    return null;
  }
  
  // Find the start of the next message (if any)
  const startPos = match.index!;
  const nextMatch = str.slice(startPos + 1).match(fromMarker);
  
  if (nextMatch) {
    // Extract just the first email
    return str.slice(startPos, startPos + 1 + nextMatch.index!);
  } else {
    // Only one email in the file
    return str.slice(startPos);
  }
}

/**
 * Check if content looks like Base64
 */
function looksLikeBase64(str: string): boolean {
  // Base64 strings are typically long and contain only these characters
  if (str.length < 50) return false;
  
  // A quick check if string contains only valid base64 characters
  return /^[A-Za-z0-9+/=]+$/.test(str.replace(/\s/g, ''));
}

/**
 * Detect character encoding from buffer
 */
function detectEncoding(buffer: Buffer): string {
  // Simple encoding detection - check for common encoding signatures
  if (buffer.length > 3) {
    // UTF-8 BOM
    if (buffer[0] === 0xEF && buffer[1] === 0xBB && buffer[2] === 0xBF) {
      return 'utf8';
    }
    // UTF-16 LE BOM
    if (buffer[0] === 0xFF && buffer[1] === 0xFE) {
      return 'utf16le';
    }
    // UTF-16 BE BOM
    if (buffer[0] === 0xFE && buffer[1] === 0xFF) {
      return 'utf16be';
    }
  }
  
  // Default to utf8 if no BOM detected
  return 'utf8';
}

/**
 * Check if content has MSG file signature
 */
function hasMsgSignature(content: any): boolean {
  // MSG files start with the signature D0 CF 11 E0
  if (Buffer.isBuffer(content) && content.length > 4) {
    return content[0] === 0xD0 && 
           content[1] === 0xCF && 
           content[2] === 0x11 && 
           content[3] === 0xE0;
  }
  return false;
}

/**
 * Check if content has MBOX signature
 */
function hasMboxSignature(content: string | Buffer): boolean {
  // MBOX files typically start with "From " followed by an email address
  if (typeof content === 'string') {
    return content.trimStart().startsWith('From ');
  }
  if (Buffer.isBuffer(content)) {
    const str = content.slice(0, 100).toString();
    return str.trimStart().startsWith('From ');
  }
  return false;
}

/**
 * Check if an object looks like an already parsed email
 */
function hasEmailFields(obj: any): boolean {
  // Check for common email fields
  return obj && 
         (obj.subject !== undefined || obj.from !== undefined) &&
         (obj.body !== undefined || obj.html !== undefined || obj.text !== undefined);
}

/**
 * Normalize an already parsed email object to our format
 */
function normalizeEmailObject(obj: any, opts: EmailParserOptions): EmailData {
  // Set up normalized object with our expected fields
  const normalized: EmailData = {
    id: obj.id || obj.messageId || `email-${Date.now()}`,
    from: obj.from,
    to: obj.to || [],
    cc: obj.cc || [],
    bcc: obj.bcc || [],
    subject: obj.subject || '(No Subject)',
    date: obj.date instanceof Date ? obj.date : new Date(obj.date || Date.now()),
    body: obj.body || obj.text || '',
    hasAttachments: !!(obj.attachments && obj.attachments.length > 0),
    attachments: obj.attachments || [],
    threadId: obj.threadId || `thread-${Date.now()}`,
    snippet: obj.snippet || createSnippet(obj.body || obj.text || '', 100)
  };
  
  // Normalize from field if needed
  if (typeof normalized.from === 'string') {
    normalized.from = {
      name: extractNameFromHeader(normalized.from),
      email: extractEmailFromHeader(normalized.from)
    };
  } else if (!normalized.from) {
    normalized.from = { name: '', email: '' };
  }
  
  // Normalize to/cc/bcc fields if needed
  ['to', 'cc', 'bcc'].forEach(field => {
    if (typeof normalized[field as keyof EmailData] === 'string') {
      (normalized as any)[field] = parseRecipientsFromHeader(normalized[field as keyof EmailData] as string);
    } else if (!Array.isArray(normalized[field as keyof EmailData])) {
      (normalized as any)[field] = [];
    }
  });
  
  return normalized;
}

/**
 * Extract body content from Gmail API parts
 */
function extractBodyFromParts(parts: any[]): BodyContent {
  if (!parts || !Array.isArray(parts)) return { text: '', html: '' };
  
  let textPart = '';
  let htmlPart = '';
  
  // First look for text parts
  for (const part of parts) {
    if (part.mimeType === 'text/plain' && part.body && part.body.data) {
      try {
        textPart = Buffer.from(part.body.data, 'base64').toString();
      } catch (e) {
        console.log('Error decoding text part:', (e as Error).message);
      }
    } else if (part.mimeType === 'text/html' && part.body && part.body.data) {
      try {
        htmlPart = Buffer.from(part.body.data, 'base64').toString();
      } catch (e) {
        console.log('Error decoding HTML part:', (e as Error).message);
      }
    }
    
    // Recursively check nested parts
    if (part.parts && part.parts.length) {
      const nestedContent = extractBodyFromParts(part.parts);
      if (nestedContent.text) {
        textPart = textPart || nestedContent.text;
      }
      if (nestedContent.html) {
        htmlPart = htmlPart || nestedContent.html;
      }
    }
  }
  
  // Generate text from HTML if we only have HTML
  if (!textPart && htmlPart) {
    textPart = extractTextFromHtml(htmlPart);
  }
  
  return { 
    text: textPart,
    html: htmlPart
  };
}

/**
 * Extract the sender information
 */
function extractSender(from: any): Recipient {
  if (!from) {
    return { name: '', email: '' };
  }
  
  let name = '';
  let email = '';
  
  if (from.value && from.value.length > 0) {
    name = from.value[0].name || '';
    email = from.value[0].address || '';
  } else if (from.text) {
    // Try to extract from text format
    const match = from.text.match(/([^<]+)<([^>]+)>/);
    if (match) {
      name = match[1].trim();
      email = match[2].trim();
    } else {
      email = from.text.trim();
    }
  } else if (typeof from === 'string') {
    // Try to extract email from string format
    const matches = from.match(/<([^>]+)>/);
    if (matches && matches[1]) {
      email = matches[1];
      // Try to get name part
      name = from.replace(/<[^>]+>/, '').trim();
    } else {
      email = from.trim();
    }
  } else if (from.name || from.address) {
    name = from.name || '';
    email = from.address || '';
  }
  
  return { name, email };
}

/**
 * Extract recipients information
 */
function extractRecipients(recipients: any): Recipient[] {
  if (!recipients) {
    return [];
  }
  
  if (recipients.value && Array.isArray(recipients.value)) {
    return recipients.value.map((r: any) => ({
      name: r.name || '',
      email: r.address || ''
    }));
  }
  
  if (recipients.text) {
    // Split by commas if multiple recipients
    return recipients.text.split(',').map((addr: string) => {
      addr = addr.trim();
      const matches = addr.match(/([^<]+)<([^>]+)>/);
      if (matches) {
        return {
          name: matches[1].trim(),
          email: matches[2].trim()
        };
      }
      return { name: '', email: addr };
    });
  }
  
  if (typeof recipients === 'string') {
    // Try to parse comma-separated string
    return recipients.split(',').map((addr: string) => {
      addr = addr.trim();
      const matches = addr.match(/<([^>]+)>/);
      if (matches && matches[1]) {
        return {
          name: addr.replace(/<[^>]+>/, '').trim(),
          email: matches[1]
        };
      }
      return { name: '', email: addr };
    });
  }
  
  return [];
}

/**
 * Extract the email body, with special handling for HTML content
 */
function extractBody(parsedEmail: ParsedEmail): BodyContent {
  let bodyText = '';
  let bodyHtml = '';
  
  // If we have HTML content, use that as our primary source
  if (parsedEmail.html) {
    // Store sanitized HTML for formatted display
    bodyHtml = sanitizeHtml(parsedEmail.html);
    
    // Extract plain text for searching, snippets, etc.
    bodyText = extractTextFromHtml(parsedEmail.html);
  }
  
  // Fallback to plain text if HTML extraction failed or returned empty
  if (!bodyText && parsedEmail.text) {
    bodyText = parsedEmail.text;
    
    // Create basic HTML from plain text for consistent API
    if (!bodyHtml) {
      bodyHtml = parsedEmail.text.replace(/\n/g, '<br>');
    }
  }
  
  // If we still don't have a body, check textAsHtml
  if (!bodyText && parsedEmail.textAsHtml) {
    bodyText = extractTextFromHtml(parsedEmail.textAsHtml);
    if (!bodyHtml) {
      bodyHtml = parsedEmail.textAsHtml;
    }
  }
  
  // Clean up the text
  return {
    text: cleanBodyText(bodyText),
    html: bodyHtml
  };
}

/**
 * Sanitize HTML to make it safe for display while preserving formatting
 */
function sanitizeHtml(html: string): string {
  if (!html) return '';
  
  try {
    const $ = cheerio.load(html, {
      decodeEntities: true,
      xmlMode: false
    });
    
    // Remove potentially dangerous elements and attributes
    $('script, iframe, object, embed, form, input, button, style').remove();
    
    // Remove on* event handlers from all elements
    $('*').each(function(this: cheerio.Element) {
      const el = $(this);
      const attrs = el.get(0)?.attribs;
      if (!attrs) return;
      
      Object.keys(attrs).forEach(attr => {
        // Remove event handlers
        if (attr.startsWith('on')) {
          el.removeAttr(attr);
        }
        
        // Remove javascript: URLs
        if ((attr === 'href' || attr === 'src') && attrs[attr].toLowerCase().startsWith('javascript:')) {
          el.removeAttr(attr);
        }
      });
    });
    
    // Optional: Add target="_blank" to links for safety
    $('a').attr('target', '_blank');
    $('a').attr('rel', 'noopener noreferrer');
    
    // Remove classes and IDs that might conflict with your application's CSS
    // Uncomment if needed:
    // $('*').removeAttr('class').removeAttr('id');
    
    // Add a wrapper class to help with styling in the application
    $('body').addClass('email-content-wrapper');
    
    // Return the sanitized HTML
    return $.html('body').replace(/<\/?body[^>]*>/g, '');
  } catch (e) {
    console.error('Error sanitizing HTML:', e);
    return html; // Return original if sanitization fails
  }
}

/**
 * Extract text content from HTML
 */
function extractTextFromHtml(html: string): string {
  try {
    const $ = cheerio.load(html, {
      decodeEntities: true,
      xmlMode: false
    });
    
    // Remove known clutter elements
    $('style, script, meta, link, head').remove();
    
    // Remove hidden elements
    $('[style*="display: none"], [style*="display:none"]').remove();
    
    // Remove email signature separators and quoted content
    $('div.gmail_quote, blockquote.gmail_quote').remove();
    $('.gmail_signature, .signature').remove();
    
    // Remove common footer dividers (without using position)
    $('hr, .divider').each(function(this: cheerio.Element) {
      // Instead of using position, check if this is near the bottom by seeing if there's
      // a limited amount of content after this element
      const elementsAfter = $(this).nextAll().length;
      if (elementsAfter < 10) {
        $(this).nextAll().remove();
        $(this).remove();
      }
    });
    
    // Process links to preserve important information
    $('a').each(function(this: cheerio.Element) {
      const href = $(this).attr('href');
      const text = $(this).text().trim();
      
      // Handle file attachments specially
      const hasFileIcon = $(this).find('img[src*="file-icon"]').length > 0;
      
      if (hasFileIcon) {
        // Just keep the filename text
        $(this).replaceWith(text);
      } else if (!text || text === href) {
        // If the link text is empty or the URL, just use the URL
        $(this).replaceWith(href || '');
      }
      // Otherwise keep the link text as is
    });
    
    // Get the text content with proper line breaks
    let text = '';
    
    // Start by processing headings - they should stand out
    $('h1, h2, h3, h4, h5, h6').each(function(this: cheerio.Element) {
      const content = $(this).text().trim();
      if (content) {
        text += content + '\n\n';
      }
    });
    
    // Process paragraphs and divs that look like paragraphs
    $('p, div:not(:has(div))').each(function(this: cheerio.Element) {
      // Skip if this is nested within something we already processed
      if ($(this).parents('p, h1, h2, h3, h4, h5, h6').length) {
        return;
      }
      
      const content = $(this).text().trim();
      if (content) {
        text += content + '\n\n';
      }
    });
    
    // Process lists with proper formatting
    $('ul, ol').each(function(this: cheerio.Element) {
      $(this).find('li').each(function(this: cheerio.Element, i: number) {
        const content = $(this).text().trim();
        if (content) {
          // For ordered lists, use numbers, for unordered use bullets
          const prefix = $(this).parent().is('ol') ? `${i+1}. ` : '• ';
          text += prefix + content + '\n';
        }
      });
      text += '\n';
    });
    
    // Process table data
    $('table').each(function(this: cheerio.Element) {
      $(this).find('tr').each(function(this: cheerio.Element) {
        const rowContent: string[] = [];
        $(this).find('td, th').each(function(this: cheerio.Element) {
          rowContent.push($(this).text().trim());
        });
        if (rowContent.length) {
          text += rowContent.join(' | ') + '\n';
        }
      });
      text += '\n';
    });
    
    // If no structured content found, get all body text
    if (!text.trim()) {
      text = $('body').text();
    }
    
    return text.trim();
  } catch (e) {
    console.error('Error extracting text from HTML:', e);
    // Return the text as fallback if HTML parsing fails
    return html.toString().replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  }
}

/**
 * Clean up the body text
 */
function cleanBodyText(text: string): string {
  if (!text) return '';
  
  // Remove email client quoted text markers
  text = text.replace(/^>+ ?/gm, '');
  
  // Remove common email signature markers
  text = text.replace(/^--\s*$/m, '');  // -- signature separator
  
  // Remove common reply headers like "On Tue, Jan 5, 2021 at 10:15 AM, John Doe wrote:"
  text = text.replace(/On .* wrote:$/gm, '');
  
  // Remove angle brackets with URLs
  text = text.replace(/<https?:\/\/[^>]+>/g, '');
  
  // Remove blocks of whitespace (more than 2 consecutive newlines)
  text = text.replace(/\n{3,}/g, '\n\n');
  
  // Remove common footer elements
  const footerPatterns = [
    /^Sent from my iPhone$/m,
    /^Sent from my Android$/m,
    /^Get Outlook for iOS$/m,
    /^Get Outlook for Android$/m
  ];
  
  footerPatterns.forEach(pattern => {
    const match = text.match(pattern);
    if (match && match.index) {
      // If found near the end, truncate the text
      if (match.index > text.length - 100) {
        text = text.substring(0, match.index).trim();
      }
    }
  });
  
  // Normalize line breaks
  text = text.replace(/\r\n/g, '\n');
  
  return text.trim();
}

/**
 * Extract email attachments with special handling for linked attachments
 */
function extractAttachments(parsedEmail: ParsedEmail, opts: EmailParserOptions): Attachment[] {
  const log = (...args: any[]): void => {
    if (opts && opts.debug) console.log(...args);
  };
  
  const attachments: Attachment[] = [];
  const seenUrls = new Set<string>();
  const iconUrls = new Map<string, number[]>(); // Map to track icon URLs and their corresponding attachment indices
  
  // Define patterns to identify icon-like attachments
  const iconPatterns = [
    /_\d+x\d+\.\w+$/i,  // Matches patterns like _16x16.png
    /\d+x\d+\.\w+$/i,   // Matches patterns like 16x16.png
    /icon[_-]?\d*\.\w+$/i, // Matches icon.png, icon_16.png, etc.
    /^file-icon/i,
    /assets\/mail\/file-icon\//i,
    /\/assets\/.*icon/i
  ];

  // Function to determine if an attachment is likely just an icon
  function isLikelyIcon(filename?: string, size?: number, contentType?: string, url?: string): boolean {
    // If the URL contains paths that are known to host icons
    if (url) {
      const iconHosts = [
        'res.public.onecdn.static.microsoft',
        'res-1.cdn.office.net/assets/mail/file-icon',
        'cdn.office.net'
      ];
      
      if (iconHosts.some(host => url.includes(host))) {
        return true;
      }
    }
    
    // Check filename patterns specifically for icon files
    if (filename && iconPatterns.some(pattern => pattern.test(filename))) {
      return true;
    }
    
    // Check if it's a tiny image file (icons are usually small)
    if (contentType && contentType.includes('image/')) {
      // Additional check for dimensions in filename
      if (filename && /\d+x\d+/.test(filename)) {
        return true;
      }
      
      // Very small images that aren't the main content are likely icons
      if (size && size < 3000) { // Less than 3KB
        return true;
      }
    }
    
    return false;
  }
  
  // Debug raw attachments data
  if (opts && opts.debug) {
    log('Raw attachments data:');
    if (parsedEmail.attachments) {
      parsedEmail.attachments.forEach((att, i) => {
        log(`  Raw attachment ${i+1}:`, 
            `filename=${att.filename || 'undefined'}`, 
            `contentType=${att.contentType || 'undefined'}`,
            `contentDisposition=${att.contentDisposition || 'undefined'}`);
      });
    } else {
      log('  No raw attachments found in parsed email');
    }
  }
  
  // Process standard email attachments
  if (parsedEmail.attachments && parsedEmail.attachments.length > 0) {
    log(`Found ${parsedEmail.attachments.length} standard attachments`);
    
    for (const att of parsedEmail.attachments) {
      // Skip attachments without content type (unlikely but possible)
      if (!att.contentType) {
        log(`Skipping attachment without content type: ${att.filename || 'unknown'}`);
        continue;
      }
      
      // Try to determine content disposition - inline vs attachment
      const isInline = att.contentDisposition === 'inline';
      
      // Determine if this is likely an icon
      const isIcon = isLikelyIcon(att.filename, att.size, att.contentType);
      
      // Skip oversized attachments if option set
      if (opts && opts.maxAttachmentSize && att.size && att.size > opts.maxAttachmentSize) {
        log(`Attachment exceeds size limit: ${att.filename} (${att.size} bytes)`);
        attachments.push({
          filename: cleanFilename(att.filename) || 'attachment',
          contentType: att.contentType,
          size: att.size || 0,
          type: determineFileType(att.filename, att.contentType),
          disposition: isInline ? 'inline' : 'attachment',
          isStandard: true,
          isLikelyIcon: isIcon,
          exceededSizeLimit: true
        });
        continue;
      }
      
      // Add the attachment
      log(`Adding standard attachment: ${att.filename}${isIcon ? ' (likely an icon)' : ''}`);
      attachments.push({
        filename: cleanFilename(att.filename) || 'attachment',
        contentType: att.contentType,
        size: att.size || 0,
        type: determineFileType(att.filename, att.contentType),
        disposition: isInline ? 'inline' : 'attachment',
        contentId: att.contentId || null,
        isStandard: true,
        isLikelyIcon: isIcon,
        content: (opts && opts.includeAttachmentContent && att.content) ? 
                Buffer.isBuffer(att.content) ? att.content.toString('base64') : att.content : undefined
      });
    }
  }
  
  // Extract linked attachments from HTML content
  if (parsedEmail.html) {
    try {
      log('Scanning HTML content for linked attachments...');
      const $ = cheerio.load(parsedEmail.html);
      
      // Find links with file icons or that look like attachments
      $('a').each((i, elem) => {
        const href = $(elem).attr('href');
        if (!href) return;
        
        // Skip if we've already seen this URL
        if (seenUrls.has(href)) return;
        
        // Get the link text which often contains the filename
        const linkText = $(elem).text().trim();
        
        // Check if it's likely a file link
        const hasFileIcon = $(elem).find('img[src*="file-icon"]').length > 0 || 
                           $(elem).find('img[src*="attachment"]').length > 0;
                           
        const isFileLink = href && (
          href.includes('sharepoint.com') || 
          href.includes('onedrive.com') ||
          href.includes('cdn.office.net') ||
          href.includes('drive.google.com') ||
          href.includes('dropbox.com') ||
          hasFileIcon ||
          // Look for file extension patterns in URLs
          /\.(pdf|docx?|xlsx?|pptx?|zip|rar|txt|jpe?g|png|gif)($|\?)/i.test(href)
        );
        
        if (isFileLink) {
          log(`Found linked attachment: ${linkText || href}`);
          const iconImg = $(elem).find('img');
          const iconSrc = iconImg.length ? iconImg.attr('src') : undefined;
          
          // Clean up the filename - remove line breaks and extra spaces
          let filename = linkText || path.basename(href).split('?')[0];
          filename = cleanFilename(filename);
          
          // Save the icon URL for tracking
          const attachmentIndex = attachments.length;
          if (iconSrc) {
            if (!iconUrls.has(iconSrc)) {
              iconUrls.set(iconSrc, []);
            }
            iconUrls.get(iconSrc)!.push(attachmentIndex);
          }
          
          // The linked file itself is NOT an icon - it's a real attachment
          attachments.push({
            filename: filename,
            url: href,
            type: determineFileType(filename, undefined, iconSrc),
            iconUrl: iconSrc,
            isLink: true,
            isLikelyIcon: false // Linked files are not icons
          });
          
          seenUrls.add(href);
        }
      });
      
      // Also check for embedded images that might be additional attachments or icons
      $('img').each((i, elem) => {
        const src = $(elem).attr('src');
        if (!src) return;
        
        // Skip already processed URLs or data URIs (they're already in the HTML)
        if (seenUrls.has(src) || src.startsWith('data:')) return;
        
        // If the image has a valid "cid:" reference, it's an inline attachment
        // and should already be in the standard attachments list
        if (src.startsWith('cid:')) return;
        
        // Determine if this image is likely just an icon
        const isIcon = isLikelyIcon(path.basename(src), undefined, 'image', src);
        
        // This is likely an embedded image from an external source
        log(`Found embedded image: ${src}${isIcon ? ' (likely an icon)' : ''}`);
        let filename = path.basename(src).split('?')[0];
        
        // Track the attachment index
        const attachmentIndex = attachments.length;
        
        // If this is an icon, track which attachments might use it
        if (isIcon) {
          if (!iconUrls.has(src)) {
            iconUrls.set(src, []);
          }
        }
        
        attachments.push({
          filename: filename || 'image.jpg',
          url: src,
          type: 'image',
          isEmbedded: true,
          isLikelyIcon: isIcon
        });
        
        seenUrls.add(src);
      });
    } catch (e) {
      console.error('Error extracting linked attachments:', e);
    }
  }
  
  // Now establish relationships between icons and their attachments
  for (let i = 0; i < attachments.length; i++) {
    const attachment = attachments[i];
    
    // For each attachment with an iconUrl, find the corresponding icon attachment
    if (attachment.iconUrl) {
      // Find the index of the icon attachment
      for (let j = 0; j < attachments.length; j++) {
        if (attachments[j].url === attachment.iconUrl) {
          attachment.iconAttachmentIndex = j;
          
          // Also mark the icon as related to this attachment
          if (!attachments[j].isIconFor) {
            attachments[j].isIconFor = [];
          }
          attachments[j].isIconFor?.push(i);
          
          break;
        }
      }
    }
    
    // If we have tracked this as an icon, add its relationships
    if (attachment.isLikelyIcon && attachment.url && iconUrls.has(attachment.url)) {
      attachment.isIconFor = iconUrls.get(attachment.url);
    }
  }
  
  // Debug final list of attachments
  if (opts && opts.debug) {
    log(`Final attachment count: ${attachments.length}`);
    attachments.forEach((att, i) => {
      log(`  Attachment ${i+1}: ${att.filename}, type=${att.type}, ${att.isLink ? 'linked' : 'standard'}${att.isLikelyIcon ? ', ICON' : ''}${
        att.iconAttachmentIndex !== undefined ? `, icon at index ${att.iconAttachmentIndex}` : ''}${
        att.isIconFor ? `, is icon for attachments: ${att.isIconFor.join(', ')}` : ''}`);
    });
  }
  
  return attachments;
}

/**
 * Extract attachments from Gmail API message
 */
function extractGmailAttachments(payload: any, opts: EmailParserOptions): Attachment[] {
  const attachments: Attachment[] = [];
  
  function processPayloadParts(parts: any[]): void {
    if (!parts || !Array.isArray(parts)) return;
    
    for (const part of parts) {
      if (part.filename && part.filename.trim()) {
        // Skip oversized attachments if option set
        const exceedsSize = opts && opts.maxAttachmentSize && 
                           part.body && part.body.size && 
                           part.body.size > opts.maxAttachmentSize;
        
        attachments.push({
          filename: cleanFilename(part.filename),
          contentType: part.mimeType,
          partId: part.partId,
          type: determineFileType(part.filename, part.mimeType),
          isStandard: true,
          exceededSizeLimit: exceedsSize,
          content: (!exceedsSize && opts && opts.includeAttachmentContent && 
                   part.body && part.body.data) ? 
                  part.body.data : undefined
        });
      }
      
      // Recursively process nested parts
      if (part.parts) {
        processPayloadParts(part.parts);
      }
    }
  }
  
  if (payload && payload.parts) {
    processPayloadParts(payload.parts);
  }
  
  return attachments;
}

/**
 * Clean up filename - remove line breaks and extra spaces
 */
function cleanFilename(filename?: string): string {
  if (!filename) return 'attachment';
  
  return filename.replace(/\s+/g, ' ').trim();
}

/**
 * Determine file type from name, content type, or icon
 */
function determineFileType(filename?: string, contentType?: string, iconUrl?: string): string {
  // Check content type first
  if (contentType) {
    if (contentType.includes('pdf')) return 'pdf';
    if (contentType.includes('word') || contentType.includes('wordprocessing')) return 'docx';
    if (contentType.includes('excel') || contentType.includes('spreadsheet')) return 'xlsx';
    if (contentType.includes('powerpoint') || contentType.includes('presentation')) return 'pptx';
    if (contentType.includes('image/')) return 'image';
    if (contentType.includes('text/plain')) return 'txt';
    if (contentType.includes('text/html')) return 'html';
    if (contentType.includes('application/zip') || contentType.includes('application/x-zip')) return 'zip';
    if (contentType.includes('video/')) return 'video';
    if (contentType.includes('audio/')) return 'audio';
  }
  
  // Check filename
  if (filename) {
    const lower = filename.toLowerCase();
    if (lower.includes('.pdf')) return 'pdf';
    if (lower.match(/\.(docx?|odt|rtf)$/)) return 'docx';
    if (lower.match(/\.(xlsx?|csv|ods)$/)) return 'xlsx';
    if (lower.match(/\.(pptx?|odp)$/)) return 'pptx';
    if (lower.match(/\.(txt|log|md)$/)) return 'txt';
    if (lower.match(/\.(html?|xhtml)$/)) return 'html';
    if (lower.match(/\.(zip|7z|rar|tar|gz)$/)) return 'zip';
    if (lower.match(/\.(jpe?g|png|gif|bmp|tiff?|webp|svg)$/)) return 'image';
    if (lower.match(/\.(mp4|mov|wmv|flv|avi|webm|mkv)$/)) return 'video';
    if (lower.match(/\.(mp3|wav|ogg|m4a|flac|aac)$/)) return 'audio';
  }
  
  // Check icon URL for hints
  if (iconUrl) {
    const lower = iconUrl.toLowerCase();
    if (lower.includes('pdf')) return 'pdf';
    if (lower.includes('doc')) return 'docx';
    if (lower.includes('xls')) return 'xlsx';
    if (lower.includes('ppt')) return 'pptx';
    if (lower.includes('txt')) return 'txt';
    if (lower.includes('html')) return 'html';
    if (lower.includes('code')) return 'code';
    if (lower.includes('zip')) return 'zip';
    if (lower.includes('image')) return 'image';
    if (lower.includes('video')) return 'video';
    if (lower.includes('audio')) return 'audio';
  }
  
  return 'file';
}

/**
 * Extract thread ID from email
 */
function extractThreadId(parsedEmail: ParsedEmail): string {
  // Try gmail thread ID first
  if (parsedEmail.headers && parsedEmail.headers.get('x-gmail-thread-id')) {
    return parsedEmail.headers.get('x-gmail-thread-id');
  }
  
  // Try outlook conversation index
  if (parsedEmail.headers && parsedEmail.headers.get('thread-index')) {
    return parsedEmail.headers.get('thread-index');
  }
  
  // Try references or in-reply-to
  if (parsedEmail.references && parsedEmail.references.length) {
    return parsedEmail.references[0];
  }
  
  if (parsedEmail.inReplyTo) {
    return parsedEmail.inReplyTo;
  }
  
  // Use message ID as last resort
  return parsedEmail.messageId || `thread-${Date.now()}`;
}

/**
 * Extract important headers from email
 */
function extractImportantHeaders(headers: any): Record<string, any> {
  if (!headers) return {};
  
  const important: Record<string, any> = {};
  const headersToExtract = [
    'message-id', 'thread-index', 'x-gmail-thread-id', 'in-reply-to',
    'references', 'importance', 'priority', 'x-priority', 'x-msmail-priority',
    'precedence', 'x-spam-status', 'list-unsubscribe', 'delivered-to', 'return-path'
  ];
  
  for (const header of headersToExtract) {
    const value = headers.get(header);
    if (value) {
      important[header] = value;
    }
  }
  
  return important;
}

/**
 * Helper to check if Gmail message has attachments
 */
function hasAttachmentsInPayload(payload: any): boolean {
  if (!payload) return false;
  
  // Check for filename in the payload
  if (payload.filename && payload.filename.trim()) {
    return true;
  }
  
  // Check nested parts
  if (payload.parts) {
    for (const part of payload.parts) {
      if (part.filename && part.filename.trim()) {
        return true;
      }
      
      // Recursive check
      if (part.parts && hasAttachmentsInPayload(part)) {
        return true;
      }
    }
  }
  
  return false;
}

/**
 * Extract name from email header
 */
function extractNameFromHeader(header?: string): string {
  if (!header) return '';
  
  const match = header.match(/^([^<]+)</);
  if (match) {
    return match[1].trim();
  }
  
  return '';
}

/**
 * Extract email from header
 */
function extractEmailFromHeader(header?: string): string {
  if (!header) return '';
  
  const match = header.match(/<([^>]+)>/);
  if (match) {
    return match[1];
  }
  
  return header.trim();
}

/**
 * Parse recipients from header
 */
function parseRecipientsFromHeader(header?: string): Recipient[] {
  if (!header) return [];
  
  return header.split(',').map(addr => {
    addr = addr.trim();
    const nameMatch = addr.match(/^([^<]+)</);
    const emailMatch = addr.match(/<([^>]+)>/);
    
    return {
      name: nameMatch ? nameMatch[1].trim() : '',
      email: emailMatch ? emailMatch[1] : addr
    };
  });
}

/**
 * Create a clean snippet from the body
 */
function createSnippet(body?: string, maxLength = 100): string {
  if (!body) return '';
  
  // Convert newlines to spaces and remove extra whitespace
  let text = body.replace(/\s+/g, ' ').trim();
  
  // Limit to max length
  if (text.length <= maxLength) {
    return text;
  }
  
  return text.substring(0, maxLength) + '...';
}

/**
 * Extract and analyze subject line information
 */
function extractSubjectInfo(subject?: string): SubjectInfo {
  if (!subject) {
    return {
      raw: '(No Subject)',
      clean: '(No Subject)',
      hasReply: false,
      hasForward: false,
      prefixes: []
    };
  }
  
  // Common prefixes to detect
  const replyPrefixes = [/^re:/i, /^response:/i, /^answered:/i, /^respuesta:/i, /^sv:/i, /^aw:/i];
  const forwardPrefixes = [/^fw:/i, /^fwd:/i, /^forwarded:/i];
  const otherPrefixes = [/^[[(].*[\])]:/i]; // Matches things like [External]:, [SPAM]:, etc.
  
  // Initialize result
  const result: SubjectInfo = {
    raw: subject,
    clean: subject,
    hasReply: false,
    hasForward: false,
    prefixes: []
  };
  
  // Detect prefixes and collect them
  let workingSubject = subject;
  let foundPrefix = true;
  
  // Keep checking for prefixes until none are found
  while (foundPrefix) {
    foundPrefix = false;
    
    // Check for reply prefixes
    for (const prefix of replyPrefixes) {
      const match = workingSubject.match(prefix);
      if (match) {
        result.hasReply = true;
        result.prefixes.push(match[0].replace(/:/i, ''));
        workingSubject = workingSubject.replace(prefix, '').trim();
        foundPrefix = true;
        break;
      }
    }
    
    // If no reply prefix found, check for forward prefixes
    if (!foundPrefix) {
      for (const prefix of forwardPrefixes) {
        const match = workingSubject.match(prefix);
        if (match) {
          result.hasForward = true;
          result.prefixes.push(match[0].replace(/:/i, ''));
          workingSubject = workingSubject.replace(prefix, '').trim();
          foundPrefix = true;
          break;
        }
      }
    }
    
    // If no reply or forward prefix found, check for other prefixes
    if (!foundPrefix) {
      for (const prefix of otherPrefixes) {
        const match = workingSubject.match(prefix);
        if (match) {
          result.prefixes.push(match[0].replace(/:/i, ''));
          workingSubject = workingSubject.replace(prefix, '').trim();
          foundPrefix = true;
          break;
        }
      }
    }
  }
  
  // Set the cleaned subject
  result.clean = workingSubject;
  
  return result;
}

// Process a single email file
async function processEmailFile(filePath: string, outputPath: string | null = null, options: EmailParserOptions = {}): Promise<EmailData> {
  console.log(`\nProcessing email file: ${filePath}`);
  
  try {
    // Ensure options has outputPath set
    const emailOptions: EmailParserOptions = {
      ...options,
      outputPath
    };
    
    console.log("Using options:", emailOptions);
    
    const emailData = await parseAnyEmail(filePath, emailOptions);
    
    console.log('\nEmail parsed successfully:');
    console.log(`From: ${emailData.from.name ? emailData.from.name + ' ' : ''}<${emailData.from.email}>`);
    console.log(`Subject: ${emailData.subject}`);
    console.log(`Date: ${emailData.date}`);
    console.log(`Attachments: ${emailData.attachments.length}`);
    console.log(`Snippet: ${emailData.snippet}`);
    
    // Verify the result
    if (!emailData) {
      console.error("ERROR: parseAnyEmail returned null or undefined");
    } else if (Object.keys(emailData).length === 0) {
      console.error("ERROR: parseAnyEmail returned an empty object");
    }
    
    // Ensure we write the output if it wasn't written in parseAnyEmail
    if (outputPath && emailData) {
      try {
        fs.writeFileSync(outputPath, JSON.stringify(emailData, null, 2));
        console.log(`Wrote output to ${outputPath}`);
      } catch (err) {
        console.error(`Error writing output file: ${(err as Error).message}`);
      }
    }
    
    return emailData;
  } catch (error) {
    console.error('Failed to process email:', error);
    throw error;
  }
}

/**
 * Process JSON email data directly without requiring file operations
 * This function can be used by external applications to directly process API responses
 * @param jsonData - The raw JSON data from an API response
 * @param options - Processing options
 * @returns Parsed email data
 */
async function processEmailJson(jsonData: any, options: EmailParserOptions = {}): Promise<EmailData> {
  const opts: EmailParserOptions = {
    debug: false,
    outputPath: null,
    includeAttachmentContent: false,
    maxAttachmentSize: 10 * 1024 * 1024, // 10MB
    ...options
  };
  
  const log = (...args: any[]): void => {
    if (opts.debug) console.log(...args);
  };
  
  log('Processing email JSON data directly...');
  
  try {
    // Directly pass the JSON object to parseAnyEmail
    const emailData = await parseAnyEmail(jsonData, opts);
    
    // Save output if path provided
    if (emailData && opts.outputPath) {
      log(`Saving parsed email to ${opts.outputPath}`);
      fs.writeFileSync(opts.outputPath, JSON.stringify(emailData, null, 2));
    }
    
    return emailData;
  } catch (error) {
    console.error('Error processing email JSON:', error);
    throw error;
  }
}

// Command-line interface
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.log('Universal Email Parser - Handles any email format');
    console.log('\nUsage:');
    console.log('  node email-parser.js <input-file> [output-file]');
    console.log('  node email-parser.js --debug <input-file> [output-file]');
    console.log('  node email-parser.js --json \'{"raw":"base64string",...}\' [output-file]');
    console.log('\nOptions:');
    console.log('  --debug    Enable detailed debug logging');
    console.log('  --content  Include attachment content in output');
    console.log('  --json     Directly process JSON string instead of a file');
    return;
  }
  
  let debugMode = false;
  let includeContent = false;
  let inputFile = '';
  let outputFile: string | null = null;
  let jsonMode = false;
  let jsonData: any = null;
  
  // Process command-line arguments
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--debug') {
      debugMode = true;
    } else if (arg === '--content') {
      includeContent = true;
    } else if (arg === '--json') {
      jsonMode = true;
      if (i + 1 < args.length) {
        try {
          jsonData = JSON.parse(args[i + 1]);
          i++; // Skip the next argument as it's the JSON string
        } catch (e) {
          console.error(`Error parsing JSON input: ${(e as Error).message}`);
          process.exit(1);
        }
      } else {
        console.error('Error: No JSON data provided after --json flag');
        process.exit(1);
      }
    } else if (!inputFile && !jsonMode) {
      inputFile = arg;
    } else if (!outputFile) {
      outputFile = arg;
    }
  }
  
  const options: EmailParserOptions = {
    debug: debugMode,
    includeAttachmentContent: includeContent,
    outputPath: outputFile
  };
  
  console.log(`Debug mode: ${debugMode ? 'ON' : 'OFF'}`);
  console.log(`Output file: ${outputFile || 'None specified'}`);
  
  try {
    let result: EmailData | undefined;
    
    if (jsonMode && jsonData) {
      console.log('Processing JSON data directly...');
      result = await processEmailJson(jsonData, options);
    } else if (inputFile) {
      console.log(`Processing file: ${inputFile}`);
      
      // Make sure the file exists
      if (!fs.existsSync(inputFile)) {
        console.error(`Error: Input file '${inputFile}' does not exist`);
        process.exit(1);
      }
      
      result = await processEmailFile(inputFile, outputFile, options);
    } else {
      console.error('Error: No input specified');
      process.exit(1);
    }
    
    if (result) {
      console.log("Email processing completed successfully");
      
      // Check if the output file was created and has content
      if (outputFile && fs.existsSync(outputFile)) {
        const stats = fs.statSync(outputFile);
        console.log(`Output file created: ${outputFile} (${stats.size} bytes)`);
        if (stats.size === 0) {
          console.error("WARNING: Output file is empty!");
        }
      } else if (outputFile) {
        console.error("WARNING: Output file was not created!");
      }
    } else {
      console.error("Email processing returned no result");
    }
  } catch (error) {
    console.error('Error in main process:', error);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main().catch(err => {
    console.error('Unhandled error:', err);
    process.exit(1);
  });
}

// Export for use in other modules
export {
  parseAnyEmail,
  processEmailFile,
  processEmailJson
}; 