# CiaraAI Email Parser

A robust, flexible Node.js utility for parsing virtually any email format and extracting standardized data including text, attachments, and metadata. Developed by CiaraAI.

## Features

- **Multi-format Support**: Handles a wide variety of email formats:
  - RFC 822/MIME format emails
  - Gmail API format (both raw and payload styles)
  - Microsoft Exchange/Outlook formats
  - Plain text email exports
  - MBOX archives
  - Base64 encoded email content
  - Direct JSON objects

- **Rich Data Extraction**:
  - Complete sender/recipient information
  - HTML and plain text body content
  - Subject with prefix analysis (RE:, FWD:, etc.)
  - Email headers and metadata
  - Threading information

- **Advanced Attachment Handling**:
  - Detects standard attachments
  - Identifies linked files (OneDrive, SharePoint, etc.)
  - Extracts file type and metadata
  - Smart icon detection to avoid counting icons as attachments
  - Linked file relationship mapping

- **Content Processing**:
  - HTML sanitization for safe display
  - Plain text extraction from HTML
  - Email body cleaning (removing signatures, quoted text)
  - Snippet generation

## Installation

```bash
# Clone the repository
git clone https://github.com/claxman/CiaraAI-Email-Parser.git
cd CiaraAI-Email-Parser

# Install dependencies
npm install
```

Required dependencies:
- mailparser
- cheerio
- iconv-lite (optional, for character encoding support)
- msg-parser (optional, for .msg file support)

## Command-line Usage

### Basic Usage

```bash
node dist/email-parser.js <input-file> [output-file]
```

### With Debug Information

```bash
node dist/email-parser.js --debug <input-file> [output-file]
```

### Process JSON Directly

```bash
node dist/email-parser.js --json '{"raw":"base64-encoded-content"}' [output-file]
```

### Include Attachment Content

```bash
node dist/email-parser.js --content <input-file> [output-file]
```

### Examples

```bash
# Parse an EML file
node dist/email-parser.js email.eml parsed_email.json

# Parse a Gmail API JSON file with debug information
node dist/email-parser.js --debug gmail_message.json parsed_email.json

# Parse directly from a Gmail API response
node dist/email-parser.js --json "$(cat gmail_response.json)" parsed_email.json

# Parse an MBOX file with attachment content included
node dist/email-parser.js --content --debug mailbox.mbox parsed_email.json
```

## Programmatic Usage

The parser can be imported and used in your Node.js applications:

```javascript
const { parseAnyEmail, processEmailFile, processEmailJson } = require('./email-parser');

// Parse from a file
async function parseEmailFile() {
  try {
    const emailData = await processEmailFile('path/to/email.eml', 'output.json', { debug: true });
    console.log(`Parsed email from ${emailData.from.name} <${emailData.from.email}>`);
    console.log(`Subject: ${emailData.subject}`);
    console.log(`Has attachments: ${emailData.hasAttachments}`);
  } catch (error) {
    console.error('Error parsing email:', error);
  }
}

// Parse from a JSON object
async function parseFromJson(jsonData) {
  try {
    const emailData = await processEmailJson(jsonData, { debug: true });
    // Process the parsed email data
    return emailData;
  } catch (error) {
    console.error('Error processing JSON:', error);
    throw error;
  }
}
```

## Output Format

The parser produces a standardized JSON output with the following structure:

```javascript
{
  "id": "unique-message-id",
  "from": {
    "name": "Sender Name",
    "email": "sender@example.com"
  },
  "to": [
    {
      "name": "Recipient Name",
      "email": "recipient@example.com"
    }
  ],
  "cc": [ /* Similar to 'to' field */ ],
  "bcc": [ /* Similar to 'to' field */ ],
  "subject": "Email Subject",
  "subjectInfo": {
    "raw": "Re: Email Subject",
    "clean": "Email Subject",
    "hasReply": true,
    "hasForward": false,
    "prefixes": ["Re"]
  },
  "date": "2023-04-15T10:30:00.000Z",
  "body": "Plain text content of the email...",
  "bodyHtml": "<div>HTML content of the email...</div>",
  "hasAttachments": true,
  "attachments": [
    {
      "filename": "document.pdf",
      "contentType": "application/pdf",
      "size": 152400,
      "type": "pdf",
      "isStandard": true,
      "isLikelyIcon": false
    },
    {
      "filename": "presentation.pptx",
      "url": "https://example.com/shared/presentation.pptx",
      "type": "pptx",
      "iconUrl": "https://cdn.example.com/icons/pptx_icon.png",
      "isLink": true,
      "isLikelyIcon": false
    }
  ],
  "headers": {
    "message-id": "<unique-id@example.com>",
    "references": "<previous-message-id@example.com>",
    "in-reply-to": "<previous-message-id@example.com>"
  },
  "threadId": "thread-123456",
  "snippet": "Beginning of the email content..."
}
```

## Attachment Detection

The parser identifies various types of attachments:

1. **Standard Attachments**: Files directly attached to the email
2. **Linked Attachments**: Files referenced by URL in the email content
3. **Embedded Images**: Images displayed inline in the email
4. **Icons**: Small images that are part of the email interface (not true attachments)

The `hasAttachments` flag is set to `true` when any non-icon attachments are found.

Each attachment object contains these common fields:

- `filename`: Original filename
- `type`: Determined file type (pdf, docx, txt, etc.)
- `isLikelyIcon`: Boolean indicating if the attachment is just an icon

Additional fields for standard attachments:
- `contentType`: MIME type
- `size`: File size in bytes
- `disposition`: 'attachment' or 'inline'
- `isStandard`: Always true for standard attachments

Additional fields for linked attachments:
- `url`: The link to the attachment
- `iconUrl`: URL of the associated icon image
- `isLink`: Always true for linked attachments

## Error Handling

The parser attempts to extract as much information as possible even from malformed emails. If parsing fails completely, it will return a minimal object with error information:

```javascript
{
  "error": "Error message",
  "id": "error-timestamp",
  "subject": "Error parsing email",
  "from": { "name": "", "email": "" },
  "to": [],
  "date": "2023-04-15T10:30:00.000Z",
  "body": "Failed to parse this email. The format may be unsupported.",
  "hasAttachments": false,
  "attachments": []
}
```

## Best Practices

1. **Use debug mode for troubleshooting**: The `--debug` flag provides detailed logs of the parsing process.

2. **Avoid `--content` for large emails**: Including attachment content can lead to very large output files and memory usage.

3. **Check file existence**: Ensure the input file exists before parsing.

4. **Handle parsing errors**: Always implement error handling when using the parser programmatically.

5. **Process attachments carefully**: Use the `type` field to determine how to handle different attachment types in your application.

## License

MIT

## Contributors

[List contributors here]

## Changelog

### v1.0.0
- Initial release

### v1.0.1
- Improved attachment detection
- Added support for more file types
- Enhanced HTML sanitization 

## TypeScript Support

The email parser is now fully written in TypeScript, providing type safety and better developer experience. The TypeScript version is available in the `src` directory, with compiled JavaScript output in `dist`.

### Building TypeScript Code

```bash
# Install dependencies
npm install

# Build the TypeScript code
npm run build

# Watch mode for development
npm run dev
```

### Using TypeScript Version

The TypeScript version maintains all the functionality of the original JavaScript version but adds type definitions and interfaces. Here's how to use it:

```typescript
import { parseAnyEmail, processEmailFile, processEmailJson } from './dist/email-parser';
import type { EmailData, EmailParserOptions } from './dist/types';

// Parse an email file
async function parseEmail() {
  const options: EmailParserOptions = {
    debug: true,
    outputPath: 'output.json'
  };
  
  const emailData: EmailData = await processEmailFile('messageraw.json', 'output.json', options);
  console.log(`Email has attachments: ${emailData.hasAttachments}`);
}

// Process JSON data directly
async function processJson() {
  const jsonData = JSON.parse(fs.readFileSync('messageraw.json', 'utf8'));
  const emailData = await processEmailJson(jsonData, { debug: true });
  console.log(`Found ${emailData.attachments.length} attachments`);
}

// Run from the command line
// The TypeScript version works exactly the same as the JavaScript version:
// node dist/email-parser.js --debug messageraw.json output.json
```

### Type Definitions

The TypeScript version includes comprehensive type definitions for all functions and data structures, making it easier to understand the code and catch potential issues during development. 