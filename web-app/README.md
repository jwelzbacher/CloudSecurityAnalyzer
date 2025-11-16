# CS Kit Web Application

A modern web interface for viewing and analyzing cloud security compliance scan results from CS Kit and Prowler.

## Features

- **Intake Form**: Configure cloud provider, credentials (client-side only), and compliance frameworks
- **Automated Scanning**: Kick off CS Kit scans directly from the browser
- **Pretty Print View**: Beautiful, filterable table view of findings
- **Filtering**: Filter by severity, status, framework, and search query
- **Export**: Export reports as PDF or standalone HTML
- **Multiple Views**: View findings by severity, by service, or all together

## Security Disclaimer

⚠️ **IMPORTANT**: Demo usage only. 

- **Credentials are posted to the local Next.js API route** solely to execute the scan and are **never persisted to disk**.
- **Only AWS scans are supported in this demo**. Other providers are rejected by the API.
- **Use disposable credentials** and avoid running against production accounts without proper authorization.

## Getting Started

### Prerequisites

- Node.js 18+ and npm/yarn/pnpm
- Modern web browser

### Installation

```bash
# Install dependencies
npm install

# Run development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Building for Production

```bash
npm run build
npm start
```

## Usage

1. **Configure Scan** (`/`):
   - Select cloud provider (AWS, GCP, or Azure)
   - Enter access credentials (demo only - not used)
   - Select compliance frameworks to scan against
   - Click "Continue to Report"

2. **Run Scan** (`/report`):
   - The scan starts automatically with the configuration from the intake form
   - Results are fetched from the CS Kit CLI and rendered as an interactive report

3. **View & Filter**:
   - Use filters to narrow down findings
   - Switch between views: by severity, by service, or all
   - Search across check IDs, titles, services, and resources

4. **Export**:
   - Export PDF: Multi-page PDF with summary and findings table
   - Export HTML: Standalone HTML file with current filtered view

## JSON Schema

The application accepts JSON files matching this structure:

```typescript
interface Finding {
  check_id?: string;
  check_title?: string;
  title?: string;              // Alternative to check_title
  provider: "aws" | "gcp" | "azure";
  service?: string;
  severity?: "critical" | "high" | "medium" | "low" | "informational";
  status?: "PASS" | "FAIL" | "INFO" | "SKIP";
  account_id?: string;
  subscription_id?: string;     // For Azure
  project_id?: string;          // For GCP
  region?: string;
  resource_id?: string;
  resource_arn?: string;
  risk?: string;
  remediation?: string | { text?: string; url?: string };
  categories?: string[];
  frameworks?: Array<{ name: string; control?: string }>;
  timestamp?: string;
  time?: string;               // Alternative to timestamp
  description?: string;
}

// Either an array of findings
type ScanInput = Finding[];

// Or a wrapped report
interface ScanReport {
  tool?: string;
  version?: string;
  provider: "aws" | "gcp" | "azure";
  framework_selection?: string[];
  started_at?: string;
  finished_at?: string;
  findings: Finding[];
}
```

## Sample Data

Test the application with the included fixtures:

- `fixtures/sample_report.json` - Full report with wrapped structure
- `fixtures/findings_array.json` - Simple array of findings

## Technology Stack

- **Next.js 14** - React framework with App Router
- **TypeScript** - Type safety
- **Tailwind CSS** - Styling
- **Zod** - Schema validation
- **jsPDF + jspdf-autotable** - PDF generation
- **Framer Motion** - Animations (optional)
- **Lucide React** - Icons

## Project Structure

```
web-app/
├── app/
│   ├── page.tsx              # Intake form
│   ├── report/
│   │   └── page.tsx          # Report viewer
│   ├── layout.tsx
│   └── globals.css
├── components/
│   ├── ui/                   # Base UI components (shadcn-style)
│   ├── SeverityChips.tsx
│   └── StatusChips.tsx
├── lib/
│   ├── zodSchemas.ts         # Zod validation schemas
│   ├── normalize.ts          # Data normalization
│   ├── filters.ts            # Filtering utilities
│   ├── exportPdf.ts          # PDF export
│   ├── exportHtml.ts         # HTML export
│   └── utils.ts
├── fixtures/                 # Sample JSON files
└── package.json
```

## Development

### Adding New Components

Components follow the shadcn/ui pattern. Base components are in `components/ui/`, custom components in `components/`.

### Extending Filters

Add new filter options in `lib/filters.ts` and update the `FilterOptions` interface.

### Customizing Export

Modify `lib/exportPdf.ts` and `lib/exportHtml.ts` to customize export formats.

## License

Part of the CS Kit project. See main project LICENSE.

## Contributing

See main CS Kit project for contribution guidelines.

