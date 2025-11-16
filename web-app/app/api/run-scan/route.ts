import { NextResponse } from "next/server";
import { z } from "zod";
import path from "path";
import fs from "fs";
import { spawn, spawnSync } from "child_process";

const requestSchema = z.object({
  provider: z.enum(["aws", "gcp", "azure"]),
  frameworks: z.array(z.string()).default([]),
  regions: z.array(z.string()).optional(),
  credentials: z.object({
    accessKeyId: z.string().min(2),
    secretAccessKey: z.string().min(2),
    sessionToken: z.string().optional(),
  }),
});

const FRAMEWORK_MAP: Record<string, Record<string, string>> = {
  aws: {
    "SOC 2": "soc2_aws",
    "ISO 27001": "iso27001_2022_aws",
    "NIST 800-53": "nist_800_53_revision_5_aws",
    "CIS AWS Foundations": "cis_4.0_aws",
  },
  azure: {
    "SOC 2": "soc2_azure",
    "ISO 27001": "iso27001_2022_azure",
    "CIS Azure": "cis_4.0_azure",
  },
  gcp: {
    "SOC 2": "soc2_gcp",
    "CIS GCP": "cis_4.0_gcp",
  },
};

function mapFrameworks(provider: "aws" | "gcp" | "azure", frameworks: string[]): string[] {
  const mapping = FRAMEWORK_MAP[provider] ?? {};
  const mapped = frameworks
    .map((fw) => mapping[fw])
    .filter((fw): fw is string => Boolean(fw));
  return Array.from(new Set(mapped));
}

interface ScanResultPayload {
  run_id: string;
  normalized: unknown[];
  summary?: Record<string, unknown> | null;
  metadata?: {
    report_path?: string | null;
    report_error?: string | null;
  } | null;
}

async function runScanScript(args: {
  provider: "aws" | "gcp" | "azure";
  frameworkIds: string[];
  regions: string[];
  credentials: {
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken?: string;
  };
}): Promise<ScanResultPayload> {
  const repoRoot = path.resolve(process.cwd(), "..");
  const scriptPath = path.join(repoRoot, "scripts", "run_scan_service.py");
  const artifactsDir = path.join(repoRoot, "artifacts");

  const venvBinDir =
    process.platform === "win32"
      ? path.join(repoRoot, ".venv", "Scripts")
      : path.join(repoRoot, ".venv", "bin");
  const venvPython = path.join(venvBinDir, process.platform === "win32" ? "python.exe" : "python");

  const poetryBinary = process.env.POETRY_BIN ?? "poetry";
  const hasVenv = fs.existsSync(venvPython);
  let pythonCommand: { command: string; args: string[] };
  if (hasVenv) {
    pythonCommand = { command: venvPython, args: [scriptPath] };
  } else {
    const checkPoetry = spawnSync(poetryBinary, ["--version"], {
      cwd: repoRoot,
      env: process.env,
      stdio: "ignore",
    });

    if (checkPoetry.error) {
      throw new Error(
        "Poetry is not installed or not available in PATH. Install Poetry or create a .venv with project dependencies.",
      );
    }

    pythonCommand = { command: poetryBinary, args: ["run", "python", scriptPath] };
  }

  const scriptArgs = [
    "--provider",
    args.provider,
    "--frameworks",
    args.frameworkIds.join(","),
    "--regions",
    args.regions.join(","),
    "--artifacts-dir",
    artifactsDir,
  ];

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    AWS_ACCESS_KEY_ID: args.credentials.accessKeyId,
    AWS_SECRET_ACCESS_KEY: args.credentials.secretAccessKey,
    AWS_DEFAULT_REGION: args.regions[0] ?? "us-east-1",
  };

  const existingPythonPath = env.PYTHONPATH ?? "";
  env.PYTHONPATH = existingPythonPath
    ? `${repoRoot}${path.delimiter}${existingPythonPath}`
    : repoRoot;

  const extraPaths: string[] = [];
  const homeDir = process.env.HOME ?? process.env.USERPROFILE;
  if (homeDir) {
    extraPaths.push(path.join(homeDir, ".poetry", "bin"));
    extraPaths.push(path.join(homeDir, ".local", "bin"));
    extraPaths.push(path.join(homeDir, "Library", "Python", "3.12", "bin"));
    extraPaths.push(path.join(homeDir, "Library", "Python", "3.11", "bin"));
  }
  extraPaths.push("/opt/homebrew/bin");
  extraPaths.push("/usr/local/bin");

  const existingPath = process.env.PATH ?? "";
  env.PATH = [existingPath, ...extraPaths.filter(Boolean)]
    .filter((value, index, array) => value && array.indexOf(value) === index)
    .join(path.delimiter);

  if (args.credentials.sessionToken) {
    env.AWS_SESSION_TOKEN = args.credentials.sessionToken;
  }

  const invokeScript = (
    command: string,
    args: string[],
  ): Promise<ScanResultPayload> =>
    new Promise<ScanResultPayload>((resolve, reject) => {
      const child = spawn(command, [...pythonCommand.args, ...args], {
        cwd: repoRoot,
        env,
      });

      let stdout = "";
      let stderr = "";

      child.stdout.on("data", (data) => {
        stdout += data.toString();
      });

      child.stderr.on("data", (data) => {
        stderr += data.toString();
      });

      child.on("error", (error) => {
        reject(error);
      });

      child.on("close", (code) => {
        if (code !== 0) {
          const message = stderr || stdout || `Scan process failed with code ${code}`;
          reject(new Error(message));
          return;
        }

        try {
          const payload = JSON.parse(stdout) as ScanResultPayload | { error: string };
          if ("error" in payload) {
            reject(new Error(payload.error));
            return;
          }
          resolve(payload);
        } catch (error) {
          reject(new Error(`Failed to parse scan output: ${(error as Error).message}`));
        }
      });
    });

  return invokeScript(pythonCommand.command, scriptArgs);
}

export async function POST(request: Request) {
  try {
    const data = await request.json();
    const parsed = requestSchema.safeParse(data);

    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid request payload", details: parsed.error.format() },
        { status: 400 },
      );
    }

    const { provider, frameworks, regions, credentials } = parsed.data;

    const frameworkIds = mapFrameworks(provider, frameworks);

    if (frameworkIds.length === 0) {
      return NextResponse.json(
        { error: "No supported frameworks selected for this provider." },
        { status: 400 },
      );
    }

    if (provider !== "aws") {
      return NextResponse.json(
        { error: "Demo scanner currently supports AWS only." },
        { status: 400 },
      );
    }

    const regionSelection = regions && regions.length > 0 ? regions : ["us-east-1"];

    const result = await runScanScript({
      provider,
      frameworkIds,
      regions: regionSelection,
      credentials,
    });

    return NextResponse.json({
      report: {
        tool: "cs_kit",
        provider,
        framework_selection: frameworks,
        findings: result.normalized,
      },
      summary: result.summary,
      runId: result.run_id,
      frameworkNote:
        frameworkIds.length > 1
          ? "Multiple frameworks selected; scans are executed sequentially for each compliance."
          : undefined,
      reportMetadata: result.metadata ?? null,
    });
  } catch (error) {
    const message = (error as Error).message;
    const lower = message.toLowerCase();
    const repoRoot = path.resolve(process.cwd(), "..");

    if (
      lower.includes("poetry is not installed") ||
      lower.includes("module not found") ||
      lower.includes("failed to start scan process")
    ) {
      const samplePath = path.join(repoRoot, "web-app", "fixtures", "sample_report.json");
      if (fs.existsSync(samplePath)) {
        const sampleReport = JSON.parse(fs.readFileSync(samplePath, "utf-8"));
        return NextResponse.json({
          report: sampleReport,
          summary: null,
          runId: "sample-data",
          simulated: true,
          warning:
            "Scanner dependencies are not installed. Showing sample results instead. Install Python dependencies (e.g. `poetry install`) to run real scans.",
        });
      }

      return NextResponse.json(
        {
          error: "Scanner dependencies missing",
          message:
            "Poetry is not installed and no sample data is available. Install dependencies with `poetry install` or create a virtualenv with required packages.",
        },
        { status: 500 },
      );
    }

    return NextResponse.json(
      {
        error: "Failed to execute scan",
        message,
      },
      { status: 500 },
    );
  }
}

