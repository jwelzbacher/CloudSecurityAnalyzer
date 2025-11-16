"use client";

import { useState, useEffect, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { SeverityChips } from "@/components/SeverityChips";
import { StatusChips } from "@/components/StatusChips";
import { normalizeScanInput } from "@/lib/normalize";
import {
  filterFindings,
  groupBySeverity,
  groupByService,
  getTopFailedControls,
  getFrameworkCoverage,
  FilterOptions,
} from "@/lib/filters";
import { exportToPdf } from "@/lib/exportPdf";
import { exportToHtml } from "@/lib/exportHtml";
import {
  Download,
  FileText,
  Search,
  AlertCircle,
  CheckCircle,
  XCircle,
  SkipForward,
  Loader2,
  AlertTriangle,
} from "lucide-react";
import type { ScanReport, Finding, Severity, Status } from "@/lib/zodSchemas";

interface ScanApiResponse {
  report: {
    tool: string;
    provider: "aws" | "gcp" | "azure";
    framework_selection?: string[];
    findings: any[];
  };
  summary?: Record<string, unknown> | null;
  runId: string;
  simulated?: boolean;
  warning?: string;
  frameworkNote?: string;
  reportMetadata?: {
    report_path?: string | null;
    report_error?: string | null;
  } | null;
}

export default function ReportPage() {
  const router = useRouter();
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState("Preparing scan...");
  const [isLoading, setIsLoading] = useState(true);
  const [simulationWarning, setSimulationWarning] = useState<string | null>(null);
  const [frameworkWarning, setFrameworkWarning] = useState<string | null>(null);
  const [reportWarning, setReportWarning] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverities, setSelectedSeverities] = useState<Severity[]>([]);
  const [selectedStatuses, setSelectedStatuses] = useState<Status[]>(["FAIL", "INFO"]);
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<"severity" | "service" | "all">("all");

  useEffect(() => {
    const intakeData = localStorage.getItem("cs_kit_intake");
    if (!intakeData) {
      setError("Scan configuration not found. Please start a new scan.");
      setIsLoading(false);
      return;
    }

    let parsedIntake: { provider: "aws" | "gcp" | "azure"; frameworks: string[] };
    try {
      parsedIntake = JSON.parse(intakeData);
      setSelectedFrameworks(parsedIntake.frameworks || []);
    } catch (intakeError) {
      setError("Failed to read saved scan configuration. Please try again.");
      setIsLoading(false);
      return;
    }

    const credentialsRaw = sessionStorage.getItem("cs_kit_credentials");
    if (!credentialsRaw) {
      setError("Credentials not found. Please re-enter them.");
      setIsLoading(false);
      return;
    }

    let credentials: {
      accessKeyId: string;
      secretAccessKey: string;
      sessionToken?: string;
    };
    try {
      credentials = JSON.parse(credentialsRaw);
    } catch (parseError) {
      setError("Could not read credentials. Please try again.");
      setIsLoading(false);
      return;
    }

    const startScan = async () => {
      try {
        setStatusMessage("Running security scan...");
        const response = await fetch("/api/run-scan", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            provider: parsedIntake.provider,
            frameworks: parsedIntake.frameworks,
            credentials,
          }),
        });

                let rawPayload: ScanApiResponse | { error?: string; message?: string };
        try {
          rawPayload = (await response.json()) as ScanApiResponse | {
            error?: string;
            message?: string;
          };
        } catch (parseError) {
          throw new Error("Received unexpected response from scanner");
        }

        // Treat anything non-OK or lacking `report` as an error
        if (!response.ok || !("report" in rawPayload)) {
          const detail =
            ("message" in rawPayload && rawPayload.message) ||
            ("error" in rawPayload && rawPayload.error) ||
            "Scan failed";
          throw new Error(detail);
        }

        // From here on, TS knows this is a ScanApiResponse
        const payload: ScanApiResponse = rawPayload;

        const normalized = normalizeScanInput({
          tool: payload.report.tool,
          provider: payload.report.provider,
          framework_selection: payload.report.framework_selection,
          findings: payload.report.findings,
        });


        setReport(normalized);
        if (payload.simulated) {
          setSimulationWarning(
            payload.warning ??
              "Showing sample results because scanner dependencies are unavailable.",
          );
          setStatusMessage("Loaded sample results");
        } else {
          setStatusMessage(`Scan completed (Run ID: ${payload.runId})`);
        }
        setFrameworkWarning(payload.frameworkNote ?? null);
        const pdfError = payload.reportMetadata?.report_error ?? null;
        setReportWarning(
          pdfError
            ? "PDF generation failed. You can export the HTML report and convert to PDF if needed."
            : null,
        );
      } catch (scanError) {
        setError((scanError as Error).message);
      } finally {
        setIsLoading(false);
        sessionStorage.removeItem("cs_kit_credentials");
      }
    };

    void startScan();
  }, []);

  const filterOptions: FilterOptions = {
    severities: selectedSeverities,
    statuses: selectedStatuses,
    frameworks: [],
    searchQuery,
  };

  const filteredFindings = useMemo(() => {
    if (!report) return [];
    return filterFindings(report.findings, filterOptions);
  }, [report, filterOptions]);

  const summary = useMemo(() => {
    if (!report) return null;
    const total = filteredFindings.length;
    const passed = filteredFindings.filter((f) => f.status === "PASS").length;
    const failed = filteredFindings.filter((f) => f.status === "FAIL").length;
    const bySeverity = {
      critical: filteredFindings.filter((f) => f.severity === "critical").length,
      high: filteredFindings.filter((f) => f.severity === "high").length,
      medium: filteredFindings.filter((f) => f.severity === "medium").length,
      low: filteredFindings.filter((f) => f.severity === "low").length,
      informational: filteredFindings.filter((f) => f.severity === "informational").length,
    };
    return { total, passed, failed, bySeverity };
  }, [filteredFindings]);

  const topFailedControls = useMemo(() => {
    if (!report) return [];
    return getTopFailedControls(filteredFindings, 5);
  }, [filteredFindings, report]);

  const frameworkCoverage = useMemo(() => {
    if (!report) return {};
    return getFrameworkCoverage(filteredFindings);
  }, [filteredFindings, report]);

  const handleExportPdf = () => {
    if (!report) return;
    exportToPdf(report, filterOptions);
  };

  const handleExportHtml = () => {
    if (!report) return;
    exportToHtml(report, filterOptions);
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 p-8">
        <div className="max-w-4xl mx-auto">
          <Card>
            <CardHeader>
              <CardTitle>Running Security Scan</CardTitle>
              <CardDescription>
                This may take a few minutes depending on your environment size.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex items-center gap-4 py-10">
              <Loader2 className="h-10 w-10 animate-spin text-blue-600" />
              <div>
                <p className="text-sm text-gray-600">{statusMessage}</p>
                <p className="text-xs text-gray-400 mt-2">
                  Keep this tab open while the scan is in progress.
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 p-8">
        <div className="max-w-4xl mx-auto">
          <Card>
            <CardHeader>
              <CardTitle>Scan Error</CardTitle>
              <CardDescription>We couldn&apos;t complete the scan.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-start gap-3 bg-red-50 border border-red-200 rounded-md p-4 text-red-800">
                <AlertTriangle className="h-5 w-5 mt-1" />
                <div>
                  <p className="font-semibold">Error</p>
                  <p className="text-sm">{error}</p>
                </div>
              </div>
              <Button variant="outline" onClick={() => router.push("/")}>
                Start a New Scan
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  if (!report) {
    return null;
  }

  const severityGroups = groupBySeverity(filteredFindings);
  const serviceGroups = groupByService(filteredFindings);

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Security Report</h1>
            <p className="text-gray-600 mt-1">
              {report.provider.toUpperCase()} • {new Date().toLocaleDateString()}
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => router.push("/")}>
              New Scan
            </Button>
            <Button variant="outline" onClick={handleExportHtml}>
              <Download className="h-4 w-4 mr-2" />
              Export HTML
            </Button>
            <Button onClick={handleExportPdf}>
              <FileText className="h-4 w-4 mr-2" />
              Export PDF
            </Button>
          </div>
        </div>

        {simulationWarning && (
          <div className="flex items-start gap-3 bg-yellow-50 border border-yellow-200 rounded-md p-4 text-yellow-900">
            <AlertTriangle className="h-5 w-5 mt-1 flex-shrink-0" />
            <div>
              <p className="font-semibold">Simulation Mode</p>
              <p className="text-sm">{simulationWarning}</p>
            </div>
          </div>
        )}

        {frameworkWarning && (
          <div className="flex items-start gap-3 bg-blue-50 border border-blue-200 rounded-md p-4 text-blue-900">
            <AlertTriangle className="h-5 w-5 mt-1 flex-shrink-0" />
            <div>
              <p className="font-semibold">Framework Selection Adjusted</p>
              <p className="text-sm">{frameworkWarning}</p>
            </div>
          </div>
        )}

        {reportWarning && (
          <div className="flex items-start gap-3 bg-yellow-50 border border-yellow-200 rounded-md p-4 text-yellow-900">
            <AlertTriangle className="h-5 w-5 mt-1 flex-shrink-0" />
            <div>
              <p className="font-semibold">PDF Generation Issue</p>
              <p className="text-sm">{reportWarning}</p>
            </div>
          </div>
        )}

        {/* Summary Cards */}
        {summary && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Total Findings</CardDescription>
                <CardTitle className="text-3xl">{summary.total}</CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Passed</CardDescription>
                <CardTitle className="text-3xl text-green-600">{summary.passed}</CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Failed</CardDescription>
                <CardTitle className="text-3xl text-red-600">{summary.failed}</CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardDescription>Critical</CardDescription>
                <CardTitle className="text-3xl text-red-800">{summary.bySeverity.critical}</CardTitle>
              </CardHeader>
            </Card>
          </div>
        )}

        {/* Filters */}
        <Card>
          <CardHeader>
            <CardTitle>Filters</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-sm font-medium mb-2 block">Search</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="Search by check ID, title, service, resource..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10"
                />
              </div>
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Severity</label>
              <SeverityChips selected={selectedSeverities} onChange={setSelectedSeverities} />
            </div>
            <div>
              <label className="text-sm font-medium mb-2 block">Status</label>
              <StatusChips selected={selectedStatuses} onChange={setSelectedStatuses} />
            </div>
          </CardContent>
        </Card>

        {/* Insights */}
        {topFailedControls.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Top Failed Controls</CardTitle>
              <CardDescription>Controls with the highest number of failing findings</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {topFailedControls.map((control) => (
                <div key={control.check_id} className="flex justify-between border-b last:border-0 pb-2">
                  <div>
                    <p className="font-medium text-sm">{control.title}</p>
                    <p className="text-xs text-gray-500 font-mono">{control.check_id}</p>
                  </div>
                  <Badge variant="destructive">{control.count} fail</Badge>
                </div>
              ))}
            </CardContent>
          </Card>
        )}

        {Object.keys(frameworkCoverage).length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Framework Coverage</CardTitle>
              <CardDescription>Pass and fail counts per compliance framework</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {Object.entries(frameworkCoverage).map(([framework, stats]) => (
                  <div key={framework} className="border rounded-md p-3">
                    <p className="font-medium text-sm">{framework}</p>
                    <div className="flex items-center gap-4 mt-2 text-sm">
                      <span className="text-gray-600">Total: {stats.total}</span>
                      <span className="text-green-600">Pass: {stats.passed}</span>
                      <span className="text-red-600">Fail: {stats.failed}</span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Tabs */}
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8">
            {(["severity", "service", "all"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab
                    ? "border-blue-500 text-blue-600"
                    : "border-transparent text-gray-500 hover:text-gray-700"
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </nav>
        </div>

        {/* Content */}
        {activeTab === "severity" && (
          <div className="space-y-6">
            {(["critical", "high", "medium", "low", "informational"] as Severity[]).map((severity) => {
              const findings = severityGroups[severity] || [];
              if (findings.length === 0) return null;
              return (
                <Card key={severity}>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Badge variant={severity}>{severity}</Badge>
                      <span className="text-lg">({findings.length})</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <FindingsTable findings={findings} />
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}

        {activeTab === "service" && (
          <div className="space-y-4">
            {Object.entries(serviceGroups).map(([service, findings]) => (
              <Card key={service}>
                <CardHeader>
                  <CardTitle>{service} ({findings.length})</CardTitle>
                </CardHeader>
                <CardContent>
                  <FindingsTable findings={findings} />
                </CardContent>
              </Card>
            ))}
          </div>
        )}

        {activeTab === "all" && (
          <Card>
            <CardHeader>
              <CardTitle>All Findings ({filteredFindings.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <FindingsTable findings={filteredFindings} />
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}

function FindingsTable({ findings }: { findings: Finding[] }) {
  const getStatusIcon = (status: string | undefined) => {
    switch (status) {
      case "PASS":
        return <CheckCircle className="h-4 w-4 text-green-600" />;
      case "FAIL":
        return <XCircle className="h-4 w-4 text-red-600" />;
      case "SKIP":
        return <SkipForward className="h-4 w-4 text-gray-400" />;
      default:
        return <AlertCircle className="h-4 w-4 text-blue-600" />;
    }
  };

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr className="border-b">
            <th className="text-left p-2">Severity</th>
            <th className="text-left p-2">Status</th>
            <th className="text-left p-2">Check ID</th>
            <th className="text-left p-2">Title</th>
            <th className="text-left p-2">Service</th>
            <th className="text-left p-2">Resource</th>
            <th className="text-left p-2">Region</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding, idx) => (
            <tr key={idx} className="border-b hover:bg-gray-50">
              <td className="p-2">
                  <Badge
                    variant={
                      (finding.severity ?? "informational") as
                        | "critical"
                        | "high"
                        | "medium"
                        | "low"
                        | "informational"
                    }
                  >
                    {finding.severity || "N/A"}
                  </Badge>
                </td>

              <td className="p-2">
                <div className="flex items-center gap-2">
                  {getStatusIcon(finding.status)}
                  <span>{finding.status || "N/A"}</span>
                </div>
              </td>
              <td className="p-2 font-mono text-xs">{finding.check_id || "N/A"}</td>
              <td className="p-2">{finding.check_title || finding.title || "N/A"}</td>
              <td className="p-2">{finding.service || "N/A"}</td>
              <td className="p-2 font-mono text-xs max-w-xs truncate">
                {finding.resource_id || finding.resource_arn || "N/A"}
              </td>
              <td className="p-2">{finding.region || "N/A"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

