"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Cloud, Key, Shield } from "lucide-react";

const AVAILABLE_FRAMEWORKS = [
  "SOC 2",
  "ISO 27001",
  "NIST 800-53",
  "CIS AWS Foundations",
  "CIS Azure",
  "CIS GCP",
];

export default function IntakePage() {
  const router = useRouter();
  const [provider, setProvider] = useState<"aws" | "gcp" | "azure">("aws");
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
  const [sessionToken, setSessionToken] = useState("");
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([]);

  // Load from localStorage on mount
  useEffect(() => {
    const saved = localStorage.getItem("cs_kit_intake");
    if (saved) {
      try {
        const data = JSON.parse(saved);
        setProvider(data.provider || "aws");
        setSelectedFrameworks(data.frameworks || []);
      } catch (e) {
        // Ignore parse errors
      }
    }
  }, []);

  const toggleFramework = (framework: string) => {
    if (selectedFrameworks.includes(framework)) {
      setSelectedFrameworks(selectedFrameworks.filter((f) => f !== framework));
    } else {
      setSelectedFrameworks([...selectedFrameworks, framework]);
    }
  };

  const handleContinue = () => {
    if (typeof window === "undefined") return;

    // Save to localStorage
    const intakeData = {
      provider,
      frameworks: selectedFrameworks,
      // Note: credentials are NOT saved - demo only
    };
    localStorage.setItem("cs_kit_intake", JSON.stringify(intakeData));

    // Store credentials in session storage (cleared on new tab/session)
    sessionStorage.setItem(
      "cs_kit_credentials",
      JSON.stringify({
        accessKeyId,
        secretAccessKey,
        sessionToken,
      }),
    );

    // Navigate to report page
    router.push("/report");
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">
            CS Kit Security Scanner
          </h1>
          <p className="text-gray-600">
            Configure your cloud security compliance scan
          </p>
        </div>

        <div className="space-y-6">
          {/* Environment Selection */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Cloud className="h-5 w-5" />
                <CardTitle>Cloud Environment</CardTitle>
              </div>
              <CardDescription>
                Select the cloud provider you want to scan
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-4">
                {(["aws", "gcp", "azure"] as const).map((p) => (
                  <Button
                    key={p}
                    variant={provider === p ? "default" : "outline"}
                    onClick={() => setProvider(p)}
                    className="flex-1"
                  >
                    {p.toUpperCase()}
                  </Button>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Credentials */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Key className="h-5 w-5" />
                <CardTitle>Access Credentials</CardTitle>
              </div>
              <CardDescription>
                Demo only — don&apos;t paste real secrets. Scanning is not performed here.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3 text-sm text-yellow-800">
                <strong>Security Note:</strong> These credentials are stored client-side only
                and never transmitted to any server. This is a demo interface.
              </div>
              <div>
                <Label htmlFor="access-key-id">Access Key ID</Label>
                <Input
                  id="access-key-id"
                  type="text"
                  value={accessKeyId}
                  onChange={(e) => setAccessKeyId(e.target.value)}
                  placeholder="AKIA..."
                  className="mt-1"
                />
              </div>
              <div>
                <Label htmlFor="secret-access-key">Secret Access Key</Label>
                <Textarea
                  id="secret-access-key"
                  value={secretAccessKey}
                  onChange={(e) => setSecretAccessKey(e.target.value)}
                  placeholder="Enter secret key..."
                  className="mt-1 font-mono text-xs"
                  rows={3}
                />
              </div>
              {provider === "aws" && (
                <div>
                  <Label htmlFor="session-token">Session Token (Optional)</Label>
                  <Textarea
                    id="session-token"
                    value={sessionToken}
                    onChange={(e) => setSessionToken(e.target.value)}
                    placeholder="Enter session token if using temporary credentials..."
                    className="mt-1 font-mono text-xs"
                    rows={2}
                  />
                </div>
              )}
            </CardContent>
          </Card>

          {/* Frameworks */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                <CardTitle>Compliance Frameworks</CardTitle>
              </div>
              <CardDescription>
                Select one or more frameworks to scan against
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-3">
                {AVAILABLE_FRAMEWORKS.map((framework) => (
                  <Button
                    key={framework}
                    variant={selectedFrameworks.includes(framework) ? "default" : "outline"}
                    onClick={() => toggleFramework(framework)}
                    className="justify-start"
                  >
                    {framework}
                  </Button>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Continue Button */}
          <div className="flex justify-end">
            <Button
              onClick={handleContinue}
              disabled={selectedFrameworks.length === 0}
              size="lg"
              className="px-8"
            >
              Continue to Report
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

