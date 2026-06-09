import { useEffect, useState } from "react";

type Tab = "system" | "logs" | "graphs" | "config" | "files";

interface TsFile {
  id: string;
  filename: string;
  size_bytes: number;
  status: string;
  uploaded_at: string;
}

const TABS: { id: Tab; label: string }[] = [
  { id: "system", label: "System Info" },
  { id: "logs", label: "Log Files" },
  { id: "graphs", label: "Graphs" },
  { id: "config", label: "Config" },
  { id: "files", label: "My Files" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("files");
  const [files, setFiles] = useState<TsFile[]>([]);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = () =>
    fetch("/api/v1/files")
      .then((r) => r.json())
      .then((d) => setFiles(d.files ?? []))
      .catch(() => setError("API unreachable"));

  useEffect(() => {
    refresh();
  }, []);

  const upload = async (f: File) => {
    setUploading(true);
    setError(null);
    const body = new FormData();
    body.append("file", f);
    const res = await fetch("/api/v1/files", { method: "POST", body });
    if (!res.ok) setError((await res.json()).error ?? "upload failed");
    setUploading(false);
    refresh();
  };

  const del = async (id: string) => {
    await fetch(`/api/v1/files/${id}`, { method: "DELETE" });
    refresh();
  };

  return (
    <div className="layout">
      <aside className="sidebar">
        <h1>PAN-TS</h1>
        {TABS.map((t) => (
          <button
            key={t.id}
            className={tab === t.id ? "active" : ""}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </aside>

      <main className="content">
        {tab === "files" && (
          <section>
            <h2>Tech-Support Files</h2>
            <label className="upload">
              {uploading ? "Uploading…" : "Upload .tgz"}
              <input
                type="file"
                accept=".tgz,.tar.gz"
                hidden
                onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])}
              />
            </label>
            {error && <p className="error">{error}</p>}
            <table>
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>Size</th>
                  <th>Status</th>
                  <th>Uploaded</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {files.map((f) => (
                  <tr key={f.id}>
                    <td>{f.filename}</td>
                    <td>{(f.size_bytes / 1024 / 1024).toFixed(1)} MB</td>
                    <td>{f.status}</td>
                    <td>{new Date(f.uploaded_at).toLocaleString()}</td>
                    <td>
                      <button onClick={() => del(f.id)}>Delete</button>
                    </td>
                  </tr>
                ))}
                {files.length === 0 && (
                  <tr>
                    <td colSpan={5}>No files uploaded yet.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </section>
        )}
        {tab === "system" && <Placeholder name="System Info" phase={3} />}
        {tab === "logs" && <Placeholder name="Log Files" phase={4} />}
        {tab === "graphs" && <Placeholder name="Graphs" phase={5} />}
        {tab === "config" && <Placeholder name="Config" phase={6} />}
      </main>
    </div>
  );
}

function Placeholder({ name, phase }: { name: string; phase: number }) {
  return (
    <section>
      <h2>{name}</h2>
      <p>Coming in phase {phase}.</p>
    </section>
  );
}
