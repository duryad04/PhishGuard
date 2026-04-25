import { useEffect, useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  const analyzeUrl = async () => {
    if (!url.trim()) {
      alert("Please enter a URL");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const response = await fetch("http://127.0.0.1:5000/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url })
      });

      const data = await response.json();

      if (!response.ok) {
        alert(data.error || "Something went wrong");
        return;
      }

      setResult(data);
      setUrl("");
      fetchHistory();
    } catch (error) {
      alert("Could not connect to backend server");
    } finally {
      setLoading(false);
    }
  };

  const fetchHistory = async () => {
    try {
      const response = await fetch("http://127.0.0.1:5000/history");
      const data = await response.json();
      setHistory(data);
    } catch (error) {
      console.log("History fetch failed");
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const getResultClass = (status) => {
    if (status === "Safe") return "safe";
    if (status === "Suspicious") return "suspicious";
    if (status === "Dangerous") return "dangerous";
    return "invalid";
  };

  return (
    <div className="app">
      <div className="main-card">
        <h1>PhishGuard</h1>
        <p className="subtitle">
          A phishing link detection tool that checks URLs for suspicious patterns.
        </p>

        <div className="input-box">
          <input
            type="text"
            placeholder="Paste suspicious URL here..."
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button onClick={analyzeUrl} disabled={loading}>
            {loading ? "Scanning..." : "Scan URL"}
          </button>
        </div>

        {result && (
          <div className={`result-card ${getResultClass(result.result)}`}>
            <h2>{result.result}</h2>
            <p>
              <strong>Risk Score:</strong> {result.risk_score}/100
            </p>
            <p>
              <strong>Scanned URL:</strong> {result.url}
            </p>

            <h3>Reasons:</h3>
            <ul>
              {result.reasons.map((reason, index) => (
                <li key={index}>{reason}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <div className="history-card">
        <h2>Recent Scan History</h2>

        {history.length === 0 ? (
          <p>No scans yet.</p>
        ) : (
          <div className="history-list">
            {history.map((item) => (
              <div key={item.id} className="history-item">
                <div>
                  <strong>{item.result}</strong>
                  <p>{item.url}</p>
                  <small>{item.scanned_at}</small>
                </div>
                <span className={getResultClass(item.result)}>
                  {item.risk_score}/100
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;