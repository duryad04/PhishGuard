// Import necessary modules
import { useEffect, useState } from "react";
import "./App.css"; // Import the CSS file for styling

function App() {
  // State variables
  const [url, setUrl] = useState(""); // Input URL
  const [result, setResult] = useState(null); // Analysis result
  const [history, setHistory] = useState([]); // Scan history
  const [loading, setLoading] = useState(false); // Loading state

  // Function to analyze the URL
  const analyzeUrl = async () => {
    if (!url.trim()) {
      alert("Please enter a URL"); // Alert if URL is empty
      return;
    }

    setLoading(true); // Set loading state
    setResult(null); // Clear previous result

    try {
      // Send POST request to backend for URL analysis
      const response = await fetch("http://127.0.0.1:5000/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url }) // Send URL in request body
      });

      const data = await response.json(); // Parse JSON response

      if (!response.ok) {
        alert(data.error || "Something went wrong"); // Show error if response is not OK
        return;
      }

      setResult(data); // Set analysis result
      setUrl(""); // Clear input field
      fetchHistory(); // Refresh scan history
    } catch (error) {
      alert("Could not connect to backend server"); // Alert if backend is unreachable
    } finally {
      setLoading(false); // Reset loading state
    }
  };

  // Function to fetch scan history
  const fetchHistory = async () => {
    try {
      const response = await fetch("http://127.0.0.1:5000/history"); // GET request to fetch history
      const data = await response.json();
      setHistory(data); // Update history state
    } catch (error) {
      console.log("History fetch failed"); // Log error if fetch fails
    }
  };

  // Function to clear scan history
  const clearHistory = async () => {
    if (!window.confirm("Clear all scan history?")) return; // Confirm before clearing history
    try {
      await fetch("http://127.0.0.1:5000/clear", { method: "DELETE" }); // DELETE request to clear history
      setHistory([]); // Clear history state
      setResult(null); // Clear result state
    } catch (error) {
      alert("Could not connect to backend server"); // Alert if backend is unreachable
    }
  };

  // Fetch history on component mount
  useEffect(() => {
    fetchHistory();
  }, []);

  // Function to get CSS class based on result status
  const getResultClass = (status) => {
    if (status === "Safe") return "safe";
    if (status === "Suspicious") return "suspicious";
    if (status === "Dangerous") return "dangerous";
    return "invalid";
  };

  return (
    <div className="app">
      {/* Main card for URL input and result */}
      <div className="main-card">
        <h1><span style={{color: "#7b49fe"}}>Phish</span><span style={{color: "#5277ec"}}>Guard</span></h1>
        <p className="subtitle" style={{marginTop: "25px"}}>
          A phishing link detection tool that checks URLs for suspicious patterns.
        </p>

        {/* Input box for URL */}
        <div className="input-box">
          <input
            type="text"
            placeholder="Paste suspicious URL here..."
            value={url}
            onChange={(e) => setUrl(e.target.value)} // Update URL state on input change
            onKeyDown={(e) => e.key === "Enter" && analyzeUrl()} // Trigger analysis on Enter key
          />
          <button onClick={analyzeUrl} disabled={loading}>
            {loading ? "Scanning..." : "Scan URL"} {/* Show loading state */}
          </button>
        </div>

        {/* Display analysis result */}
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
                <li key={index}>{reason}</li> // Display reasons for risk score
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* History card for recent scans */}
      <div className="history-card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h2>Recent Scan History</h2>
          <button onClick={clearHistory} style={{
            background: "#c0392b", color: "white", border: "none",
            padding: "6px 14px", borderRadius: "6px", cursor: "pointer", fontSize: "14px"
          }}>
            Clear History
          </button>
        </div>

        {/* Display scan history */}
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