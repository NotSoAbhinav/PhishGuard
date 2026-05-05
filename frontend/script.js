async function analyzeURL() {
  const url = document.getElementById("urlInput").value;

  const res = await fetch("http://127.0.0.1:5000/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url })
  });

  const data = await res.json();

  const resultDiv = document.getElementById("result");
  const reasonsList = document.getElementById("reasons");

  reasonsList.innerHTML = "";

  // 🎯 Result + Risk Score
  let color = "green";
  let text = "✅ Safe URL";

  if (data.result === "phishing") {
    color = "red";
    text = "❌ Phishing Detected";
  } else if (data.risk_score > 50) {
    color = "orange";
    text = "⚠️ Suspicious";
  }

  resultDiv.innerHTML = `
    <strong style="color:${color}; font-size:24px;">
      ${text}
    </strong>
    <br/>
    Risk Score: <b>${data.risk_score}%</b>
  `;

  // 🧠 Reasons list
  if (data.reasons && data.reasons.length > 0) {
    data.reasons.forEach(reason => {
      const li = document.createElement("li");
      li.innerText = reason;
      reasonsList.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.innerText = "No major risks detected";
    reasonsList.appendChild(li);
  }
}