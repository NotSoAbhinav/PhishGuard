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

  if (data.result === "phishing") {
    resultDiv.innerHTML = "❌ Phishing Detected";
    resultDiv.style.color = "red";
  } else {
    resultDiv.innerHTML = "✅ Safe URL";
    resultDiv.style.color = "green";
  }

  if (data.reasons) {
    data.reasons.forEach(r => {
      const li = document.createElement("li");
      li.innerText = r;
      reasonsList.appendChild(li);
    });
  }
}