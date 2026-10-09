(function () {
  var node = document.getElementById("stats-data");
  if (!node || typeof Chart === "undefined") return;
  var stats = JSON.parse(node.textContent);
  Chart.defaults.color = "#8fa3c7";
  Chart.defaults.borderColor = "#223152";

  var sev = stats.by_severity;
  new Chart(document.getElementById("sevChart"), {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{
        data: [sev.Critical, sev.High, sev.Medium, sev.Low],
        backgroundColor: ["#be123c", "#ea580c", "#ca8a04", "#475569"],
        borderWidth: 0
      }]
    },
    options: { plugins: { legend: { position: "bottom" } } }
  });

  new Chart(document.getElementById("trendChart"), {
    type: "bar",
    data: {
      labels: stats.trend.map(function (t) { return t.hour.replace("T", " ") + ":00"; }),
      datasets: [{ label: "Alerts", data: stats.trend.map(function (t) { return t.count; }), backgroundColor: "#22d3ee" }]
    },
    options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
  });
})();
