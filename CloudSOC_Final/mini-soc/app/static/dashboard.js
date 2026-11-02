(() => {
  const $ = (id) => document.getElementById(id);
  const fmt = (n) => Number(n).toLocaleString();
  const hhmm = (iso) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const hhmmss = (iso) => new Date(iso).toLocaleTimeString([], { hour12: false });
  let timelineChart = null;
  let countryChart = null;

  function initCharts() {
    Chart.defaults.color = "#94a3b8";
    Chart.defaults.borderColor = "#1e293b";
    timelineChart = new Chart($("timelineChart"), {
      type: "line",
      data: { labels: [], datasets: [{
        label: "Failed logins per minute", data: [],
        borderColor: "#ff3366", backgroundColor: "rgba(255,51,102,.14)",
        fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2,
      }] },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { ticks: { maxTicksLimit: 8 } } },
      },
    });
    countryChart = new Chart($("countryChart"), {
      type: "doughnut",
      data: { labels: [], datasets: [{
        data: [], borderColor: "#0f172a", borderWidth: 2,
        backgroundColor: ["#00d2ff", "#ff3366", "#10b981", "#f59e0b", "#a78bfa", "#38bdf8", "#fb7185", "#94a3b8"],
      }] },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        plugins: { legend: { position: "right", labels: { boxWidth: 12 } } },
      },
    });
  }

  // textContent only: attacker-controlled strings can never inject HTML
  function cell(text, cls) {
    const td = document.createElement("td");
    td.textContent = text;
    if (cls) td.className = cls;
    return td;
  }
  function badge(text, cls) {
    const td = document.createElement("td");
    const span = document.createElement("span");
    span.className = "badge " + cls;
    span.textContent = text;
    td.appendChild(span);
    return td;
  }
  function fill(tbodyId, rows, build, cols) {
    const tbody = $(tbodyId);
    tbody.replaceChildren();
    if (!rows.length) {
      const tr = document.createElement("tr");
      const td = cell("No attempts recorded yet. Send a few failed logins to the honeypot to see data here.", "muted");
      td.colSpan = cols;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    rows.forEach((r) => tbody.appendChild(build(r)));
  }

  function render(d) {
    $("kpi-total").textContent = fmt(d.totals.attempts);
    $("kpi-hour").textContent = fmt(d.totals.last_hour);
    $("kpi-unique").textContent = fmt(d.totals.unique_ips);
    $("kpi-blocks").textContent = fmt(d.totals.active_blocks);
    $("kpi-denied").textContent = fmt(d.totals.denied_requests);

    if (timelineChart && countryChart) {   // charts are optional: tables and KPIs must work without the CDN
      timelineChart.data.labels = d.timeline.labels.map(hhmm);
      timelineChart.data.datasets[0].data = d.timeline.values;
      timelineChart.update();
      countryChart.data.labels = d.countries.map((c) => c.country);
      countryChart.data.datasets[0].data = d.countries.map((c) => c.count);
      countryChart.update();
    }

    fill("top-ips", d.top_ips, (r) => {
      const tr = document.createElement("tr");
      tr.append(cell(r.ip, "ip"), cell(r.country), cell(fmt(r.count), "num"),
                r.blocked ? badge("BLOCKED", "red") : badge("WATCHING", "amber"));
      return tr;
    }, 4);

    fill("recent", d.recent, (r) => {
      const tr = document.createElement("tr");
      tr.append(cell(hhmmss(r.time), "mono muted"), cell(r.ip, "ip"), cell(r.country),
                cell(r.username || "(empty)", "mono"), cell(r.password_hint, "mono muted"),
                cell(r.user_agent || "-", "muted"));
      return tr;
    }, 6);
  }

  async function refresh() {
    const status = $("status");
    try {
      const res = await fetch("/admin/api/stats", { credentials: "same-origin" });
      if (res.status === 401) { window.location.href = "/admin/login"; return; }
      if (!res.ok) throw new Error("HTTP " + res.status);
      render(await res.json());
      status.textContent = "IDS AGENT ONLINE, updated " + new Date().toLocaleTimeString([], { hour12: false });
      status.className = "pill live";
    } catch (err) {
      status.textContent = "Connection lost, retrying";
      status.className = "pill down";
    }
  }

  if (typeof Chart !== "undefined") {
    initCharts();
  } else {
    document.querySelectorAll(".chart-box").forEach((box) => {
      box.textContent = "Charts could not be loaded (check the internet connection). Tables and counters still work.";
      box.className = "chart-box muted";
    });
  }
  refresh();
  setInterval(refresh, 5000);
})();
