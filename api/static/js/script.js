document.addEventListener("DOMContentLoaded", () => {
    let activeModules = [];
  
    // ========== Toasty ==========
    function showToast(message, type = "success") {
      const toastContainer = document.getElementById("toast-container");
  
      const toast = document.createElement("div");
      toast.className = `toast ${type}`;
      toast.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check' : type === 'error' ? 'exclamation' : 'info'}-circle toast-icon"></i>
        <span>${message}</span>
        <button class="close-btn"><i class="fas fa-times"></i></button>
      `;
  
      toastContainer.appendChild(toast);
  
      toast.querySelector(".close-btn").addEventListener("click", () => toast.remove());
  
      setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 500);
      }, 4000);
    }
    window.showToast = showToast;  
    // ========== Wysyłanie żądania do API ==========
    function sendRequest(url, moduleName) {
      const button = document.querySelector(`[data-module="${moduleName}"]`);
      if (button) button.disabled = true;
    
      fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: moduleName })
      })
        .then(async res => {
          const isJson = res.headers.get("content-type")?.includes("application/json");
          const body = isJson ? await res.json() : {};
    
          // Obsługa 403 - brak uprawnień
          if (res.status === 403) {
            showToast(body.message || "Brak uprawnień do wykonania tej operacji!", "error");
            throw new Error("403 Forbidden");
          }
    
          if (res.status === 200 && body.status === "success") {
            // 🔄 Dobieranie typu powiadomienia w zależności od akcji
            let toastType = "success";
            if (url.includes("stop_module")) toastType = "error";
            if (url.includes("restart_module")) toastType = "warning";
    
            showToast(body.message, toastType);
    
            if (url.includes("start_module")) activeModules.push(moduleName);
            if (url.includes("stop_module")) activeModules = activeModules.filter(m => m !== moduleName);
    
            updateModuleStatuses();
            updateCounters();
          } else {
            showToast(body.message || "Nieznany błąd!", "error");
          }
        })
        .catch(error => {
          console.error("Błąd:", error);
          if (error.message !== "403 Forbidden") {
            showToast("Błąd połączenia z serwerem!", "error");
          }
        })
        .finally(() => {
          if (button) button.disabled = false;
        });
    }
  
    // ========== Aktualizacja statusów ==========
    function updateModuleStatuses() {
      document.querySelectorAll(".module-item").forEach(moduleItem => {
        const name = moduleItem.dataset.module;
        const status = document.getElementById(`status-${name}`);
        const isActive = activeModules.includes(name);
  
        status.textContent = isActive ? "Aktywny" : "Nieaktywny";
        status.className = "module-status " + (isActive ? "status-active" : "status-inactive");
  
        moduleItem.classList.toggle("inactive", !isActive);
      });
    }
  
    function updateCounters() {
      const total = document.querySelectorAll(".module-item").length;
      document.getElementById("active-modules-count").textContent = activeModules.length;
      document.getElementById("inactive-modules-count").textContent = total - activeModules.length;
    }
  
    // ========== Obsługa kliknięć start/stop ==========
    document.querySelectorAll(".start-module").forEach(btn =>
      btn.addEventListener("click", () => sendRequest("/start_module", btn.dataset.module))
    );
  
    document.querySelectorAll(".stop-module").forEach(btn =>
      btn.addEventListener("click", () => sendRequest("/stop_module", btn.dataset.module))
    );
  
    // ========== Status ACL ==========
    const statusButton = document.getElementById("status-acl");
    if (statusButton) {
      statusButton.addEventListener("click", () => {
        statusButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Ładowanie...';
  
        fetch("/list_modules")
          .then(res => res.json())
          .then(data => {
            activeModules = data.active_modules || [];
            updateModuleStatuses();
            updateCounters();
  
            const statusBox = document.getElementById("acl-status");
            if (activeModules.length) {
              statusBox.innerHTML = `<i class="fas fa-check-circle text-success"></i> Aktywne moduły: <strong>${activeModules.join(", ")}</strong>`;
            } else {
              statusBox.innerHTML = `<i class="fas fa-exclamation-circle text-warning"></i> Brak aktywnych modułów`;
            }
  
            showToast("Status modułów zaktualizowany", "info");
          })
          .catch(() => showToast("Błąd połączenia z serwerem!", "error"))
          .finally(() => {
            statusButton.innerHTML = '<i class="fas fa-sync-alt"></i> Odśwież status modułów';
          });
      });
  
      // Automatyczne załadowanie przy starcie
      statusButton.click();
    }
  
    // ========== CPU / RAM ==========
    function updateSystemStatus() {
      fetch("/api/system_status")
        .then(res => res.json())
        .then(data => {
          const cpu = data.cpu;
          const mem = data.memory;
  
          updateProgressBar(".fa-microchip", cpu);
          updateProgressBar(".fa-memory", mem);
        })
        .catch(() => console.warn("Nie udało się pobrać danych systemowych."));
    }
  
    function updateProgressBar(selector, value) {
      const bar = document.querySelector(selector)?.closest("div")?.querySelector(".progress-bar");
      if (!bar) return;
  
      let color = 'bg-success';
      if (value > 80) color = 'bg-danger';
      else if (value > 50) color = 'bg-warning';
  
      bar.className = 'progress-bar ' + color;
      bar.style.width = value + "%";
      bar.textContent = Math.round(value) + "%";
    }
  
    updateSystemStatus();
    setInterval(updateSystemStatus, 5000);
  });


  
// Lista modułów z ustawieniami
const configurableModules = [
  'bandwidth_limiter',
  'syn_flood',
  'udp_flood',
  'dns_ampl',
  'ntp_ampl',
  'bypass_protection',
  'traffic_monitor',
  'AI.ai_traffic_monitor'
];

// Otwieranie dynamicznego modala
function openSettingsModal(module) {
  fetch(`/get_${module}_settings`)
    .then(res => res.json())
    .then(data => {
      const modal = document.getElementById("dynamicModal");
      const form = document.getElementById("dynamicForm");
      const title = document.getElementById("modal-title");

      // Debug
      console.log("🔧 Odpowiedź z backendu:", data);

      title.textContent = data.title || `Ustawienia: ${module}`;
      form.innerHTML = "";  // Wyczyść poprzednie pola

      const fields = Array.isArray(data.fields) ? data.fields : [];

      fields.forEach(field => {
        const label = document.createElement("label");
        label.setAttribute("for", field.id);
        label.textContent = field.label;

        const input = document.createElement("input");
        input.type = field.type || "text";
        input.id = field.id;
        input.name = field.id;
        input.className = "form-control mb-2";
        input.value = field.value ?? "";  // Obsługa null/undefined

        form.appendChild(label);
        form.appendChild(input);
      });

      // ✅ Zawsze dodaj przycisk ZAPISZ (nawet jeśli brak pól)
      const submitBtn = document.createElement("button");
      submitBtn.type = "submit";
      submitBtn.className = "btn btn-primary mt-2";
      submitBtn.textContent = "ZAPISZ";
      form.appendChild(submitBtn);

      // Obsługa zapisu formularza
      form.onsubmit = function (e) {
        e.preventDefault();
        const payload = {};
        fields.forEach(field => {
          payload[field.id] = document.getElementById(field.id)?.value ?? "";
        });

        fetch(`/update_${module}_settings`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        })
          .then(res => res.json())
          .then(resp => {
            showToast("Zapisano ustawienia", "success");
            modal.style.display = "none";
          })
          .catch(() => showToast("Błąd zapisu ustawień!", "error"));
      };

      modal.style.display = "block";
    })
    .catch(err => {
      console.error("❌ Błąd danych z backendu:", err);
      alert("❌ Nie udało się pobrać ustawień dla: " + module);
    });
}

function closeDynamicModal() {
  document.getElementById("dynamicModal").style.display = "none";
}

// log 
document.getElementById("clearLog").addEventListener("click", async () => {
    const type = document.getElementById("logType").value;
    if (!confirm("Czy na pewno chcesz wyczyścić log " + type + "?")) return;

    const response = await fetch(`/api/logs/${type}/clear`, {
        method: "POST"
    });

    const result = await response.json();
    alert(result.message || "Wyczyszczono.");
    loadLog();  // przeładuj widok
});

async function blockIPManual() {
    const ip = document.getElementById("manualIP").value;
    const duration = document.getElementById("manualDuration").value || 60;

    if (!ip) {
        alert("Wprowadź adres IP.");
        return;
    }

    const response = await fetch("/api/block_ip_manual", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, duration })
    });

    const result = await response.json();
    alert(result.message || "Gotowe.");
}

let autoRefreshTimer = null;

function manageAutoRefresh() {
  const enabled = document.getElementById("autoRefresh").checked;
  const interval = parseInt(document.getElementById("refreshInterval").value) * 1000;

  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }

  if (enabled && interval >= 3000) {
    autoRefreshTimer = setInterval(() => {
      loadLog();
    }, interval);
  }
}

// Eventy
document.getElementById("autoRefresh").addEventListener("change", manageAutoRefresh);
document.getElementById("refreshInterval").addEventListener("input", manageAutoRefresh);