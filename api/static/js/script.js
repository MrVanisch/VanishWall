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
        .then(res => res.json().then(data => ({ status: res.status, body: data })))
        .then(({ status, body }) => {
          if (status === 200 && body.status === "success") {
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
            showToast(body.message, "error");
          }
        })
        .catch(() => showToast("Błąd połączenia z serwerem!", "error"))
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
  