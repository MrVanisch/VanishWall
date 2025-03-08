function showToast(message, type) {
    const toastContainer = document.getElementById("toast-container");

    // Tworzenie powiadomienia
    const toast = document.createElement("div");
    toast.classList.add("toast", type);

    // Ustawienie treści dymka
    toast.innerHTML = `
        <span>${message}</span>
        <button class="close-btn">&times;</button>
    `;

    // Dodanie powiadomienia do kontenera
    toastContainer.appendChild(toast);

    // Obsługa zamknięcia
    toast.querySelector(".close-btn").addEventListener("click", function () {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 500);
    });

    // Automatyczne zamknięcie po 4 sekundach
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 500);
    }, 4000);
}

document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".start-module").forEach(button => {
        button.addEventListener("click", function () {
            let moduleName = this.getAttribute("data-module");
            fetch("/api/module/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ module: moduleName })
            })
            .then(response => response.json())
            .then(data => showToast(data.message, "success"))
            .catch(() => showToast("Błąd uruchamiania modułu", "error"));
        });
    });

    document.querySelectorAll(".stop-module").forEach(button => {
        button.addEventListener("click", function () {
            let moduleName = this.getAttribute("data-module");
            fetch("/api/module/stop", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ module: moduleName })
            })
            .then(response => response.json())
            .then(data => showToast(data.message, "info"))
            .catch(() => showToast("Błąd zatrzymywania modułu", "error"));
        });
    });

    document.addEventListener("DOMContentLoaded", function () {
        document.getElementById("status-acl").addEventListener("click", function () {
            fetchStatus();
        });
    });
    
    function fetchStatus() {
        fetch("/api/modules/status")
            .then(response => response.json())
            .then(data => {
                let statusText = Object.entries(data).map(([key, value]) =>
                    `${key}: ${value ? "🟢 Działa" : "🔴 Zatrzymany"}`
                ).join("<br>");
                document.getElementById("acl-status").innerHTML = statusText;
            })
            .catch(() => showToast("Błąd sprawdzania statusu", "error"));
    }
    
});
