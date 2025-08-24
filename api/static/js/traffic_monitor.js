console.log('🚀 Traffic Monitor JS loading...');

document.addEventListener('DOMContentLoaded', function() {
    console.log('✅ DOM loaded, initializing Traffic Monitor');
    
    // Elementy DOM
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn'); 
    const restartBtn = document.getElementById('restart-btn');
    const refreshBtn = document.getElementById('refresh-btn');
    const alertsList = document.getElementById('recent-alerts');
    
    let alertChart, serviceChart;

    // Sprawdź dostępność elementów
    console.log('🔍 Elements check:', {
        startBtn: !!startBtn,
        stopBtn: !!stopBtn,
        restartBtn: !!restartBtn,
        refreshBtn: !!refreshBtn,
        alertsList: !!alertsList,
        chartJs: typeof Chart !== 'undefined'
    });

    // Funkcja aktualizacji kart - NAPRAWIONA
    function updateCards(data) {
        console.log('📊 Updating cards with data:', data);
        
        const mappings = {
            'monitoring_active': data => data ? '🟢 Aktywny' : '🔴 Nieaktywny',
            'uptime_seconds': data => Math.floor(data || 0).toLocaleString(),
            'total_packets': data => (data || 0).toLocaleString(),
            'total_mb': data => (data || 0).toFixed(2),
            'active_services': data => data || 0,
            'monitored_ips': data => data || 0,
            'recent_alerts': data => data || 0
        };

        Object.entries(mappings).forEach(([key, formatter]) => {
            const element = document.querySelector(`[data-key="${key}"]`);
            if (element) {
                const newValue = formatter(data[key]);
                element.textContent = newValue;
                console.log(`✓ Updated ${key}: ${newValue}`);
            } else {
                console.warn(`⚠️ Element not found for key: ${key}`);
            }
        });
    }

    // Funkcja renderowania wykresów - NAPRAWIONA
    function renderCharts(data) {
        console.log('📈 Rendering charts with data:', data);
        
        // Alert breakdown chart
        const alertCtx = document.getElementById('alert-breakdown-chart');
        if (alertCtx && typeof Chart !== 'undefined') {
            try {
                const breakdown = data.alert_breakdown || {};
                console.log('📊 Alert breakdown data:', breakdown);
                
                let labels = Object.keys(breakdown);
                let values = Object.values(breakdown);
                
                // Jeśli brak alertów, pokaż komunikat
                if (labels.length === 0 || values.every(v => v === 0)) {
                    labels = ['Brak alertów'];
                    values = [1];
                    
                    // Zniszcz poprzedni wykres
                    if (alertChart) {
                        alertChart.destroy();
                    }
                    
                    alertChart = new Chart(alertCtx, {
                        type: 'doughnut',
                        data: {
                            labels: labels,
                            datasets: [{
                                data: values,
                                backgroundColor: ['#E8F5E8']
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    position: 'bottom'
                                },
                                tooltip: {
                                    enabled: false
                                }
                            }
                        }
                    });
                } else {
                    // Zniszcz poprzedni wykres
                    if (alertChart) {
                        alertChart.destroy();
                    }
                    
                    alertChart = new Chart(alertCtx, {
                        type: 'doughnut',
                        data: {
                            labels: labels,
                            datasets: [{
                                data: values,
                                backgroundColor: [
                                    '#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', 
                                    '#FFEAA7', '#DDA0DD', '#98D8C8', '#F7DC6F'
                                ]
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    position: 'bottom'
                                }
                            }
                        }
                    });
                }
                console.log('✅ Alert chart created');
            } catch (error) {
                console.error('❌ Error creating alert chart:', error);
            }
        }

        // Services chart - NAPRAWIONA
        const servicesCtx = document.getElementById('top-services-chart');
        if (servicesCtx && typeof Chart !== 'undefined') {
            try {
                const services = data.top_services || [];
                console.log('📊 Services data:', services);
                
                let labels = [];
                let values = [];
                
                if (services.length > 0) {
                    labels = services.map(s => s.service || 'Unknown');
                    values = services.map(s => s.packets || 0);
                } else {
                    labels = ['Brak aktywnych usług'];
                    values = [0];
                }

                // Zniszcz poprzedni wykres
                if (serviceChart) {
                    serviceChart.destroy();
                }
                
                serviceChart = new Chart(servicesCtx, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: services.length > 0 ? 'Pakiety' : '',
                            data: values,
                            backgroundColor: services.length > 0 ? '#4ECDC4' : '#E8F5E8',
                            borderColor: services.length > 0 ? '#26A69A' : '#C8E6C9',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        indexAxis: 'y',
                        plugins: {
                            legend: {
                                display: services.length > 0
                            },
                            tooltip: {
                                enabled: services.length > 0
                            }
                        },
                        scales: {
                            x: {
                                beginAtZero: true,
                                display: services.length > 0
                            },
                            y: {
                                display: true
                            }
                        }
                    }
                });
                console.log('✅ Services chart created');
            } catch (error) {
                console.error('❌ Error creating services chart:', error);
            }
        }
    }

    // Funkcja aktualizacji alertów - NAPRAWIONA
    function updateAlerts(alertCount, breakdown) {
        if (!alertsList) {
            console.warn('⚠️ Alerts list element not found');
            return;
        }
        
        console.log(`🚨 Updating alerts: count=${alertCount}`, breakdown);
        
        if (!alertCount || alertCount === 0) {
            alertsList.innerHTML = `
                <li class="list-group-item text-center py-4">
                    <i class="fas fa-check-circle fa-2x text-success mb-2"></i>
                    <p class="mb-0 text-success">Brak alertów w ostatnich 60 minutach</p>
                    <small class="text-muted">System działa normalnie</small>
                </li>
            `;
        } else {
            let breakdownHtml = '';
            if (breakdown && typeof breakdown === 'object') {
                const entries = Object.entries(breakdown);
                console.log('🔍 Processing breakdown entries:', entries);
                
                entries.forEach(([type, count]) => {
                    if (count > 0) {
                        const badgeClass = {
                            'port scan': 'danger',
                            'dos attack': 'danger', 
                            'syn flood': 'warning',
                            'brute force': 'warning',
                            'http traffic': 'info',
                            'https traffic': 'primary',
                            'ssh access': 'secondary',
                            'http': 'info',
                            'https': 'primary',
                            'ssh': 'secondary'
                        }[type.toLowerCase()] || 'primary';
                        
                        breakdownHtml += `
                            <div class="d-flex justify-content-between align-items-center mb-1">
                                <span class="text-capitalize">${type}:</span>
                                <span class="badge bg-${badgeClass}">${count}</span>
                            </div>
                        `;
                    }
                });
            }
            
            alertsList.innerHTML = `
                <li class="list-group-item">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <strong class="text-primary">Ostatnie 60 minut</strong>
                        <span class="badge bg-primary rounded-pill">${alertCount}</span>
                    </div>
                    <div class="mt-2">
                        ${breakdownHtml || '<em class="text-muted">Wykryto aktywność sieciową</em>'}
                    </div>
                </li>
            `;
        }
    }

    // Główna funkcja ładowania danych - NAPRAWIONA
    function loadData() {
        console.log('🔄 Loading traffic monitor data...');
        
        // Spinner na przycisku refresh
        if (refreshBtn) {
            const icon = refreshBtn.querySelector('i');
            if (icon) {
                icon.classList.add('fa-spin');
            }
            refreshBtn.disabled = true;
        }
        
        fetch('/api/traffic_monitor/summary')
            .then(response => {
                console.log(`📡 API Response: ${response.status} ${response.statusText}`);
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response.json();
            })
            .then(response => {
                console.log('📊 Raw API response:', response);
                
                // Obsługa różnych formatów odpowiedzi
                let data;
                if (response.data) {
                    // Format: {"status": "success", "data": {...}}
                    data = response.data;
                } else if (response.status === 'success') {
                    // Format: {"status": "success", "monitoring_active": ..., ...}
                    data = response;
                } else {
                    throw new Error('Invalid response format');
                }
                
                console.log('📊 Processed data:', data);
                
                // Aktualizuj wszystkie komponenty
                updateCards(data);
                renderCharts(data);
                updateAlerts(data.recent_alerts || 0, data.alert_breakdown || {});
                
                console.log('✅ Data update completed');
            })
            .catch(error => {
                console.error('❌ Error loading traffic data:', error);
                
                // Pokaż błąd w interfejsie
                if (alertsList) {
                    alertsList.innerHTML = `
                        <li class="list-group-item text-center py-4">
                            <i class="fas fa-exclamation-triangle fa-2x text-danger mb-2"></i>
                            <p class="mb-1 text-danger">Błąd połączenia z API</p>
                            <small class="text-muted">${error.message}</small>
                            <div class="mt-2">
                                <button class="btn btn-sm btn-outline-primary" onclick="loadData()">
                                    Spróbuj ponownie
                                </button>
                            </div>
                        </li>
                    `;
                }
                
                // Pokaż błąd w kartach
                const errorData = {
                    monitoring_active: false,
                    uptime_seconds: 0,
                    total_packets: 0,
                    total_mb: 0,
                    active_services: 0,
                    monitored_ips: 0,
                    recent_alerts: 0,
                    alert_breakdown: {},
                    top_services: []
                };
                updateCards(errorData);
                renderCharts(errorData);
            })
            .finally(() => {
                // Usuń spinner
                if (refreshBtn) {
                    const icon = refreshBtn.querySelector('i');
                    if (icon) {
                        icon.classList.remove('fa-spin');
                    }
                    refreshBtn.disabled = false;
                }
                console.log('🏁 Load data completed');
            });
    }

    // Funkcja wykonywania akcji (start/stop/restart) - BEZ ZMIAN
    function performAction(action) {
        console.log(`🎬 Performing action: ${action}`);
        
        const buttons = { 
            start: startBtn, 
            stop: stopBtn, 
            restart: restartBtn 
        };
        const button = buttons[action];
        
        if (!button) {
            console.error(`❌ Button not found for action: ${action}`);
            return;
        }
        
        // Pokaż loading state
        const originalHtml = button.innerHTML;
        const originalDisabled = button.disabled;
        
        button.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Ładowanie...';
        button.disabled = true;
        
        fetch(`/api/traffic_monitor/${action}`, { 
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            console.log(`📡 Action ${action} response: ${response.status}`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(result => {
            console.log(`✅ Action ${action} result:`, result);
            
            // Pokaż komunikat o sukcesie/błędzie
            if (result.success) {
                console.log(`✅ ${result.message}`);
            } else {
                console.warn(`⚠️ ${result.message}`);
            }
            
            // Poczekaj chwilę i odśwież dane
            setTimeout(() => {
                loadData();
            }, 1500);
        })
        .catch(error => {
            console.error(`❌ Action ${action} error:`, error);
            alert(`Błąd wykonania akcji ${action}: ${error.message}`);
        })
        .finally(() => {
            // Przywróć przycisk
            button.innerHTML = originalHtml;
            button.disabled = originalDisabled;
        });
    }

    // Event listeners - BEZ ZMIAN
    if (startBtn) {
        startBtn.addEventListener('click', () => performAction('start'));
        console.log('✓ Start button listener attached');
    }
    
    if (stopBtn) {
        stopBtn.addEventListener('click', () => performAction('stop'));
        console.log('✓ Stop button listener attached');
    }
    
    if (restartBtn) {
        restartBtn.addEventListener('click', () => performAction('restart'));
        console.log('✓ Restart button listener attached');
    }
    
    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadData);
        console.log('✓ Refresh button listener attached');
    }

    // Udostępnij funkcje globalnie dla debugging
    window.loadData = loadData;
    window.performAction = performAction;
    window.updateCards = updateCards;
    window.renderCharts = renderCharts;
    window.updateAlerts = updateAlerts;

    // Początkowe załadowanie danych
    console.log('🚀 Starting initial data load...');
    loadData();
    
    // Auto-refresh co 15 sekund
    const refreshInterval = setInterval(loadData, 15000);
    console.log('⏰ Auto-refresh set to 15 seconds');
    
    // Cleanup przy unload
    window.addEventListener('beforeunload', () => {
        if (refreshInterval) {
            clearInterval(refreshInterval);
        }
        if (alertChart) alertChart.destroy();  
        if (serviceChart) serviceChart.destroy();
    });
    
    console.log('🎉 Traffic Monitor fully initialized!');
});

console.log('📁 Traffic Monitor JS file loaded');