// Define la URL base
let API_URL = "https://taxisweb.onrender.com/api";  // URL completa del backend

fetch(`${API_URL}/config`)
  .then(res => res.json())
  .then(config => {
    const backendAPIUrl = config.apiUrl; // Usamos una variable diferente para almacenar la URL
    console.log("API URL cargada:", backendAPIUrl);
    // Aquí puedes hacer lo que necesites con backendAPIUrl
  })
  .catch(err => console.error("Error cargando API_URL:", err));

// Helper function to add authentication headers
function getAuthHeaders() {
    const token = localStorage.getItem('token');
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
    };
}

// Example of protected API call
async function fetchProtectedData(endpoint) {
    const response = await fetch(`${API_URL}${endpoint}`, {
        headers: getAuthHeaders()
    });
    if (response.status === 401) {
        // Token expired or invalid
        window.location.href = '/login.html';
        return;
    }
    return response.json();
}
