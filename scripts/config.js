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
