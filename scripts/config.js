// Si tienes la URL del backend como una variable de entorno, puedes usarla
let API_URL = "https://taxisweb.onrender.com";  // URL completa del backend

fetch(`${API_URL}/api/config`)
  .then(res => res.json())
  .then(config => {
    API_URL = config.apiUrl;
    console.log("API URL cargada:", API_URL);
  })
  .catch(err => console.error("Error cargando API_URL:", err));

