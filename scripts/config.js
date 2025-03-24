require('dotenv').config();  // Cargar variables de entorno desde .env

let API_URL = process.env.API_URL + "/config";  // Usar la variable API_URL del .env

fetch(API_URL)
  .then(res => res.json())
  .then(config => {
    API_URL = config.apiUrl;
    console.log("API URL cargada:", API_URL);
  })
  .catch(err => console.error("Error cargando API_URL:", err));
