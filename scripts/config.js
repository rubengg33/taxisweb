let API_URL = "";

fetch("/api/config")
  .then(res => res.json())
  .then(config => {
    API_URL = config.apiUrl;
    console.log("API URL cargada:", API_URL);
  })
  .catch(err => console.error("Error cargando API_URL:", err));
